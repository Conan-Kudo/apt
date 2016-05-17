// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
// $Id: http.cc,v 1.59 2004/05/08 19:42:35 mdz Exp $
/* ######################################################################

   HTTP Acquire Method - This is the HTTP acquire method for APT.
   
   It uses HTTP/1.1 and many of the fancy options there-in, such as
   pipelining, range, if-range and so on. 

   It is based on a doubly buffered select loop. A groupe of requests are 
   fed into a single output buffer that is constantly fed out the 
   socket. This provides ideal pipelining as in many cases all of the
   requests will fit into a single packet. The input socket is buffered 
   the same way and fed into the fd for the file (may be a pipe in future).
   
   This double buffering provides fairly substantial transfer rates,
   compared to wget the http method is about 4% faster. Most importantly,
   when HTTP is compared with FTP as a protocol the speed difference is
   huge. In tests over the internet from two sites to llug (via ATM) this
   program got 230k/s sustained http transfer rates. FTP on the other 
   hand topped out at 170k/s. That combined with the time to setup the
   FTP connection makes HTTP a vastly superior protocol.
      
   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#include <config.h>

#include <apt-pkg/fileutl.h>
#include <apt-pkg/acquire-method.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/netrc.h>
#include <apt-pkg/strutl.h>
#include <apt-pkg/proxy.h>

#include <stddef.h>
#include <stdlib.h>
#include <sys/select.h>
#include <cstring>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <iostream>
#include <sstream>

#include <seccomp.h>

#include "config.h"
#include "connect.h"
#include "http.h"

#include <apti18n.h>
									/*}}}*/
using namespace std;

unsigned long long CircleBuf::BwReadLimit=0;
unsigned long long CircleBuf::BwTickReadData=0;
struct timeval CircleBuf::BwReadTick={0,0};
const unsigned int CircleBuf::BW_HZ=10;

// CircleBuf::CircleBuf - Circular input buffer				/*{{{*/
// ---------------------------------------------------------------------
/* */
CircleBuf::CircleBuf(unsigned long long Size)
   : Size(Size), Hash(NULL), TotalWriten(0)
{
   Buf = new unsigned char[Size];
   Reset();

   CircleBuf::BwReadLimit = _config->FindI("Acquire::http::Dl-Limit",0)*1024;
}
									/*}}}*/
// CircleBuf::Reset - Reset to the default state			/*{{{*/
// ---------------------------------------------------------------------
/* */
void CircleBuf::Reset()
{
   InP = 0;
   OutP = 0;
   StrPos = 0;
   TotalWriten = 0;
   MaxGet = (unsigned long long)-1;
   OutQueue = string();
   if (Hash != NULL)
   {
      delete Hash;
      Hash = NULL;
   }
}
									/*}}}*/
// CircleBuf::Read - Read from a FD into the circular buffer		/*{{{*/
// ---------------------------------------------------------------------
/* This fills up the buffer with as much data as is in the FD, assuming it
   is non-blocking.. */
bool CircleBuf::Read(int Fd)
{
   while (1)
   {
      // Woops, buffer is full
      if (InP - OutP == Size)
	 return true;

      // what's left to read in this tick
      unsigned long long const BwReadMax = CircleBuf::BwReadLimit/BW_HZ;

      if(CircleBuf::BwReadLimit) {
	 struct timeval now;
	 gettimeofday(&now,0);

	 unsigned long long d = (now.tv_sec-CircleBuf::BwReadTick.tv_sec)*1000000 +
	    now.tv_usec-CircleBuf::BwReadTick.tv_usec;
	 if(d > 1000000/BW_HZ) {
	    CircleBuf::BwReadTick = now;
	    CircleBuf::BwTickReadData = 0;
	 } 
	 
	 if(CircleBuf::BwTickReadData >= BwReadMax) {
	    usleep(1000000/BW_HZ);
	    return true;
	 }
      }

      // Write the buffer segment
      ssize_t Res;
      if(CircleBuf::BwReadLimit) {
	 Res = read(Fd,Buf + (InP%Size), 
		    BwReadMax > LeftRead() ? LeftRead() : BwReadMax);
      } else
	 Res = read(Fd,Buf + (InP%Size),LeftRead());
      
      if(Res > 0 && BwReadLimit > 0) 
	 CircleBuf::BwTickReadData += Res;
    
      if (Res == 0)
	 return false;
      if (Res < 0)
      {
	 if (errno == EAGAIN)
	    return true;
	 return false;
      }

      if (InP == 0)
	 gettimeofday(&Start,0);
      InP += Res;
   }
}
									/*}}}*/
// CircleBuf::Read - Put the string into the buffer			/*{{{*/
// ---------------------------------------------------------------------
/* This will hold the string in and fill the buffer with it as it empties */
bool CircleBuf::Read(string Data)
{
   OutQueue += Data;
   FillOut();
   return true;
}
									/*}}}*/
// CircleBuf::FillOut - Fill the buffer from the output queue		/*{{{*/
// ---------------------------------------------------------------------
/* */
void CircleBuf::FillOut()
{
   if (OutQueue.empty() == true)
      return;
   while (1)
   {
      // Woops, buffer is full
      if (InP - OutP == Size)
	 return;
      
      // Write the buffer segment
      unsigned long long Sz = LeftRead();
      if (OutQueue.length() - StrPos < Sz)
	 Sz = OutQueue.length() - StrPos;
      memcpy(Buf + (InP%Size),OutQueue.c_str() + StrPos,Sz);
      
      // Advance
      StrPos += Sz;
      InP += Sz;
      if (OutQueue.length() == StrPos)
      {
	 StrPos = 0;
	 OutQueue = "";
	 return;
      }
   }
}
									/*}}}*/
// CircleBuf::Write - Write from the buffer into a FD			/*{{{*/
// ---------------------------------------------------------------------
/* This empties the buffer into the FD. */
bool CircleBuf::Write(int Fd)
{
   while (1)
   {
      FillOut();
      
      // Woops, buffer is empty
      if (OutP == InP)
	 return true;
      
      if (OutP == MaxGet)
	 return true;
      
      // Write the buffer segment
      ssize_t Res;
      Res = write(Fd,Buf + (OutP%Size),LeftWrite());

      if (Res == 0)
	 return false;
      if (Res < 0)
      {
	 if (errno == EAGAIN)
	    return true;
	 
	 return false;
      }

      TotalWriten += Res;
      
      if (Hash != NULL)
	 Hash->Add(Buf + (OutP%Size),Res);
      
      OutP += Res;
   }
}
									/*}}}*/
// CircleBuf::WriteTillEl - Write from the buffer to a string		/*{{{*/
// ---------------------------------------------------------------------
/* This copies till the first empty line */
bool CircleBuf::WriteTillEl(string &Data,bool Single)
{
   // We cheat and assume it is unneeded to have more than one buffer load
   for (unsigned long long I = OutP; I < InP; I++)
   {      
      if (Buf[I%Size] != '\n')
	 continue;
      ++I;
      
      if (Single == false)
      {
         if (I < InP  && Buf[I%Size] == '\r')
            ++I;
         if (I >= InP || Buf[I%Size] != '\n')
            continue;
         ++I;
      }
      
      Data = "";
      while (OutP < I)
      {
	 unsigned long long Sz = LeftWrite();
	 if (Sz == 0)
	    return false;
	 if (I - OutP < Sz)
	    Sz = I - OutP;
	 Data += string((char *)(Buf + (OutP%Size)),Sz);
	 OutP += Sz;
      }
      return true;
   }      
   return false;
}
									/*}}}*/
// CircleBuf::Stats - Print out stats information			/*{{{*/
// ---------------------------------------------------------------------
/* */
void CircleBuf::Stats()
{
   if (InP == 0)
      return;
   
   struct timeval Stop;
   gettimeofday(&Stop,0);
/*   float Diff = Stop.tv_sec - Start.tv_sec + 
             (float)(Stop.tv_usec - Start.tv_usec)/1000000;
   clog << "Got " << InP << " in " << Diff << " at " << InP/Diff << endl;*/
}
									/*}}}*/
CircleBuf::~CircleBuf()
{
   delete [] Buf;
   delete Hash;
}

// HttpServerState::HttpServerState - Constructor			/*{{{*/
HttpServerState::HttpServerState(URI Srv,HttpMethod *Owner) : ServerState(Srv, Owner), In(64*1024), Out(4*1024)
{
   TimeOut = _config->FindI("Acquire::http::Timeout",TimeOut);
   Reset();
}
									/*}}}*/
// HttpServerState::Open - Open a connection to the server		/*{{{*/
// ---------------------------------------------------------------------
/* This opens a connection to the server. */
bool HttpServerState::Open()
{
   // Use the already open connection if possible.
   if (ServerFd != -1)
      return true;
   
   Close();
   In.Reset();
   Out.Reset();
   Persistent = true;
   
   // Determine the proxy setting
   AutoDetectProxy(ServerName);
   string SpecificProxy = _config->Find("Acquire::http::Proxy::" + ServerName.Host);
   if (!SpecificProxy.empty())
   {
	   if (SpecificProxy == "DIRECT")
		   Proxy = "";
	   else
		   Proxy = SpecificProxy;
   }
   else
   {
	   string DefProxy = _config->Find("Acquire::http::Proxy");
	   if (!DefProxy.empty())
	   {
		   Proxy = DefProxy;
	   }
	   else
	   {
		   char* result = getenv("http_proxy");
		   Proxy = result ? result : "";
	   }
   }
   
   // Parse no_proxy, a , separated list of domains
   if (getenv("no_proxy") != 0)
   {
      if (CheckDomainList(ServerName.Host,getenv("no_proxy")) == true)
	 Proxy = "";
   }
   
   // Determine what host and port to use based on the proxy settings
   int Port = 0;
   string Host;   
   if (Proxy.empty() == true || Proxy.Host.empty() == true)
   {
      if (ServerName.Port != 0)
	 Port = ServerName.Port;
      Host = ServerName.Host;
   }
   else
   {
      if (Proxy.Port != 0)
	 Port = Proxy.Port;
      Host = Proxy.Host;
   }
   
   // Connect to the remote server
   if (Connect(Host,Port,"http",80,ServerFd,TimeOut,Owner) == false)
      return false;
   
   return true;
}
									/*}}}*/
// HttpServerState::Close - Close a connection to the server		/*{{{*/
// ---------------------------------------------------------------------
/* */
bool HttpServerState::Close()
{
   close(ServerFd);
   ServerFd = -1;
   return true;
}
									/*}}}*/
// HttpServerState::RunData - Transfer the data from the socket		/*{{{*/
bool HttpServerState::RunData(FileFd * const File)
{
   State = Data;
   
   // Chunked transfer encoding is fun..
   if (Encoding == Chunked)
   {
      while (1)
      {
	 // Grab the block size
	 bool Last = true;
	 string Data;
	 In.Limit(-1);
	 do
	 {
	    if (In.WriteTillEl(Data,true) == true)
	       break;
	 }
	 while ((Last = Go(false, File)) == true);

	 if (Last == false)
	    return false;
	 	 
	 // See if we are done
	 unsigned long long Len = strtoull(Data.c_str(),0,16);
	 if (Len == 0)
	 {
	    In.Limit(-1);
	    
	    // We have to remove the entity trailer
	    Last = true;
	    do
	    {
	       if (In.WriteTillEl(Data,true) == true && Data.length() <= 2)
		  break;
	    }
	    while ((Last = Go(false, File)) == true);
	    if (Last == false)
	       return false;
	    return !_error->PendingError();
	 }
	 
	 // Transfer the block
	 In.Limit(Len);
	 while (Go(true, File) == true)
	    if (In.IsLimit() == true)
	       break;
	 
	 // Error
	 if (In.IsLimit() == false)
	    return false;
	 
	 // The server sends an extra new line before the next block specifier..
	 In.Limit(-1);
	 Last = true;
	 do
	 {
	    if (In.WriteTillEl(Data,true) == true)
	       break;
	 }
	 while ((Last = Go(false, File)) == true);
	 if (Last == false)
	    return false;
      }
   }
   else
   {
      /* Closes encoding is used when the server did not specify a size, the
         loss of the connection means we are done */
      if (Persistent == false)
	 In.Limit(-1);
      else if (JunkSize != 0)
	 In.Limit(JunkSize);
      else
	 In.Limit(DownloadSize);
      
      // Just transfer the whole block.
      do
      {
	 if (In.IsLimit() == false)
	    continue;
	 
	 In.Limit(-1);
	 return !_error->PendingError();
      }
      while (Go(true, File) == true);
   }

   return Owner->Flush() && !_error->PendingError();
}
									/*}}}*/
bool HttpServerState::ReadHeaderLines(std::string &Data)		/*{{{*/
{
   return In.WriteTillEl(Data);
}
									/*}}}*/
bool HttpServerState::LoadNextResponse(bool const ToFile, FileFd * const File)/*{{{*/
{
   return Go(ToFile, File);
}
									/*}}}*/
bool HttpServerState::WriteResponse(const std::string &Data)		/*{{{*/
{
   return Out.Read(Data);
}
									/*}}}*/
APT_PURE bool HttpServerState::IsOpen()					/*{{{*/
{
   return (ServerFd != -1);
}
									/*}}}*/
bool HttpServerState::InitHashes(HashStringList const &ExpectedHashes)	/*{{{*/
{
   delete In.Hash;
   In.Hash = new Hashes(ExpectedHashes);
   return true;
}
									/*}}}*/

APT_PURE Hashes * HttpServerState::GetHashes()				/*{{{*/
{
   return In.Hash;
}
									/*}}}*/
// HttpServerState::Die - The server has closed the connection.		/*{{{*/
bool HttpServerState::Die(FileFd &File)
{
   unsigned int LErrno = errno;

   // Dump the buffer to the file
   if (State == ServerState::Data)
   {
      // on GNU/kFreeBSD, apt dies on /dev/null because non-blocking
      // can't be set
      if (File.Name() != "/dev/null")
	 SetNonBlock(File.Fd(),false);
      while (In.WriteSpace() == true)
      {
	 if (In.Write(File.Fd()) == false)
	    return _error->Errno("write",_("Error writing to the file"));

	 // Done
	 if (In.IsLimit() == true)
	    return true;
      }
   }

   // See if this is because the server finished the data stream
   if (In.IsLimit() == false && State != HttpServerState::Header &&
       Persistent == true)
   {
      Close();
      if (LErrno == 0)
	 return _error->Error(_("Error reading from server. Remote end closed connection"));
      errno = LErrno;
      return _error->Errno("read",_("Error reading from server"));
   }
   else
   {
      In.Limit(-1);

      // Nothing left in the buffer
      if (In.WriteSpace() == false)
	 return false;

      // We may have got multiple responses back in one packet..
      Close();
      return true;
   }

   return false;
}
									/*}}}*/
// HttpServerState::Flush - Dump the buffer into the file		/*{{{*/
// ---------------------------------------------------------------------
/* This takes the current input buffer from the Server FD and writes it
   into the file */
bool HttpServerState::Flush(FileFd * const File)
{
   if (File != NULL)
   {
      // on GNU/kFreeBSD, apt dies on /dev/null because non-blocking
      // can't be set
      if (File->Name() != "/dev/null")
	 SetNonBlock(File->Fd(),false);
      if (In.WriteSpace() == false)
	 return true;
      
      while (In.WriteSpace() == true)
      {
	 if (In.Write(File->Fd()) == false)
	    return _error->Errno("write",_("Error writing to file"));
	 if (In.IsLimit() == true)
	    return true;
      }

      if (In.IsLimit() == true || Persistent == false)
	 return true;
   }
   return false;
}
									/*}}}*/
// HttpServerState::Go - Run a single loop				/*{{{*/
// ---------------------------------------------------------------------
/* This runs the select loop over the server FDs, Output file FDs and
   stdin. */
bool HttpServerState::Go(bool ToFile, FileFd * const File)
{
   // Server has closed the connection
   if (ServerFd == -1 && (In.WriteSpace() == false || 
			       ToFile == false))
      return false;
   
   fd_set rfds,wfds;
   FD_ZERO(&rfds);
   FD_ZERO(&wfds);
   
   /* Add the server. We only send more requests if the connection will 
      be persisting */
   if (Out.WriteSpace() == true && ServerFd != -1 
       && Persistent == true)
      FD_SET(ServerFd,&wfds);
   if (In.ReadSpace() == true && ServerFd != -1)
      FD_SET(ServerFd,&rfds);
   
   // Add the file
   int FileFD = -1;
   if (File != NULL)
      FileFD = File->Fd();
   
   if (In.WriteSpace() == true && ToFile == true && FileFD != -1)
      FD_SET(FileFD,&wfds);

   // Add stdin
   if (_config->FindB("Acquire::http::DependOnSTDIN", true) == true)
      FD_SET(STDIN_FILENO,&rfds);
	  
   // Figure out the max fd
   int MaxFd = FileFD;
   if (MaxFd < ServerFd)
      MaxFd = ServerFd;

   // Select
   struct timeval tv;
   tv.tv_sec = TimeOut;
   tv.tv_usec = 0;
   int Res = 0;
   if ((Res = select(MaxFd+1,&rfds,&wfds,0,&tv)) < 0)
   {
      if (errno == EINTR)
	 return true;
      return _error->Errno("select",_("Select failed"));
   }
   
   if (Res == 0)
   {
      _error->Error(_("Connection timed out"));
      return Die(*File);
   }
   
   // Handle server IO
   if (ServerFd != -1 && FD_ISSET(ServerFd,&rfds))
   {
      errno = 0;
      if (In.Read(ServerFd) == false)
	 return Die(*File);
   }
	 
   if (ServerFd != -1 && FD_ISSET(ServerFd,&wfds))
   {
      errno = 0;
      if (Out.Write(ServerFd) == false)
	 return Die(*File);
   }

   // Send data to the file
   if (FileFD != -1 && FD_ISSET(FileFD,&wfds))
   {
      if (In.Write(FileFD) == false)
	 return _error->Errno("write",_("Error writing to output file"));
   }

   if (MaximumSize > 0 && File && File->Tell() > MaximumSize)
   {
      Owner->SetFailReason("MaximumSizeExceeded");
      return _error->Error("Writing more data than expected (%llu > %llu)",
                           File->Tell(), MaximumSize);
   }

   // Handle commands from APT
   if (FD_ISSET(STDIN_FILENO,&rfds))
   {
      if (Owner->Run(true) != -1)
	 exit(100);
   }   
       
   return true;
}
									/*}}}*/

// HttpMethod::SendReq - Send the HTTP request				/*{{{*/
// ---------------------------------------------------------------------
/* This places the http request in the outbound buffer */
void HttpMethod::SendReq(FetchItem *Itm)
{
   URI Uri = Itm->Uri;

   // The HTTP server expects a hostname with a trailing :port
   std::stringstream Req;
   string ProperHost;

   if (Uri.Host.find(':') != string::npos)
      ProperHost = '[' + Uri.Host + ']';
   else
      ProperHost = Uri.Host;

   /* RFC 2616 §5.1.2 requires absolute URIs for requests to proxies,
      but while its a must for all servers to accept absolute URIs,
      it is assumed clients will sent an absolute path for non-proxies */
   std::string requesturi;
   if (Server->Proxy.empty() == true || Server->Proxy.Host.empty())
      requesturi = Uri.Path;
   else
      requesturi = Itm->Uri;

   // The "+" is encoded as a workaround for a amazon S3 bug
   // see LP bugs #1003633 and #1086997.
   requesturi = QuoteString(requesturi, "+~ ");

   /* Build the request. No keep-alive is included as it is the default
      in 1.1, can cause problems with proxies, and we are an HTTP/1.1
      client anyway.
      C.f. https://tools.ietf.org/wg/httpbis/trac/ticket/158 */
   Req << "GET " << requesturi << " HTTP/1.1\r\n";
   if (Uri.Port != 0)
      Req << "Host: " << ProperHost << ":" << Uri.Port << "\r\n";
   else
      Req << "Host: " << ProperHost << "\r\n";

   // generate a cache control header (if needed)
   if (_config->FindB("Acquire::http::No-Cache",false) == true)
      Req << "Cache-Control: no-cache\r\n"
	 << "Pragma: no-cache\r\n";
   else if (Itm->IndexFile == true)
      Req << "Cache-Control: max-age=" << _config->FindI("Acquire::http::Max-Age",0) << "\r\n";
   else if (_config->FindB("Acquire::http::No-Store",false) == true)
      Req << "Cache-Control: no-store\r\n";

   // If we ask for uncompressed files servers might respond with content-
   // negotiation which lets us end up with compressed files we do not support,
   // see 657029, 657560 and co, so if we have no extension on the request
   // ask for text only. As a sidenote: If there is nothing to negotate servers
   // seem to be nice and ignore it.
   if (_config->FindB("Acquire::http::SendAccept", true) == true)
   {
      size_t const filepos = Itm->Uri.find_last_of('/');
      string const file = Itm->Uri.substr(filepos + 1);
      if (flExtension(file) == file)
	 Req << "Accept: text/*\r\n";
   }

   // Check for a partial file and send if-queries accordingly
   struct stat SBuf;
   if (stat(Itm->DestFile.c_str(),&SBuf) >= 0 && SBuf.st_size > 0)
      Req << "Range: bytes=" << SBuf.st_size << "-\r\n"
	 << "If-Range: " << TimeRFC1123(SBuf.st_mtime) << "\r\n";
   else if (Itm->LastModified != 0)
      Req << "If-Modified-Since: " << TimeRFC1123(Itm->LastModified).c_str() << "\r\n";

   if (Server->Proxy.User.empty() == false || Server->Proxy.Password.empty() == false)
      Req << "Proxy-Authorization: Basic "
	 << Base64Encode(Server->Proxy.User + ":" + Server->Proxy.Password) << "\r\n";

   maybe_add_auth (Uri, _config->FindFile("Dir::Etc::netrc"));
   if (Uri.User.empty() == false || Uri.Password.empty() == false)
      Req << "Authorization: Basic "
	 << Base64Encode(Uri.User + ":" + Uri.Password) << "\r\n";

   Req << "User-Agent: " << _config->Find("Acquire::http::User-Agent",
		"Debian APT-HTTP/1.3 (" PACKAGE_VERSION ")") << "\r\n";

   Req << "\r\n";

   if (Debug == true)
      cerr << Req.str() << endl;

   Server->WriteResponse(Req.str());
}
									/*}}}*/
// HttpMethod::Configuration - Handle a configuration message		/*{{{*/
// ---------------------------------------------------------------------
/* We stash the desired pipeline depth */
bool HttpMethod::Configuration(string Message)
{
   if (ServerMethod::Configuration(Message) == false)
      return false;

   int rc;
   scmp_filter_ctx ctx = NULL;

   ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS));
   if (ctx == NULL)
      return _error->FatalE("HttpMethod::Configuration", "Cannot init seccomp");

   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "open");

   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "read");

   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "write");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ioctl), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "ioctl");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "fcntl");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "lseek");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(ftruncate), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "ftruncate");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(utimes), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "utimes");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getdents), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "getdents");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "dup2");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "close");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "unlink");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rename), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "unlink");

   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "brk");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "mmap");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mprotect), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "mmap");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "munmap");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(pipe), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "pipe");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fork), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "fork");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "clone");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "wait");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(nanosleep), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "nanosleep");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "getpid");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "exit_group");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_tid_address), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "set_tid_address");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "set_robust_list");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "rt_sigaction");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "rt_sigprocmask");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getrlimit), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "getrlimit");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(uname), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "uname");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "socket");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(connect), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "connect");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(poll), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "poll");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(select), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "select");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendto), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "sendto");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvmsg), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "recvmsg");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(recvfrom), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "recvfrom");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(bind), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "bind");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockname), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "getsockname");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getsockopt), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "getsockopt");

   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(stat), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "stat");

   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(newfstatat), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "statat");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "fstat");
   rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0);
   if (rc != 0)
      return _error->FatalE("HttpMethod::Configuration", "Cannot allow %s", "access");


   rc = seccomp_load(ctx);
   if (rc)
      return _error->FatalE("HttpMethod::Configuration", "Cannot load context");

   AllowRedirect = _config->FindB("Acquire::http::AllowRedirect",true);
   PipelineDepth = _config->FindI("Acquire::http::Pipeline-Depth",
				  PipelineDepth);
   Debug = _config->FindB("Debug::Acquire::http",false);

   return true;
}
									/*}}}*/
std::unique_ptr<ServerState> HttpMethod::CreateServerState(URI const &uri)/*{{{*/
{
   return std::unique_ptr<ServerState>(new HttpServerState(uri, this));
}
									/*}}}*/
void HttpMethod::RotateDNS()						/*{{{*/
{
   ::RotateDNS();
}
									/*}}}*/
