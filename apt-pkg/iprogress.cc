#include <apt-pkg/iprogress.h>
#include <apt-pkg/strutl.h>

#include <termios.h>
#include <sys/ioctl.h>

namespace APT {
namespace Progress {

static void SetupTerminalScrollArea(int nr_rows)
{
     // scroll down a bit to avoid visual glitch when the screen
     // area shrinks by one row
     std::cout << "\n";
         
     // save cursor
     std::cout << "\033[s";
         
     // set scroll region (this will place the cursor in the top left)
     std::cout << "\033[1;" << nr_rows - 1 << "r";
            
     // restore cursor but ensure its inside the scrolling area
     std::cout << "\033[u";
     static const char *move_cursor_up = "\033[1A";
     std::cout << move_cursor_up;
     std::flush(std::cout);
}

PackageManagerFancy::PackageManagerFancy()
   : nr_terminal_rows(-1)
{
   struct winsize win;
   if(ioctl(STDOUT_FILENO, TIOCGWINSZ, (char *)&win) == 0)
   {
      nr_terminal_rows = win.ws_row;
   }
}

void PackageManagerFancy::Started()
{
   SetupTerminalScrollArea(nr_terminal_rows);
}

void PackageManagerFancy::Finished()
{
   SetupTerminalScrollArea(nr_terminal_rows + 1);

   // override the progress line (sledgehammer)
   static const char* clear_screen_below_cursor = "\033[J";
   std::cout << clear_screen_below_cursor;
}

void PackageManagerFancy::StatusChanged(std::string PackageName, 
                                        unsigned int StepsDone,
                                        unsigned int TotalSteps)
{
   int reporting_steps = _config->FindI("DpkgPM::Reporting-Steps", 1);
   float percentage = StepsDone/(float)TotalSteps * 100.0;

   if(percentage < (last_reported_progress + reporting_steps))
      return;

   std::string progress_str;
   strprintf(progress_str, "Progress: [%3i%%]", (int)percentage);

   int row = nr_terminal_rows;

   static string save_cursor = "\033[s";
   static string restore_cursor = "\033[u";
   
   static string set_bg_color = "\033[42m"; // green
   static string set_fg_color = "\033[30m"; // black
   
   static string restore_bg =  "\033[49m";
   static string restore_fg = "\033[39m";
   
   std::cout << save_cursor
      // move cursor position to last row
             << "\033[" << row << ";0f" 
             << set_bg_color
             << set_fg_color
             << progress_str
             << restore_cursor
             << restore_bg
             << restore_fg;
   std::flush(std::cout);
   last_reported_progress = percentage;
}

void PackageManagerText::StatusChanged(std::string PackageName, 
                                       unsigned int StepsDone,
                                       unsigned int TotalSteps)
{
   int reporting_steps = _config->FindI("DpkgPM::Reporting-Steps", 1);
   float percentage = StepsDone/(float)TotalSteps * 100.0;

   if(percentage < (last_reported_progress + reporting_steps))
      return;

   std::string progress_str;
   strprintf(progress_str, "Progress: [%3i%%]", (int)percentage);

   std::cout << progress_str << "\r\n";
   std::flush(std::cout);
                   
   last_reported_progress = percentage;
}


}; // namespace progress
}; // namespace apt