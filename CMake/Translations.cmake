# translations.cmake - Translations using APT's translation system.
# Copyright (C) 2009, 2016 Julian Andres Klode <jak@debian.org>

function(apt_add_translation_domain)
    set(options)
    set(oneValueArgs DOMAIN)
    set(multiValueArgs TARGETS SCRIPTS)
    cmake_parse_arguments(NLS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    # Build the list of source files of the target
    set(files "")
    set(abs_files "")
    set(scripts "")
    set(abs_scripts "")
    set(targets ${NLS_TARGETS})
    set(domain ${NLS_DOMAIN})
    set(xgettext_params
        --add-comments
        --foreign
        --package-name=${PROJECT_NAME}
        --package-version=${PACKAGE_VERSION}
        --msgid-bugs-address=${PACKAGE_MAIL}
    )
    foreach(source ${NLS_SCRIPTS})
            path_join(file "${CMAKE_CURRENT_SOURCE_DIR}" "${source}")
            file(RELATIVE_PATH relfile ${PROJECT_SOURCE_DIR} ${file})
            list(APPEND scripts ${relfile})
            list(APPEND abs_scripts ${file})
        endforeach()
    foreach(target ${targets})
        get_target_property(source_dir ${target} SOURCE_DIR)
        get_target_property(sources ${target} SOURCES)
        foreach(source ${sources})
            path_join(file "${source_dir}" "${source}")
            file(RELATIVE_PATH relfile ${PROJECT_SOURCE_DIR} ${file})
            set(files ${files} ${relfile})
            set(abs_files ${abs_files} ${file})
        endforeach()

        target_compile_definitions(${target} PRIVATE -DAPT_DOMAIN="${domain}")
    endforeach()

    if("${scripts}" STREQUAL "")
        set(sh_pot "/dev/null")
    else()
        set(sh_pot ${PROJECT_BINARY_DIR}/${domain}.sh.pot)
        # Create the template for this specific sub-domain
        add_custom_command (OUTPUT ${sh_pot}
            COMMAND xgettext ${xgettext_params} -L Shell
                             -o ${sh_pot} ${scripts}
            DEPENDS ${abs_scripts}
            VERBATIM
            WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        )
    endif()


    add_custom_command (OUTPUT ${PROJECT_BINARY_DIR}/${domain}.c.pot
        COMMAND xgettext ${xgettext_params} -k_ -kN_
                         --keyword=P_:1,2
                         -o ${PROJECT_BINARY_DIR}/${domain}.c.pot ${files}
        DEPENDS ${abs_files}
        VERBATIM
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    )

    add_custom_command (OUTPUT ${PROJECT_BINARY_DIR}/${domain}.pot
        COMMAND msgcomm --more-than=0 --sort-by-file
                         ${sh_pot}
                         ${PROJECT_BINARY_DIR}/${domain}.c.pot
                         --output=${PROJECT_BINARY_DIR}/${domain}.pot
        DEPENDS ${sh_pot}
                ${PROJECT_BINARY_DIR}/${domain}.c.pot
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
    )

    # Build .mo files
    file(GLOB translations "${PROJECT_SOURCE_DIR}/po/*.po")
    list(SORT translations)
    foreach(file ${translations})
        get_filename_component(langcode ${file} NAME_WE)
        set(outdir ${PROJECT_BINARY_DIR}/locale/${langcode}/LC_MESSAGES)
        file(MAKE_DIRECTORY ${outdir})
        # Command to merge and compile the messages
        add_custom_command(OUTPUT ${outdir}/${domain}.po
            COMMAND msgmerge -qo ${outdir}/${domain}.po ${file} ${PROJECT_BINARY_DIR}/${domain}.pot
            DEPENDS ${file} ${PROJECT_BINARY_DIR}/${domain}.pot
        )
        add_custom_command(OUTPUT ${outdir}/${domain}.mo
            COMMAND msgfmt --statistics -o ${outdir}/${domain}.mo  ${outdir}/${domain}.po
            DEPENDS ${outdir}/${domain}.po
        )

        set(mofiles ${mofiles} ${outdir}/${domain}.mo)
        install(FILES ${outdir}/${domain}.mo
                DESTINATION "${CMAKE_INSTALL_LOCALEDIR}/${langcode}/LC_MESSAGES")
    endforeach(file ${translations})

    add_custom_target(nls-${domain} ALL DEPENDS ${mofiles})
endfunction()

# Usage: apt_add_update_po(output domain [domain ...])
function(apt_add_update_po)
    set(options)
    set(oneValueArgs TEMPLATE)
    set(multiValueArgs DOMAINS)
    cmake_parse_arguments(NLS "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    set(output ${CMAKE_CURRENT_SOURCE_DIR}/${NLS_TEMPLATE}.pot)
    foreach(domain ${NLS_DOMAINS})
        list(APPEND potfiles ${PROJECT_BINARY_DIR}/${domain}.pot)
    endforeach()

    get_filename_component(master_name ${output} NAME_WE)
    add_custom_target(nls-${master_name}
                       COMMAND msgcomm --sort-by-file --add-location=file
                                        --more-than=0 --output=${output}
                                ${potfiles}
                       DEPENDS ${potfiles})

    file(GLOB translations "${PROJECT_SOURCE_DIR}/po/*.po")
    foreach(translation ${translations})
            get_filename_component(langcode ${translation} NAME_WE)
            add_custom_target(update-po-${langcode}
                COMMAND msgmerge -q --update --backup=none ${translation} ${output}
                DEPENDS nls-${master_name}
            )
            add_dependencies_maybe_create_target(update-po update-po-${langcode})
    endforeach()
    add_dependencies_maybe_create_target(update-po nls-${master_name})
endfunction()
