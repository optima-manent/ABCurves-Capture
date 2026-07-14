include_guard(GLOBAL)

get_filename_component(ABCT_REPOSITORY_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

# Resolve an identity that can be compiled into every executable and repeated
# in the release manifest. A source archive without Git metadata remains
# auditable through the source-tree digest produced by Package-Windows.ps1.
function(abct_detect_source_identity out_revision out_dirty out_epoch out_id)
    set(revision "unversioned")
    set(dirty TRUE)
    set(epoch "315532800") # 1980-01-01, the earliest portable ZIP timestamp.

    find_package(Git QUIET)
    if(Git_FOUND AND EXISTS "${ABCT_REPOSITORY_ROOT}/.git")
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" -C "${ABCT_REPOSITORY_ROOT}"
                    rev-parse --verify HEAD
            RESULT_VARIABLE revision_result
            OUTPUT_VARIABLE revision_output
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        string(LENGTH "${revision_output}" revision_length)
        # CMake's regular-expression dialect does not support the {40}
        # repetition syntax consistently, so validate the length separately.
        if(revision_result EQUAL 0 AND revision_length EQUAL 40 AND
           revision_output MATCHES "^[0-9a-fA-F]+$")
            string(TOLOWER "${revision_output}" revision)

            execute_process(
                COMMAND "${GIT_EXECUTABLE}" -C "${ABCT_REPOSITORY_ROOT}"
                        show -s --format=%ct HEAD
                RESULT_VARIABLE epoch_result
                OUTPUT_VARIABLE epoch_output
                ERROR_QUIET
                OUTPUT_STRIP_TRAILING_WHITESPACE)
            if(epoch_result EQUAL 0 AND epoch_output MATCHES "^[0-9]+$")
                set(epoch "${epoch_output}")
            endif()
        endif()

        execute_process(
            COMMAND "${GIT_EXECUTABLE}" -C "${ABCT_REPOSITORY_ROOT}"
                    status --porcelain=v1 --untracked-files=normal
            RESULT_VARIABLE status_result
            OUTPUT_VARIABLE status_output
            ERROR_QUIET
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(status_result EQUAL 0 AND status_output STREQUAL "")
            set(dirty FALSE)
        endif()
    endif()

    if(DEFINED ENV{SOURCE_DATE_EPOCH} AND
       "$ENV{SOURCE_DATE_EPOCH}" MATCHES "^[0-9]+$")
        set(epoch "$ENV{SOURCE_DATE_EPOCH}")
    endif()

    set(source_id "${revision}")
    if(dirty)
        string(APPEND source_id "-dirty")
    endif()

    set(${out_revision} "${revision}" PARENT_SCOPE)
    set(${out_dirty} "${dirty}" PARENT_SCOPE)
    set(${out_epoch} "${epoch}" PARENT_SCOPE)
    set(${out_id} "${source_id}" PARENT_SCOPE)
endfunction()

# Add normal Windows Explorer version metadata without coupling it to the
# manifest resource already selected by each executable.
function(abct_add_windows_version_resource target description internal_name original_filename)
    if(NOT WIN32)
        return()
    endif()
    if(NOT TARGET "${target}")
        message(FATAL_ERROR "Cannot add version metadata to missing target '${target}'")
    endif()

    set(ABCT_FILE_DESCRIPTION "${description}")
    set(ABCT_INTERNAL_NAME "${internal_name}")
    set(ABCT_ORIGINAL_FILENAME "${original_filename}")
    if(PROJECT_VERSION_TWEAK STREQUAL "")
        set(ABCT_VERSION_TWEAK 0)
    else()
        set(ABCT_VERSION_TWEAK "${PROJECT_VERSION_TWEAK}")
    endif()

    set(resource_directory "${CMAKE_CURRENT_BINARY_DIR}/generated/version")
    file(MAKE_DIRECTORY "${resource_directory}")
    set(resource "${resource_directory}/${target}_version.rc")
    configure_file(
        "${ABCT_REPOSITORY_ROOT}/cmake/windows_version.rc.in"
        "${resource}"
        @ONLY)
    target_sources("${target}" PRIVATE "${resource}")
endfunction()
