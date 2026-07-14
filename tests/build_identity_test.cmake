cmake_minimum_required(VERSION 3.25)

if(NOT DEFINED ABCT_SOURCE_DIRECTORY OR
   NOT IS_DIRECTORY "${ABCT_SOURCE_DIRECTORY}")
    message(FATAL_ERROR "ABCT_SOURCE_DIRECTORY must name the source tree")
endif()

include("${ABCT_SOURCE_DIRECTORY}/cmake/ABCTBuildIdentity.cmake")
abct_detect_source_identity(
    detected_revision
    detected_dirty
    detected_epoch
    detected_id)

find_package(Git QUIET)
if(Git_FOUND AND EXISTS "${ABCT_SOURCE_DIRECTORY}/.git")
    execute_process(
        COMMAND "${GIT_EXECUTABLE}" -C "${ABCT_SOURCE_DIRECTORY}"
                rev-parse --verify HEAD
        RESULT_VARIABLE expected_result
        OUTPUT_VARIABLE expected_revision
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(expected_result EQUAL 0)
        string(TOLOWER "${expected_revision}" expected_revision)
        if(NOT detected_revision STREQUAL expected_revision)
            message(FATAL_ERROR
                "Build identity revision mismatch: expected '${expected_revision}', "
                "detected '${detected_revision}'")
        endif()
        string(FIND "${detected_id}" "${expected_revision}" revision_prefix)
        if(NOT revision_prefix EQUAL 0)
            message(FATAL_ERROR
                "Build identity '${detected_id}' does not start with Git HEAD")
        endif()
    endif()
endif()

if(NOT detected_epoch MATCHES "^[0-9]+$")
    message(FATAL_ERROR "Build identity epoch is not numeric: '${detected_epoch}'")
endif()
