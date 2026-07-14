include_guard(GLOBAL)

include(CMakeParseArguments)
include("${CMAKE_CURRENT_LIST_DIR}/ABCTBuildIdentity.cmake")

option(ABCT_ENABLE_PACKAGING
    "Enable the audited portable Windows x64 package target" OFF)
set(ABCT_PACKAGE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/package" CACHE PATH
    "Directory that receives ABCurves participant release ZIP files")

function(abct_configure_windows_release)
    set(one_value_args
        PARTICIPANT_TARGET
        CAPTURE_TARGET
        PROBE_TARGET
        SESSION_TARGET
        RESEARCH_TARGET)
    cmake_parse_arguments(ABCT_RELEASE "" "${one_value_args}" "" ${ARGN})

    if(NOT ABCT_ENABLE_PACKAGING)
        return()
    endif()
    if(NOT WIN32 OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR
            "ABCT release packages are supported only by a Windows x64 build")
    endif()

    foreach(required_arg PARTICIPANT_TARGET CAPTURE_TARGET SESSION_TARGET RESEARCH_TARGET)
        if(NOT ABCT_RELEASE_${required_arg})
            message(FATAL_ERROR "abct_configure_windows_release requires ${required_arg}")
        endif()
        if(NOT TARGET "${ABCT_RELEASE_${required_arg}}")
            message(FATAL_ERROR
                "Release target '${ABCT_RELEASE_${required_arg}}' does not exist")
        endif()
    endforeach()

    set(runtime_targets
        "${ABCT_RELEASE_PARTICIPANT_TARGET}"
        "${ABCT_RELEASE_CAPTURE_TARGET}"
        "${ABCT_RELEASE_SESSION_TARGET}"
        "${ABCT_RELEASE_RESEARCH_TARGET}")
    set(probe_target "")
    if(ABCT_RELEASE_PROBE_TARGET AND TARGET "${ABCT_RELEASE_PROBE_TARGET}")
        set(probe_target "${ABCT_RELEASE_PROBE_TARGET}")
        list(APPEND runtime_targets "${probe_target}")
    endif()

    # The helper clients resolve privileged tools beside the participant app,
    # so all executables intentionally share the portable package root.
    install(TARGETS ${runtime_targets}
        RUNTIME DESTINATION "."
        COMPONENT Participant)
    install(FILES
        "${ABCT_REPOSITORY_ROOT}/README.md"
        "${ABCT_REPOSITORY_ROOT}/LICENSE"
        "${ABCT_REPOSITORY_ROOT}/THIRD_PARTY_NOTICES.md"
        DESTINATION "."
        COMPONENT Participant)
    install(FILES
        "${ABCT_REPOSITORY_ROOT}/licenses/HIDAPI-BSD-3-Clause.txt"
        "${ABCT_REPOSITORY_ROOT}/licenses/USBPcap-BSD-2-Clause.txt"
        "${ABCT_REPOSITORY_ROOT}/licenses/ZLIB.txt"
        DESTINATION "licenses"
        COMPONENT Participant)
    install(FILES
        "${ABCT_REPOSITORY_ROOT}/docs/INSTALLATION.md"
        "${ABCT_REPOSITORY_ROOT}/docs/USER_GUIDE.md"
        "${ABCT_REPOSITORY_ROOT}/docs/PRIVACY.md"
        "${ABCT_REPOSITORY_ROOT}/docs/ARCHITECTURE.md"
        "${ABCT_REPOSITORY_ROOT}/docs/DATA_CONTRACT.md"
        "${ABCT_REPOSITORY_ROOT}/docs/FAILURE_POLICY.md"
        "${ABCT_REPOSITORY_ROOT}/docs/TESTING.md"
        "${ABCT_REPOSITORY_ROOT}/docs/RESEARCH_EXPORT.md"
        DESTINATION "docs"
        COMPONENT Participant)
    install(DIRECTORY "${ABCT_REPOSITORY_ROOT}/media/"
        DESTINATION "media"
        COMPONENT Participant
        PATTERN ".mci_cache" EXCLUDE
        PATTERN "*.log" EXCLUDE)

    if(NOT DEFINED ABCT_SOURCE_REVISION OR
       NOT DEFINED ABCT_SOURCE_DIRTY OR
       NOT DEFINED ABCT_SOURCE_EPOCH OR
       NOT DEFINED ABCT_SOURCE_ID)
        abct_detect_source_identity(
            ABCT_SOURCE_REVISION
            ABCT_SOURCE_DIRTY
            ABCT_SOURCE_EPOCH
            ABCT_SOURCE_ID)
    endif()

    find_program(ABCT_POWERSHELL_EXECUTABLE NAMES pwsh powershell)
    if(NOT ABCT_POWERSHELL_EXECUTABLE)
        message(FATAL_ERROR "PowerShell is required to build an ABCT release package")
    endif()

    set(package_command
        "${ABCT_POWERSHELL_EXECUTABLE}"
        -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass
        -File "${ABCT_REPOSITORY_ROOT}/scripts/Package-Windows.ps1"
        -CMakeCommand "${CMAKE_COMMAND}"
        -SourceDirectory "${ABCT_REPOSITORY_ROOT}"
        -BuildDirectory "${CMAKE_BINARY_DIR}"
        -OutputDirectory "${ABCT_PACKAGE_OUTPUT_DIRECTORY}"
        -Configuration "$<CONFIG>"
        -Version "${PROJECT_VERSION}"
        -Protocol "3"
        -SourceId "${ABCT_SOURCE_ID}"
        -SourceRevision "${ABCT_SOURCE_REVISION}"
        -SourceDirty "${ABCT_SOURCE_DIRTY}"
        -SourceEpoch "${ABCT_SOURCE_EPOCH}"
        -Generator "${CMAKE_GENERATOR}"
        -Toolchain "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}"
        -ParticipantApp "$<TARGET_FILE_NAME:${ABCT_RELEASE_PARTICIPANT_TARGET}>"
        -CaptureHelper "$<TARGET_FILE_NAME:${ABCT_RELEASE_CAPTURE_TARGET}>"
        -SessionTool "$<TARGET_FILE_NAME:${ABCT_RELEASE_SESSION_TARGET}>"
        -ResearchExporter "$<TARGET_FILE_NAME:${ABCT_RELEASE_RESEARCH_TARGET}>")
    if(probe_target)
        list(APPEND package_command
            -ProbeHelper "$<TARGET_FILE_NAME:${probe_target}>")
    endif()

    if(TARGET abct_package)
        message(FATAL_ERROR "The abct_package target is already defined")
    endif()
    add_custom_target(abct_package
        COMMAND ${package_command}
        DEPENDS ${runtime_targets}
        COMMENT "Creating and smoke-testing the portable Windows x64 package"
        USES_TERMINAL
        VERBATIM)
    set_property(TARGET abct_package PROPERTY FOLDER "Packaging")
endfunction()
