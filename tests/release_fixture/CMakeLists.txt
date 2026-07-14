cmake_minimum_required(VERSION 3.25)

project(ABCTReleaseFixture VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/ABCTBuildIdentity.cmake")
abct_detect_source_identity(
    ABCT_SOURCE_REVISION
    ABCT_SOURCE_DIRTY
    ABCT_SOURCE_EPOCH
    ABCT_SOURCE_ID)

function(add_fixture_executable target command_name output_name)
    add_executable("${target}"
        fixture_main.cpp
        "${ABCT_REPOSITORY_ROOT}/src/app/console.rc")
    target_include_directories("${target}" PRIVATE "${ABCT_REPOSITORY_ROOT}/src")
    target_compile_definitions("${target}" PRIVATE
        UNICODE
        _UNICODE
        ABDC_VERSION="${PROJECT_VERSION}"
        ABDC_SOURCE_REVISION="${ABCT_SOURCE_ID}"
        FIXTURE_COMMAND_NAME="${command_name}")
    set_target_properties("${target}" PROPERTIES OUTPUT_NAME "${output_name}")
    if(MSVC)
        target_compile_options("${target}" PRIVATE /W4 /permissive- /utf-8)
        target_link_options("${target}" PRIVATE /MANIFEST:NO)
    endif()
endfunction()

add_fixture_executable(
    abct_participant_app "ABCurvesCaptureTrainer" "ABCurves Capture Trainer")
add_fixture_executable(
    abct_capture_helper "abct_capture_helper" "abct_capture_helper")
add_fixture_executable(
    abct_probe_helper "abct_probe_helper" "abct_probe_helper")
add_fixture_executable(
    abct_session_tool "abct_session_tool" "abct_session_tool")
target_compile_definitions(abct_session_tool PRIVATE FIXTURE_SESSION_TOOL=1)
add_fixture_executable(
    abct_research_export "abct_research_export" "abct_research_export")

abct_add_windows_version_resource(
    abct_participant_app
    "ABCurves Capture Trainer"
    "ABCurvesCaptureTrainer"
    "ABCurves Capture Trainer.exe")
abct_add_windows_version_resource(
    abct_capture_helper
    "ABCurves USB capture helper"
    "abct_capture_helper"
    "abct_capture_helper.exe")
abct_add_windows_version_resource(
    abct_probe_helper
    "ABCurves USB certification probe helper"
    "abct_probe_helper"
    "abct_probe_helper.exe")
abct_add_windows_version_resource(
    abct_session_tool
    "ABCurves session validation tool"
    "abct_session_tool"
    "abct_session_tool.exe")
abct_add_windows_version_resource(
    abct_research_export
    "ABCurves offline research export tool"
    "abct_research_export"
    "abct_research_export.exe")

include("${ABCT_REPOSITORY_ROOT}/cmake/ABCTRelease.cmake")
abct_configure_windows_release(
    PARTICIPANT_TARGET abct_participant_app
    CAPTURE_TARGET abct_capture_helper
    PROBE_TARGET abct_probe_helper
    SESSION_TARGET abct_session_tool
    RESEARCH_TARGET abct_research_export)
