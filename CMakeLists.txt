cmake_minimum_required(VERSION 3.25)

project(ABCurvesCaptureTrainer VERSION 0.4.1 LANGUAGES C CXX)

include(cmake/ABCTBuildIdentity.cmake)
abct_detect_source_identity(
    ABCT_SOURCE_REVISION
    ABCT_SOURCE_DIRTY
    ABCT_SOURCE_EPOCH
    ABCT_SOURCE_ID)

option(ABCT_BUILD_TESTS "Build unit and contract tests" ON)
option(ABCT_BUILD_APP "Build the Windows participant application" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(abct_hidapi_descriptor_reconstructor STATIC
    third_party/hidapi-0.15.0/windows/hidapi_descriptor_reconstruct.c)
set_target_properties(abct_hidapi_descriptor_reconstructor PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED TRUE
    C_EXTENSIONS OFF)
target_include_directories(abct_hidapi_descriptor_reconstructor PUBLIC
    third_party/hidapi-0.15.0/windows
    third_party/hidapi-0.15.0/hidapi)
target_compile_definitions(abct_hidapi_descriptor_reconstructor PUBLIC
    HIDAPI_USE_DDK
    HID_API_NO_EXPORT_DEFINE)
if(MSVC)
    target_compile_options(abct_hidapi_descriptor_reconstructor PRIVATE
        /W3 /wd4200 /wd4201 /wd4214 /utf-8)
endif()

add_library(abct_zlib STATIC
    third_party/zlib-1.3.2/adler32.c
    third_party/zlib-1.3.2/compress.c
    third_party/zlib-1.3.2/crc32.c
    third_party/zlib-1.3.2/deflate.c
    third_party/zlib-1.3.2/gzclose.c
    third_party/zlib-1.3.2/gzlib.c
    third_party/zlib-1.3.2/gzread.c
    third_party/zlib-1.3.2/gzwrite.c
    third_party/zlib-1.3.2/infback.c
    third_party/zlib-1.3.2/inffast.c
    third_party/zlib-1.3.2/inflate.c
    third_party/zlib-1.3.2/inftrees.c
    third_party/zlib-1.3.2/trees.c
    third_party/zlib-1.3.2/uncompr.c
    third_party/zlib-1.3.2/zutil.c)
set_target_properties(abct_zlib PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED TRUE
    C_EXTENSIONS OFF)
target_include_directories(abct_zlib PUBLIC third_party/zlib-1.3.2)
if(MSVC)
    target_compile_definitions(abct_zlib PRIVATE
        _CRT_SECURE_NO_DEPRECATE
        _CRT_NONSTDC_NO_DEPRECATE)
    target_compile_options(abct_zlib PRIVATE /W3 /utf-8)
endif()

add_library(abct_core STATIC
    src/acquisition/CaptureHelperClient.cpp
    src/acquisition/CaptureHelperRecordingControl.cpp
    src/acquisition/CaptureWorker.cpp
    src/acquisition/CertificationProbe.cpp
    src/acquisition/CertificationProbeClient.cpp
    src/app/ApplicationPaths.cpp
    src/app/HighscoreStore.cpp
    src/app/ParticipantInventory.cpp
    src/app/ParticipantFlow.cpp
    src/app/ParticipantSettings.cpp
    src/app/ParticipantUi.cpp
    src/base/Binary.cpp
    src/base/Crc32.cpp
    src/base/Sha256.cpp
    src/base/Json.cpp
    src/base/AtomicFile.cpp
    src/capture/PcapReader.cpp
    src/capture/UsbPcapPacket.cpp
    src/capture/HidDescriptor.cpp
    src/capture/StreamingPcapParser.cpp
    src/capture/DevicePcapWriter.cpp
    src/capture/MouseReportExtractor.cpp
    src/capture/ReportStream.cpp
    src/capture/LiveReportMirror.cpp
    src/device/MouseDiscovery.cpp
    src/device/WindowsHidDecoderEvidence.cpp
    src/device/PhysicalMouseSelection.cpp
    src/device/UsbTopologyResolver.cpp
    src/device/ActivityCorrelation.cpp
    src/device/CertificationFlow.cpp
    src/derive/AxisConvention.cpp
    src/derive/ClockAnchorFit.cpp
    src/derive/MillisecondDeriver.cpp
    src/export/ResearchExport.cpp
    src/windows_capture/NativeUsbPcap.cpp
    src/platform/ClockAnchor.cpp
    src/platform/QpcClock.cpp
    src/platform/RawInput.cpp
    src/protocol/protocol_v1.cpp
    src/trainer/TrainerEngine.cpp
    src/session/AppendOnlyJsonl.cpp
    src/session/AbandonedSessionRecovery.cpp
    src/session/ClockJournal.cpp
    src/session/CaptureArtifactValidation.cpp
    src/session/CapturePrefixRecovery.cpp
    src/session/CrashRecovery.cpp
    src/session/FailurePolicy.cpp
    src/session/GameplayJournal.cpp
    src/session/PseudonymousIdentity.cpp
    src/session/RecordingSession.cpp
    src/session/SessionArchive.cpp
    src/session/SessionValidator.cpp
    src/session/SessionWorkspace.cpp
)
target_include_directories(abct_core PUBLIC src)
target_compile_definitions(abct_core PUBLIC
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    ABDC_VERSION="${PROJECT_VERSION}"
    ABDC_SOURCE_REVISION="${ABCT_SOURCE_ID}")
target_link_libraries(abct_core PUBLIC
    bcrypt shell32 ole32 advapi32 wintrust crypt32 version cfgmgr32 hid setupapi user32)
target_link_libraries(abct_core PRIVATE
    abct_hidapi_descriptor_reconstructor
    abct_zlib)
if(MSVC)
    target_compile_options(abct_core PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8)
endif()

if(ABCT_BUILD_TESTS)
    enable_testing()
    add_executable(abct_tests
        tests/app_settings_tests.cpp
        tests/abandoned_session_recovery_tests.cpp
        tests/highscore_store_tests.cpp
        tests/participant_flow_tests.cpp
        tests/participant_ui_tests.cpp
        tests/capture_helper_client_tests.cpp
        tests/capture_recording_control_tests.cpp
        tests/test_main.cpp
        tests/capture_source_tests.cpp
        tests/acquisition_worker_tests.cpp
        tests/certification_tests.cpp
        tests/certification_flow_tests.cpp
        tests/certification_probe_tests.cpp
        tests/certification_probe_client_tests.cpp
        tests/clock_journal_tests.cpp
        tests/derive_contract_tests.cpp
        tests/research_export_tests.cpp
        tests/gameplay_journal_tests.cpp
        tests/session_policy_tests.cpp
        tests/recording_session_tests.cpp
        tests/session_recovery_tests.cpp
        tests/session_workspace_tests.cpp
        tests/trainer_engine_tests.cpp)
    target_link_libraries(abct_tests PRIVATE abct_core)
    target_include_directories(abct_tests PRIVATE tests)
    if(MSVC)
        target_compile_options(abct_tests PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8)
    endif()
    add_test(NAME abct_contracts COMMAND abct_tests)

    add_executable(abct_hidapi_reconstructor_fixture_tests
        third_party/hidapi-0.15.0/windows/test/hid_report_reconstructor_test.c)
    set_target_properties(abct_hidapi_reconstructor_fixture_tests PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED TRUE
        C_EXTENSIONS OFF)
    target_link_libraries(abct_hidapi_reconstructor_fixture_tests
        PRIVATE abct_hidapi_descriptor_reconstructor)
    foreach(fixture
            045E_02FF_0005_0001
            046D_C077_0002_0001
            1532_00A3_0002_0001)
        add_test(NAME "abct_hidapi_${fixture}"
            COMMAND abct_hidapi_reconstructor_fixture_tests
                "${CMAKE_SOURCE_DIR}/third_party/hidapi-0.15.0/windows/test/data/${fixture}.pp_data"
                "${CMAKE_SOURCE_DIR}/third_party/hidapi-0.15.0/windows/test/data/${fixture}_expected.rpt_desc")
    endforeach()
endif()

add_library(abct_ui STATIC
    src/audio/AudioEngine.cpp
    src/platform/Win32Window.cpp
    src/render/CrosshairRenderer.cpp
    src/render/D3D11Renderer.cpp
    src/render/GridRenderer.cpp
    src/render/HudRenderer.cpp
    src/render/TargetRenderer.cpp
    src/render/UiTextLayout.cpp)
target_include_directories(abct_ui PUBLIC src)
target_link_libraries(abct_ui PUBLIC abct_core)
target_link_libraries(abct_ui PRIVATE d3d11 dxgi d3dcompiler winmm)
if(MSVC)
    target_compile_options(abct_ui PRIVATE /W4 /permissive- /Zc:__cplusplus /utf-8)
endif()

if(ABCT_BUILD_APP)
    add_executable(ABCurvesCaptureTrainer WIN32
        src/app/app_main.cpp
        src/app/ParticipantApplication.cpp
        src/app/app.rc)
    target_link_libraries(ABCurvesCaptureTrainer PRIVATE abct_ui)
    set_target_properties(ABCurvesCaptureTrainer PROPERTIES
        OUTPUT_NAME "ABCurves Capture Trainer")
    abct_add_windows_version_resource(
        ABCurvesCaptureTrainer
        "ABCurves Capture Trainer"
        "ABCurvesCaptureTrainer"
        "ABCurves Capture Trainer.exe")
    if(MSVC)
        target_compile_options(ABCurvesCaptureTrainer PRIVATE
            /W4 /permissive- /Zc:__cplusplus /utf-8)
        target_link_options(ABCurvesCaptureTrainer PRIVATE /MANIFEST:NO)
    endif()
endif()

add_executable(abct_capture_helper
    src/tools/capture_helper_main.cpp
    src/app/console.rc)
target_link_libraries(abct_capture_helper PRIVATE abct_core)
abct_add_windows_version_resource(
    abct_capture_helper
    "ABCurves USB capture helper"
    "abct_capture_helper"
    "abct_capture_helper.exe")
if(MSVC)
    target_compile_options(abct_capture_helper PRIVATE
        /W4 /permissive- /Zc:__cplusplus /utf-8)
    target_link_options(abct_capture_helper PRIVATE /MANIFEST:NO)
endif()

add_executable(abct_probe_helper
    src/tools/probe_helper_main.cpp
    src/app/console.rc)
target_link_libraries(abct_probe_helper PRIVATE abct_core)
abct_add_windows_version_resource(
    abct_probe_helper
    "ABCurves USB certification probe helper"
    "abct_probe_helper"
    "abct_probe_helper.exe")
if(MSVC)
    target_compile_options(abct_probe_helper PRIVATE
        /W4 /permissive- /Zc:__cplusplus /utf-8)
    target_link_options(abct_probe_helper PRIVATE /MANIFEST:NO)
endif()

add_executable(abct_session_tool
    src/tools/session_tool_main.cpp
    src/app/console.rc)
target_link_libraries(abct_session_tool PRIVATE abct_core)
abct_add_windows_version_resource(
    abct_session_tool
    "ABCurves session validation tool"
    "abct_session_tool"
    "abct_session_tool.exe")
if(MSVC)
    target_compile_options(abct_session_tool PRIVATE
        /W4 /permissive- /Zc:__cplusplus /utf-8)
    target_link_options(abct_session_tool PRIVATE /MANIFEST:NO)
endif()

add_executable(abct_research_export
    src/tools/research_export_main.cpp
    src/app/console.rc)
target_link_libraries(abct_research_export PRIVATE abct_core)
abct_add_windows_version_resource(
    abct_research_export
    "ABCurves offline research export tool"
    "abct_research_export"
    "abct_research_export.exe")
if(MSVC)
    target_compile_options(abct_research_export PRIVATE
        /W4 /permissive- /Zc:__cplusplus /utf-8)
    target_link_options(abct_research_export PRIVATE /MANIFEST:NO)
endif()

# Investigator-only, single-file diagnostic. It deliberately is not included
# in participant release packages.
add_executable(abct_usbpcap_diagnostic
    src/tools/usbpcap_diagnostic_main.cpp
    src/tools/diagnostic.rc)
target_link_libraries(abct_usbpcap_diagnostic PRIVATE abct_core)
abct_add_windows_version_resource(
    abct_usbpcap_diagnostic
    "ABCurves USBPcap diagnostic"
    "abct_usbpcap_diagnostic"
    "ABCurves USBPcap Diagnostic.exe")
set_target_properties(abct_usbpcap_diagnostic PROPERTIES
    OUTPUT_NAME "ABCurves USBPcap Diagnostic")
if(MSVC)
    target_compile_options(abct_usbpcap_diagnostic PRIVATE
        /W4 /permissive- /Zc:__cplusplus /utf-8)
    target_link_options(abct_usbpcap_diagnostic PRIVATE /MANIFEST:NO)
endif()

include(cmake/ABCTRelease.cmake)
abct_configure_windows_release(
    PARTICIPANT_TARGET ABCurvesCaptureTrainer
    CAPTURE_TARGET abct_capture_helper
    PROBE_TARGET abct_probe_helper
    SESSION_TARGET abct_session_tool
    RESEARCH_TARGET abct_research_export)
