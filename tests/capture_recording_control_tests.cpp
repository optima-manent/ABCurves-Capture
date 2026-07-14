#include "TestHarness.h"

#include "acquisition/CaptureHelperRecordingControl.h"

using abdc::acquisition::CaptureHelperClientSnapshot;
using abdc::acquisition::CaptureHelperClientState;
using abdc::acquisition::CaptureHelperErrorSnapshot;
using abdc::acquisition::CaptureHelperHealthSnapshot;
using abdc::acquisition::CaptureHelperReadySnapshot;

TEST_CASE("capture recording control maps a healthy running helper") {
    CaptureHelperClientSnapshot source;
    source.state = CaptureHelperClientState::Running;
    source.ready = CaptureHelperReadySnapshot{};
    source.health = CaptureHelperHealthSnapshot{
        "running", "none", "capture healthy", "", 1000, 20, 18, 17, 2, 1000, 0};

    const auto mapped = abdc::acquisition::MapCaptureHelperSnapshot(source);
    EXPECT_TRUE(mapped.ready);
    EXPECT_TRUE(mapped.running);
    EXPECT_TRUE(!mapped.stop_complete);
    EXPECT_TRUE(!mapped.fatal_issue.has_value());
    EXPECT_EQ(mapped.counters.source_bytes, 1000U);
    EXPECT_EQ(mapped.counters.raw_pcap_records, 18U);
    EXPECT_EQ(mapped.counters.decoded_reports, 17U);
    EXPECT_EQ(mapped.counters.anomaly_count, 2U);
}

TEST_CASE("capture recording control maps clean completion") {
    CaptureHelperClientSnapshot source;
    source.state = CaptureHelperClientState::Completed;
    source.ready = CaptureHelperReadySnapshot{};
    source.health = CaptureHelperHealthSnapshot{
        "completed", "none", "capture published", "participant", 2000, 30,
        28, 27, 1, 2000, 0};

    const auto mapped = abdc::acquisition::MapCaptureHelperSnapshot(source);
    EXPECT_TRUE(!mapped.running);
    EXPECT_TRUE(mapped.stop_complete);
    EXPECT_TRUE(mapped.clean_stop);
    EXPECT_TRUE(!mapped.fatal_issue.has_value());
}

TEST_CASE("capture recording control maps destructive helper failures") {
    struct Case {
        const char* helper_reason;
        abdc::session::RuntimeIssue issue;
    };
    const Case cases[] = {
        {"queue_or_byte_loss", abdc::session::RuntimeIssue::NativeQueueOverflow},
        {"native_or_device_loss", abdc::session::RuntimeIssue::CaptureHelperLost},
        {"device_identity_changed", abdc::session::RuntimeIssue::SelectedDeviceChanged},
        {"pcap_framing", abdc::session::RuntimeIssue::PcapFramingLost},
        {"writer_failure", abdc::session::RuntimeIssue::StorageWriteFailed},
        {"invalid_configuration", abdc::session::RuntimeIssue::IntegrityFailed},
    };

    for (const auto& test : cases) {
        CaptureHelperClientSnapshot source;
        source.state = CaptureHelperClientState::Failed;
        source.error = CaptureHelperErrorSnapshot{test.helper_reason, "fatal"};
        const auto mapped = abdc::acquisition::MapCaptureHelperSnapshot(source);
        EXPECT_TRUE(mapped.stop_complete);
        EXPECT_TRUE(mapped.fatal_issue.has_value());
        EXPECT_EQ(*mapped.fatal_issue, test.issue);
    }
}

TEST_CASE("capture recording control never treats anomalies as fatal") {
    CaptureHelperClientSnapshot source;
    source.state = CaptureHelperClientState::Running;
    source.ready = CaptureHelperReadySnapshot{};
    source.health = CaptureHelperHealthSnapshot{
        "running", "none", "decode warnings retained", "", 3000, 50, 48,
        20, 999, 3000, 0};
    const auto mapped = abdc::acquisition::MapCaptureHelperSnapshot(source);
    EXPECT_TRUE(mapped.running);
    EXPECT_TRUE(!mapped.fatal_issue.has_value());
    EXPECT_EQ(mapped.counters.anomaly_count, 999U);
}

TEST_CASE("capture recording control never seals while a failed helper is alive") {
    CaptureHelperClientSnapshot source;
    source.state = CaptureHelperClientState::Failed;
    source.process_alive = true;
    source.message = "capture helper could not be proven stopped";

    const auto mapped = abdc::acquisition::MapCaptureHelperSnapshot(source);
    EXPECT_TRUE(mapped.running);
    EXPECT_TRUE(!mapped.stop_complete);
    EXPECT_TRUE(mapped.shutdown_failed);
    EXPECT_TRUE(mapped.fatal_issue.has_value());
}
