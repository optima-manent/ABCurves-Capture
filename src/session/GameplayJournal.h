#pragma once

#include "session/AppendOnlyJsonl.h"
#include "trainer/TrainerEngine.h"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace abdc::session {

// A single trainer record contradicted its own scientific invariants before
// any bytes were offered to durable storage. RecordingSession treats this as
// event-local uncertainty, not as a disk or authoritative-capture failure.
class GameplayRecordValidationError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Identity and count-space context repeated on every scientific record. This
// makes individual recovered JSONL records useful even without a manifest.
struct GameplayJournalIdentity final {
    std::string session_id;
    std::string user_id;
    std::int64_t qpc_frequency = 0;
    double trainer_sensitivity = 1.0;
    bool operator==(const GameplayJournalIdentity&) const = default;
};

// Evidence for the exact linear transform used by the frame that presented a
// target. Counts remain the scientific coordinate space; pixels are retained
// so presentation can be audited and replayed.
struct RenderEvidence final {
    int viewport_width_px = 0;
    int viewport_height_px = 0;
    double pixels_per_count_x = 0.0;
    double pixels_per_count_y = 0.0;
    double counts_per_pixel_x = 0.0;
    double counts_per_pixel_y = 0.0;
    std::string transform_revision;
    double effective_radians_per_count =
        protocol::V1Constants::target_generation_radians_per_count;
    double crosshair_scale = 0.75;
    bool target_highlight_enabled = true;
    bool fullscreen = false;
    bool operator==(const RenderEvidence&) const = default;
};

struct GameplayEventRecord final {
    GameplayJournalIdentity identity;
    RenderEvidence render;
    trainer::TrainerEvent event;
};

struct GameplayBlockRecord final {
    GameplayJournalIdentity identity;
    trainer::BlockResult block;
};

// Windows Raw Input is intentionally only an optional gameplay witness. It
// never replaces the certified USBPcap device stream and is never required
// for a trainer event to be valid.
struct RawInputWitnessPacket final {
    std::int64_t receipt_qpc = 0;
    bool selected_device = false;
    std::string device_token;
    std::int64_t dx_counts = 0;
    std::int64_t dy_counts = 0;
    std::uint32_t button_flags = 0;
    std::int32_t button_data = 0;
};

struct LifecycleAnnotation final {
    std::int64_t qpc = 0;
    std::string name;
    std::optional<std::size_t> block_ordinal;
    std::optional<std::int64_t> event_id;
    std::string detail;
};

struct PauseAnnotation final {
    std::int64_t qpc = 0;
    bool paused = false;
    std::string reason;
    std::optional<std::int64_t> event_id;
};

struct FocusAnnotation final {
    std::int64_t qpc = 0;
    bool focused = true;
    bool minimized = false;
    std::optional<std::int64_t> event_id;
};

struct PresentationAnnotation final {
    std::int64_t qpc = 0;
    std::int64_t event_id = -1;
    bool successful = false;
    RenderEvidence render;
    std::string detail;
};

class GameplayJournal final {
public:
    static constexpr std::string_view kEventSchema =
        "abcurves.gameplay.trainer_event.v2";
    static constexpr std::string_view kBlockSchema =
        "abcurves.gameplay.block_result.v1";
    static constexpr std::string_view kRawInputWitnessSchema =
        "abcurves.gameplay.raw_input_witness.v1";
    static constexpr std::string_view kLifecycleSchema =
        "abcurves.gameplay.lifecycle.v1";
    static constexpr std::string_view kPauseSchema =
        "abcurves.gameplay.pause.v1";
    static constexpr std::string_view kFocusSchema =
        "abcurves.gameplay.focus.v1";
    static constexpr std::string_view kPresentationSchema =
        "abcurves.gameplay.presentation.v2";

    GameplayJournal(std::filesystem::path gameplay_directory,
                    GameplayJournalIdentity identity);
    ~GameplayJournal();

    GameplayJournal(const GameplayJournal&) = delete;
    GameplayJournal& operator=(const GameplayJournal&) = delete;

    std::uint64_t AppendEvent(const trainer::TrainerEvent& event,
                              const RenderEvidence& render);
    std::uint64_t AppendBlockResult(const trainer::BlockResult& block);

    // Returns false when optional witness input is malformed or its private
    // journal becomes unavailable. Neither condition can invalidate the
    // authoritative USB capture or trainer records.
    bool TryAppendRawInputWitness(const RawInputWitnessPacket& packet);

    std::uint64_t AppendLifecycle(const LifecycleAnnotation& annotation);
    std::uint64_t AppendPause(const PauseAnnotation& annotation);
    std::uint64_t AppendFocus(const FocusAnnotation& annotation);
    std::uint64_t AppendPresentation(const PresentationAnnotation& annotation);

    void Checkpoint();
    void Finalize();

    [[nodiscard]] const std::filesystem::path& Directory() const noexcept {
        return directory_;
    }
    [[nodiscard]] const GameplayJournalIdentity& Identity() const noexcept {
        return identity_;
    }
    [[nodiscard]] bool IsFinalized() const noexcept { return finalized_; }

private:
    struct JournalPaths;

    void DisableRawInputWitness() noexcept;

    std::filesystem::path directory_;
    GameplayJournalIdentity identity_;
    std::unique_ptr<JournalPaths> paths_;
    std::unique_ptr<AppendOnlyJsonlWriter> events_;
    std::unique_ptr<AppendOnlyJsonlWriter> blocks_;
    std::unique_ptr<AppendOnlyJsonlWriter> raw_input_witness_;
    std::unique_ptr<AppendOnlyJsonlWriter> lifecycle_;
    std::unique_ptr<AppendOnlyJsonlWriter> pauses_;
    std::unique_ptr<AppendOnlyJsonlWriter> focus_;
    std::unique_ptr<AppendOnlyJsonlWriter> presentation_;
    bool finalized_ = false;
};

// Strict readers reconstruct the complete trainer domain records and verify
// the underlying JSONL sequence, schema, and per-record CRC on the way in.
[[nodiscard]] std::vector<GameplayEventRecord> ReadGameplayEvents(
    const std::filesystem::path& path);
[[nodiscard]] std::vector<GameplayBlockRecord> ReadGameplayBlockResults(
    const std::filesystem::path& path);

}  // namespace abdc::session
