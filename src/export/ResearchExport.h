#pragma once

#include "derive/AxisConvention.h"

#include <cstdint>
#include <filesystem>
#include <string>

namespace abdc::research {

inline constexpr const char* kResearchExportSchema =
    "abcurves.research_export.v1";
inline constexpr const char* kDenseMouseCsvSchema =
    "abcurves.native_count_1khz.v1";
inline constexpr const char* kTrainerEventCsvSchema =
    "abcurves.trainer_event_index.v1";
inline constexpr const char* kBlockResultCsvSchema =
    "abcurves.block_result_index.v1";
inline constexpr const char* kClockFitSchema =
    "abcurves.qpc_utc_clock_fit.v1";

struct ResearchExportOptions final {
    std::filesystem::path sealed_session_directory;
    std::filesystem::path output_directory;
    derive::AxisConventionVersion axis_convention =
        derive::kCurrentResearchAxisConvention;

    // A corrupt-but-authentic timestamp gap must not turn an offline command
    // into an unbounded allocation. The canonical 21-block run is far below
    // this default (10,000 seconds of dense rows).
    std::uint64_t maximum_dense_bins = 10'000'000;
};

struct ResearchExportResult final {
    std::filesystem::path output_directory;
    std::string source_session_id;
    std::uint64_t report_count = 0;
    std::uint64_t bin_count = 0;
    std::uint64_t event_count = 0;
    std::uint64_t block_count = 0;
    std::uint32_t clock_warning_mask = 0;
};

// Validates the sealed source before creating anything, writes into a new
// sibling staging directory, and atomically publishes the completed export.
// The output directory must not exist and may not be inside the sealed source.
// The source session is never opened for writing.
[[nodiscard]] ResearchExportResult ExportResearchSession(
    const ResearchExportOptions& options);

}  // namespace abdc::research
