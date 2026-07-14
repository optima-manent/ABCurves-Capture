#pragma once

#include <cstdint>
#include <filesystem>

namespace abdc::app {

struct ApplicationPaths final {
    std::filesystem::path executable;
    std::filesystem::path executable_directory;
    std::filesystem::path local_state_directory;
    std::filesystem::path settings_file;
    std::filesystem::path participant_identity_directory;
    std::filesystem::path highscores_file;
    std::filesystem::path sessions_directory;
    std::filesystem::path media_directory;
};

[[nodiscard]] ApplicationPaths ResolveApplicationPaths();

// Creates only participant-owned state/output directories and verifies the
// session location can durably store a realistically useful recording.
void PrepareApplicationPaths(const ApplicationPaths& paths,
                             std::uint64_t minimum_session_free_bytes =
                                 256U * 1024U * 1024U);

}  // namespace abdc::app
