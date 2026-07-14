#include "export/ResearchExport.h"

#include "base/BuildInfo.h"

#include <exception>
#include <iostream>
#include <string>

namespace {

void Usage() {
    std::cerr
        << "Usage: abct_research_export <sealed-session-directory> "
           "<new-output-directory>\n";
}

}  // namespace

int wmain(const int argc, wchar_t** argv) {
    if (abdc::IsVersionRequest(argc, argv)) {
        return abdc::PrintBuildVersion("abct_research_export");
    }
    if (argc != 3) {
        Usage();
        return 2;
    }
    try {
        abdc::research::ResearchExportOptions options;
        options.sealed_session_directory =
            std::filesystem::absolute(std::filesystem::path(argv[1]));
        options.output_directory =
            std::filesystem::absolute(std::filesystem::path(argv[2]));
        const auto result = abdc::research::ExportResearchSession(options);
        std::cout << "Research export complete\n"
                  << "  source session: " << result.source_session_id << '\n'
                  << "  reports: " << result.report_count << '\n'
                  << "  dense 1 ms bins: " << result.bin_count << '\n'
                  << "  trainer events: " << result.event_count << '\n'
                  << "  block results: " << result.block_count << '\n'
                  << "  clock warning mask: " << result.clock_warning_mask << '\n'
                  << "  output: " << result.output_directory.string() << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Research export failed: " << error.what() << '\n';
        return 1;
    }
}
