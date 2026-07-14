#include "base/BuildInfo.h"

#include <iostream>

int wmain(const int argc, wchar_t** argv) {
    if (abdc::IsVersionRequest(argc, argv)) {
        return abdc::PrintBuildVersion(FIXTURE_COMMAND_NAME);
    }
#ifdef FIXTURE_SESSION_TOOL
    if (argc == 1) {
        std::cout
            << "ABCurves session tool\n"
            << "  abct_session_tool validate <session-directory-or-zip>\n"
            << "  abct_session_tool archive <sealed-session-directory> [output.zip]\n";
        return 64;
    }
#endif
    return 0;
}
