#include "parser/packet_console.h"
#include "storage/pcap_reader.h"
#ifdef _WIN32
#include <windows.h>
#endif
using namespace flowguard;
namespace {
int run(const std::filesystem::path& path, bool json) {
    PcapReader reader;
    auto result=reader.open(path);
    if (!result.ok()) { std::cerr << result.message << '\n'; return 1; }
    RawPacket raw;
    std::uint64_t sequence=0;
    for (;;) {
        const auto status=reader.readNext(raw,result);
        if (status==ReadStatus::EndOfFile) break;
        if (status==ReadStatus::Error) { std::cerr << result.message << '\n'; return 1; }
        console::print(parsePacket(raw,++sequence),json);
    }
    if (!json) std::cout << "Read " << sequence << " packet(s)\n";
    return 0;
}
}
#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    const auto previous=GetConsoleOutputCP();
    struct Restore { UINT cp; ~Restore() { if (cp) SetConsoleOutputCP(cp); } } restore{previous};
    SetConsoleOutputCP(CP_UTF8);
    const bool json=argc==3 && std::wstring(argv[1])==L"--json";
#else
int main(int argc, char** argv) {
    const bool json=argc==3 && std::string(argv[1])=="--json";
#endif
    if (argc!=2 && !json) { std::cerr << "Usage: flowguard_offline_probe [--json] <classic.pcap>\n"; return 2; }
    return run(std::filesystem::path(argv[json ? 2 : 1]),json);
}
