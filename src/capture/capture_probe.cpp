// Maintainer: He Junjie. AI-assisted implementation; see accompanying tests.
#include "core/module_contracts.h"
#include <windows.h>
#include <iostream>
#include <string>

namespace {
class ConsoleUtf8 {
public:
    ConsoleUtf8() : previous_(GetConsoleOutputCP())
    {
        if (previous_) SetConsoleOutputCP(CP_UTF8);
    }
    ~ConsoleUtf8()
    {
        if (previous_) SetConsoleOutputCP(previous_);
    }
private:
    UINT previous_;
};
void printUsage(std::ostream& output)
{
    output << "Usage: flowguard_capture_probe --list-devices\n"
              "Lists Npcap adapters without opening them or capturing packets.\n";
}
} // namespace

int main(int argc, char* argv[])
{
    const ConsoleUtf8 consoleEncoding;
    if (argc == 2 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        printUsage(std::cout);
        return 0;
    }
    if (argc != 2 || std::string(argv[1]) != "--list-devices") {
        printUsage(std::cerr);
        return 2;
    }
    const auto result = flowguard::enumerateDevices();
    if (!result.result.ok()) {
        std::cerr << "Adapter enumeration failed: " << result.result.message << '\n';
        return 1;
    }
    std::cout << "Npcap adapters: " << result.devices.size() << '\n';
    if (result.devices.empty()) {
        std::cout << "No capture adapters available.\n";
    }
    for (std::size_t index = 0; index < result.devices.size(); ++index) {
        const auto& device = result.devices[index];
        std::cout << '\n' << '[' << index + 1 << "] " << device.id
                  << "\n  Description: " << (device.description.empty() ? "(none)" : device.description)
                  << "\n  Loopback: " << (device.loopback ? "yes" : "no") << '\n';
        if (device.addresses.empty()) std::cout << "  Addresses: (none)\n";
        for (const auto& address : device.addresses) std::cout << "  Address: " << address << '\n';
    }
    return std::cout ? 0 : 1;
}
