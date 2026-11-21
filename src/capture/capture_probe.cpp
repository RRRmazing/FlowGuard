// Maintainer: He Junjie. AI-assisted implementation; see accompanying tests.
#include "core/module_contracts.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <charconv>
#include <chrono>
#include <thread>

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
              "       flowguard_capture_probe --capture --device ID [--seconds N] [--cycles N] [--bpf EXPR]\n"
              "List mode does not capture. Capture mode prints metadata only; no payload or file output.\n";
}
int capture(int argc, char* argv[])
{
    flowguard::CaptureOptions options;
    int seconds = 3, cycles = 1;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 >= argc) { printUsage(std::cerr); return 2; }
        const std::string key(argv[i]), value(argv[i + 1]);
        if (key == "--device") options.deviceId = value;
        else if (key == "--bpf") options.bpfExpression = value;
        else if (key == "--seconds" || key == "--cycles") {
            int number = 0;
            const auto converted = std::from_chars(value.data(), value.data() + value.size(), number);
            if (converted.ec != std::errc{} || converted.ptr != value.data() + value.size() ||
                number < 1 || number > (key == "--seconds" ? 300 : 10)) {
                std::cerr << "Invalid duration/cycle count\n"; return 2;
            }
            (key == "--seconds" ? seconds : cycles) = number;
        } else { printUsage(std::cerr); return 2; }
    }
    if (options.deviceId.empty()) { printUsage(std::cerr); return 2; }
    flowguard::CaptureSession session;
    for (int cycle = 1; cycle <= cycles; ++cycle) {
        const auto started = session.start(options);
        if (!started.ok()) { std::cerr << started.message << '\n'; return 1; }
        std::uint64_t processed = 0;
        auto drain = [&] {
            flowguard::RawPacket packet;
            while (session.tryPop(packet)) {
                ++processed;
                if (processed <= 5) {
                    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(
                        packet.timestamp.time_since_epoch()).count();
                    std::cout << "timestamp_us=" << micros << " original=" << packet.originalLength
                              << " captured=" << packet.capturedLength << " link=" << packet.linkType << '\n';
                }
            }
        };
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
        while (std::chrono::steady_clock::now() < deadline &&
               session.status().state == flowguard::CaptureState::Running) {
            drain();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        const auto before = std::chrono::steady_clock::now();
        session.stop(); drain();
        const auto stopMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - before).count();
        const auto status = session.status();
        std::cout << "cycle=" << cycle << " processed=" << processed
                  << " received=" << status.receivedPackets << " enqueued=" << status.enqueuedPackets
                  << " dropped=" << status.queueDroppedPackets << " invalid=" << status.invalidPackets
                  << " stop_ms=" << stopMs << '\n';
        if (!status.lastError.ok()) { std::cerr << status.lastError.message << '\n'; return 1; }
    }
    return 0;
}
} // namespace

int main(int argc, char* argv[])
{
    const ConsoleUtf8 consoleEncoding;
    if (argc >= 2 && std::string(argv[1]) == "--capture") return capture(argc, argv);
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
