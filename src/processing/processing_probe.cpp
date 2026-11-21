// Maintainer: He Junjie. CLI for stage-2 integration, no Qt UI.
#include "core/processing_session.h"
#include <charconv>
#include <iostream>
#include <thread>

int wmain(int argc, wchar_t** argv)
{
    flowguard::ProcessingOptions options;
    flowguard::CaptureOptions capture;
    std::filesystem::path input;
    int seconds = 5;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 >= argc) return 2;
        // Windows narrow argv uses the local code page, not UTF-8. Convert from
        // native wide arguments so Chinese paths survive the CLI boundary.
        const auto key = std::filesystem::path(argv[i]).u8string();
        const auto value = std::filesystem::path(argv[i + 1]).u8string();
        if (key == "--input") input = std::filesystem::u8path(value);
        else if (key == "--device") capture.deviceId = value;
        else if (key == "--bpf") capture.bpfExpression = value;
        else if (key == "--output") options.savePath = std::filesystem::u8path(value);
        else if (key == "--seconds") {
            const auto converted = std::from_chars(value.data(), value.data() + value.size(), seconds);
            if (converted.ec != std::errc{} || converted.ptr != value.data() + value.size() || seconds < 1 || seconds > 86400) return 2;
        } else if (key == "--speed") {
            try { std::size_t used; options.replaySpeed = std::stod(value, &used); if (used != value.size()) return 2; }
            catch (...) { return 2; }
            options.pacedReplay = true;
        } else return 2;
    }
    if (input.empty() == capture.deviceId.empty()) {
        std::cerr << "Use --input PCAP or --device ID [--bpf EXPR], with optional --output NEW.pcap, --seconds N, --speed N\n";
        return 2;
    }
    flowguard::ProcessingSession session;
    const auto result = input.empty() ? session.startLive(capture, options) : session.startFile(input, options);
    if (!result.ok()) { std::cerr << result.message << '\n'; return 1; }
    const auto start = std::chrono::steady_clock::now();
    auto nextReport = start;
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        const auto status = session.snapshot();
        session.takePackets(); // Consume bounded UI batches without printing private packet fields.
        if (now >= nextReport) {
            std::cout << "elapsed=" << std::chrono::duration<double>(now - start).count()
                      << " packets=" << status.statistics.totalPackets << " bytes=" << status.statistics.totalBytes
                      << " saved=" << status.savedPackets << " queue=" << status.capture.queuedPackets
                      << " dropped=" << status.capture.queueDroppedPackets << " ui_dropped=" << status.displayDroppedPackets
                      << " history=" << status.history.size() << " pps=" << status.rate.packetsPerSecond
                      << " saving_error=" << static_cast<int>(status.savingError.code) << '\n' << std::flush;
            nextReport = now + std::chrono::seconds(1);
        }
        if (status.state == flowguard::ProcessingState::Completed || status.state == flowguard::ProcessingState::Failed ||
            now - start >= std::chrono::seconds(seconds)) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    session.stop();
    const auto status = session.snapshot();
    std::cout << "FINAL packets=" << status.statistics.totalPackets << " saved=" << status.savedPackets
              << " history=" << status.history.size() << " error=" << static_cast<int>(status.error.code)
              << " saving_error=" << static_cast<int>(status.savingError.code) << '\n';
    return status.error.ok() && status.savingError.ok() ? 0 : 1;
}
