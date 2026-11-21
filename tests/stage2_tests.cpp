// Maintainer: He Junjie. AI-assisted stage-2 behavioral and integration tests.
#include "core/processing_session.h"
#include <windows.h>
#include <cmath>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <thread>

using namespace flowguard;
using namespace std::chrono;
namespace {
std::size_t checks = 0;
void check(bool value, const char* message)
{
    ++checks;
    if (!value) throw std::runtime_error(message);
}
template<class F> void waitFor(F predicate, const char* message)
{
    const auto deadline = steady_clock::now() + seconds(4);
    while (!predicate() && steady_clock::now() < deadline) std::this_thread::sleep_for(milliseconds(5));
    check(predicate(), message);
}
bool finished(ProcessingSession& s)
{
    auto state = s.snapshot().state;
    return state == ProcessingState::Completed || state == ProcessingState::Failed;
}
struct TempDirectory {
    std::filesystem::path path;
    TempDirectory() {
        path = std::filesystem::temp_directory_path() / ("FlowGuard-stage2-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64()));
        check(std::filesystem::create_directory(path), "create unique owned test directory");
    }
    ~TempDirectory() {
        // This path is the exact unique directory created above, never a user root.
        std::error_code error; std::filesystem::remove_all(path, error);
    }
};
std::vector<RawPacket> load(const std::filesystem::path& path)
{
    PcapReader reader; check(reader.open(path).ok(), "open fixture");
    std::vector<RawPacket> packets;
    for (;;) {
        RawPacket packet; OperationResult result;
        const auto status = reader.readNext(packet, result);
        check(result.ok(), "read fixture without error");
        if (status == ReadStatus::EndOfFile) break;
        check(status == ReadStatus::Packet, "read packet"); packets.push_back(std::move(packet));
    }
    return packets;
}
void write(const std::filesystem::path& path, const std::vector<RawPacket>& packets)
{
    PcapWriter writer;
    check(writer.open(path, {}).ok(), "open new writer");
    for (const auto& packet : packets) check(writer.write(packet).ok(), "write fixture packet");
    check(writer.flush().ok() && writer.close().ok() && writer.close().ok(), "flush and idempotent close");
}
void statisticsTests()
{
    StatisticsEngine engine;
    const std::uint32_t lengths[] = {46, 47, 1500, 1501, 65536, 4000000};
    for (int i = 0; i < 6; ++i) {
        PacketRecord record; record.originalLength = lengths[i];
        record.network = i == 0 ? NetworkProtocol::IPv4 : i == 1 ? NetworkProtocol::IPv6 : i == 2 ? NetworkProtocol::Arp : NetworkProtocol::Other;
        record.transport = i == 0 ? TransportProtocol::Tcp : i == 1 ? TransportProtocol::Udp : TransportProtocol::Other;
        record.status = i == 5 ? ParseStatus::Malformed : ParseStatus::Complete;
        record.isDns = i == 1; engine.add(record);
    }
    const auto result = engine.snapshot();
    check(result.totalPackets == 6 && result.totalBytes == 4068630, "lengths use original bytes");
    check(result.lengthGroups == std::array<std::uint64_t, 3>{1, 2, 3}, "46/47/1500/1501 interval boundaries");
    check(result.lengthFrequency.at(65536) == 2 && result.lengthFrequency.size() == 5, "bounded oversized frequency key");
    check(result.networkCounts.at(NetworkProtocol::Arp) == 1 && result.networkCounts.at(NetworkProtocol::Other) == 3 &&
          result.transportCounts.at(TransportProtocol::Tcp) == 1 && result.transportCounts.at(TransportProtocol::Udp) == 1,
          "network and transport categories remain separate");
    check(result.parseCounts.at(ParseStatus::Malformed) == 1 && result.dnsPackets == 1, "malformed and DNS counts");
    const auto rate = calculateRate({}, result, 2);
    check(rate.packetsPerSecond == 3 && rate.bytesPerSecond == 2034315 && std::abs(rate.dnsFraction - 1.0 / 6) < 1e-12, "rate units and interval DNS denominator");
    check(calculateRate(result, result, 1).dnsFraction == 0 && calculateRate({}, result, 0).packetsPerSecond == 0 &&
          calculateRate({}, result, -1).bytesPerSecond == 0 &&
          calculateRate({}, result, (std::numeric_limits<double>::quiet_NaN)()).packetsPerSecond == 0, "zero traffic and invalid intervals");
    engine.reset(); check(engine.snapshot().totalPackets == 0 && engine.snapshot().lengthFrequency.empty(), "reset clears counters");
    check(calculateRate(result, engine.snapshot(), 1).packetsPerSecond == 0, "do not rate across reset");
    PacketRecord large; large.originalLength = (std::numeric_limits<std::uint32_t>::max)();
    engine.add(large); engine.add(large);
    check(engine.snapshot().totalBytes == 8589934590ULL, "byte counters are 64-bit");
}
void writerTests(const std::filesystem::path& root, const std::vector<RawPacket>& packets)
{
    const auto path = root / std::filesystem::u8path(u8"保存重读.pcap");
    write(path, packets);
    const auto reread = load(path);
    check(reread.size() == packets.size(), "saved count equals read count");
    for (std::size_t i = 0; i < reread.size(); ++i) {
        check(reread[i].bytes == packets[i].bytes && reread[i].originalLength == packets[i].originalLength &&
              reread[i].capturedLength == packets[i].capturedLength && reread[i].linkType == packets[i].linkType,
              "saved bytes, original/captured lengths and link type match");
        const auto delta = packets[i].timestamp - reread[i].timestamp;
        check(delta >= system_clock::duration::zero() && delta < microseconds(1), "microsecond timestamp rounding");
    }
    const auto size = std::filesystem::file_size(path);
    PcapWriter writer;
    check(!writer.open(path, {}).ok() && std::filesystem::file_size(path) == size, "refuse overwrite atomically");
    check(!writer.open(root / "missing" / "file.pcap", {}).ok(), "report bad output directory");
    PcapWriteOptions options; options.maxFileBytes = 23;
    check(writer.open(root / "bad-limit.pcap", options).code == ErrorCode::InvalidArgument, "global header requires 24 bytes");
    options.maxFileBytes = 24 + 16 + packets[0].capturedLength;
    check(writer.open(root / "limited.pcap", options).ok(), "open limited output");
    check(writer.open(root / "other.pcap", options).code == ErrorCode::InvalidState, "reject repeated open");
    check(writer.write(packets[0]).ok() && writer.write(packets[0]).code == ErrorCode::ResourceLimit, "file cap includes headers and rejects whole next record");
    check(writer.close().ok() && load(root / "limited.pcap").size() == 1, "limited output stays readable");
    check(writer.open(root / "invalid-records.pcap", {}).ok(), "reopen after close");
    auto bad = packets[0]; ++bad.linkType;
    check(writer.write(bad).code == ErrorCode::InvalidArgument, "link type cannot change");
    bad = packets[0]; bad.capturedLength += 1;
    check(writer.write(bad).code == ErrorCode::InvalidArgument, "reject length mismatch");
    bad = packets[0]; bad.timestamp = system_clock::time_point(seconds(-1));
    check(writer.write(bad).code == ErrorCode::InvalidArgument, "reject negative timestamps");
    bad = packets[0]; bad.timestamp = system_clock::time_point(seconds(4294967296ULL));
    check(writer.write(bad).code == ErrorCode::InvalidArgument, "reject PCAP timestamp overflow");
    check(writer.close().ok() && load(root / "invalid-records.pcap").empty(), "invalid records do not append bytes");
    check(writer.write(packets[0]).code == ErrorCode::InvalidState, "closed writer rejects writes");
}
void processingTests(const std::filesystem::path& root, const std::filesystem::path& fixture,
                     const std::vector<RawPacket>& packets)
{
    ProcessingSession session;
    check(!session.pause().ok(), "idle pause rejected");
    ProcessingOptions options; options.pendingLimit = 2; options.savePath = root / "pipeline.pcap";
    check(session.startFile(fixture, options).ok(), "start offline processing and save");
    waitFor([&] { return finished(session); }, "offline completion"); session.stop();
    auto result = session.snapshot();
    check(result.state == ProcessingState::Completed && result.error.ok() && result.savingError.ok(), "offline processing state");
    check(result.statistics.totalPackets == packets.size() && result.savedPackets == packets.size(), "all packets processed and saved despite bounded display");
    check(result.displayDroppedPackets == packets.size() - 2, "display backpressure is separate");
    auto batch = session.takePackets(1);
    check(batch.sessionId == result.sessionId && batch.packets.size() == 1 && batch.packets[0].record.sequence == packets.size() - 1, "batch carries session ID and recent sequence");
    check(session.takePackets().packets.size() == 1 && session.takePackets().packets.empty(), "consume batches");
    const auto expected = result.statistics;
    check(session.startFile(root / "pipeline.pcap").ok(), "re-read saved pipeline file");
    waitFor([&] { return finished(session); }, "readback completes"); session.stop();
    result = session.snapshot();
    check(result.statistics.totalBytes == expected.totalBytes && result.statistics.networkCounts == expected.networkCounts &&
          result.statistics.transportCounts == expected.transportCounts && result.statistics.lengthFrequency == expected.lengthFrequency &&
          result.statistics.dnsPackets == expected.dnsPackets, "save/readback statistics consistency");
    const auto firstId = result.sessionId;
    check(!session.startFile(root / "not-found.pcap").ok() && session.snapshot().state == ProcessingState::Failed,
          "invalid input reports error");
    options = {}; options.savePath = fixture; // Existing input must not be overwritten.
    check(session.startFile(fixture, options).ok(), "analysis starts despite invalid output");
    waitFor([&] { return finished(session); }, "save failure does not stop analysis"); session.stop();
    result = session.snapshot();
    check(result.sessionId > firstId && result.statistics.totalPackets == packets.size() && !result.savingError.ok() &&
          result.state == ProcessingState::Completed, "saving error is isolated from analysis");
    options.savePath = root / "pipeline-cap.pcap"; options.maxSavedBytes = 24;
    check(session.startFile(fixture, options).ok(), "start capped pipeline save");
    waitFor([&] { return finished(session); }, "cap still completes analysis"); session.stop();
    check(session.snapshot().savingError.code == ErrorCode::ResourceLimit &&
          session.snapshot().statistics.totalPackets == packets.size() && load(root / "pipeline-cap.pcap").empty(), "size cap leaves valid empty PCAP and analysis intact");

    auto timeline = std::vector<RawPacket>(3, packets[0]);
    for (int i = 0; i < 3; ++i) timeline[i].timestamp = system_clock::time_point(seconds(100 + 10 * i));
    const auto replay = root / "replay.pcap"; write(replay, timeline);
    options = {}; options.pacedReplay = true; options.replaySpeed = 100;
    check(session.startFile(replay, options).ok(), "paced replay starts");
    waitFor([&] { return session.snapshot().statistics.totalPackets >= 1; }, "first replay packet");
    check(session.pause().ok(), "pause playback");
    std::this_thread::sleep_for(milliseconds(30));
    const auto pausedCount = session.snapshot().statistics.totalPackets;
    std::this_thread::sleep_for(milliseconds(150));
    check(session.snapshot().statistics.totalPackets == pausedCount, "pause stops processing");
    check(session.startLive({}).code == ErrorCode::InvalidState, "live and offline are mutually exclusive");
    check(session.enableSaving(root / "toggle-a.pcap").ok(), "asynchronous save enable");
    waitFor([&] { return session.snapshot().savingActive; }, "save opens while paused");
    session.disableSaving();
    waitFor([&] { return !session.snapshot().savingActive; }, "save disable closes");
    check(session.enableSaving(root / "toggle-b.pcap").ok(), "save can be enabled again");
    waitFor([&] { return session.snapshot().savingActive; }, "second save opens");
    check(session.resume().ok(), "resume playback");
    waitFor([&] { return finished(session); }, "resumed playback completes"); session.stop();
    check(session.snapshot().statistics.totalPackets == 3 && load(root / "toggle-a.pcap").empty() &&
          load(root / "toggle-b.pcap").size() == 3 - pausedCount, "save starts at next processed packet only");
    options.replaySpeed = 1;
    check(session.startFile(replay, options).ok(), "slow replay starts");
    waitFor([&] { return session.snapshot().statistics.totalPackets == 1; }, "slow first packet");
    const auto before = steady_clock::now(); session.stop(); session.stop();
    check(steady_clock::now() - before < seconds(1), "stop interrupts long replay waits");

    timeline.resize(4, packets[0]); const int times[] = {100, 3700, 99, 3699};
    for (int i = 0; i < 4; ++i) timeline[i].timestamp = system_clock::time_point(seconds(times[i]));
    write(root / "out-of-order.pcap", timeline);
    check(session.startFile(root / "out-of-order.pcap").ok(), "out-of-order import");
    waitFor([&] { return finished(session); }, "out-of-order complete"); session.stop();
    result = session.snapshot();
    check(result.history.size() == 3600 && result.lateHistoryPackets == 1 && result.statistics.totalPackets == 4,
          "offline history bounded with explicit late-packet count");
    check(result.history.front().rate.packetsPerSecond == 0 && result.history.back().rate.packetsPerSecond == 1,
          "missing file-time buckets are zero, not import speed");
}
} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) return 2;
    try {
        TempDirectory directory;
        const std::filesystem::path fixture(argv[1]);
        const auto packets = load(fixture);
        check(!packets.empty(), "fixture is not empty");
        statisticsTests(); writerTests(directory.path, packets); processingTests(directory.path, fixture, packets);
        std::cout << "Stage-2 checks passed: " << checks << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << '\n'; return 1; }
}
