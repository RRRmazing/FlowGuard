// Primary maintainer: He Junjie; interface contributors: Xie Fuxiang.
// AI-assisted declarations, checked against docs/interfaces.md v1.0.
// Declarations only: unimplemented modules intentionally have no success stubs.
#pragma once
#include "core/packet_types.h"
#include <array>
#include <cstddef>
#include <filesystem>
#include <map>

namespace flowguard {

enum class ErrorCode {
    None, InvalidArgument, InvalidState, DeviceError,
    FilterError, IoError, Unsupported, ResourceLimit
};
struct OperationResult {
    ErrorCode code = ErrorCode::None;
    std::string message;
    bool ok() const { return code == ErrorCode::None; }
};

struct CaptureDevice {
    std::string id;                   // 传回 Npcap 的稳定设备标识
    std::string description;          // 供用户选择，不作设备键值
    std::vector<std::string> addresses;
    bool loopback = false;
};
struct DeviceListResult {
    OperationResult result;
    std::vector<CaptureDevice> devices;
};
struct CaptureOptions {
    std::string deviceId;
    std::string bpfExpression;         // 空字符串表示不过滤
    std::uint32_t snapshotLength = 65535;
    int readTimeoutMs = 100;
    bool promiscuous = false;
    std::size_t maxQueuePackets = 8192;
    std::size_t maxQueueBytes = 64 * 1024 * 1024;
};
enum class CaptureState { Stopped, Running, Failed };
struct CaptureStatus {
    CaptureState state = CaptureState::Stopped;
    OperationResult lastError;
    std::uint64_t receivedPackets = 0;
    std::uint64_t enqueuedPackets = 0;
    std::uint64_t queueDroppedPackets = 0;
    std::uint64_t invalidPackets = 0;
    std::size_t queuedPackets = 0;
    std::size_t queuedBytes = 0;
    std::optional<std::uint64_t> driverReceived;
    std::optional<std::uint64_t> driverDropped;
    std::optional<std::uint64_t> interfaceDropped;
};
DeviceListResult enumerateDevices();
class CaptureSession {
public:
    CaptureSession();
    ~CaptureSession();
    CaptureSession(const CaptureSession&) = delete;
    CaptureSession& operator=(const CaptureSession&) = delete;
    OperationResult start(const CaptureOptions& options);
    void stop();
    bool tryPop(RawPacket& packet);
    CaptureStatus status() const;
    // 具体私有成员由实现者补充；不暴露 pcap_t 或内部队列。
};

struct ProtocolField {
    std::string name;
    std::string value;
    std::vector<ProtocolField> children;
};
struct ParsedPacket {
    PacketRecord record;
    std::vector<ProtocolField> fields;
};
ParsedPacket parsePacket(const RawPacket& packet, std::uint64_t sequence);

struct StatisticsSnapshot {
    std::uint64_t totalPackets = 0;
    std::uint64_t totalBytes = 0;
    std::map<std::uint32_t, std::uint64_t> lengthFrequency;
    std::array<std::uint64_t, 3> lengthGroups{};
    std::map<NetworkProtocol, std::uint64_t> networkCounts;
    std::map<TransportProtocol, std::uint64_t> transportCounts;
    std::map<ParseStatus, std::uint64_t> parseCounts;
    std::uint64_t dnsPackets = 0;
};
struct RateSample {
    double packetsPerSecond = 0;
    double bytesPerSecond = 0;
    double dnsFraction = 0;            // 0..1，界面自行乘 100 显示百分比
};
class StatisticsEngine {
public:
    void reset();
    void add(const PacketRecord& record);
    StatisticsSnapshot snapshot() const;
};
RateSample calculateRate(const StatisticsSnapshot& previous,
                         const StatisticsSnapshot& current,
                         double elapsedSeconds);

enum class ReadStatus { Packet, EndOfFile, Error };
struct PcapFileInfo {
    std::uint32_t linkType = 1;
    std::uint32_t snapshotLength = 65535;
    bool nanosecondPrecision = false;
};
class PcapReader {
public:
    PcapReader();
    ~PcapReader();
    PcapReader(const PcapReader&) = delete;
    PcapReader& operator=(const PcapReader&) = delete;
    OperationResult open(const std::filesystem::path& path);
    PcapFileInfo info() const;
    ReadStatus readNext(RawPacket& packet, OperationResult& result);
    void close();
};
struct PcapWriteOptions {
    std::uint32_t linkType = 1;
    std::uint32_t snapshotLength = 65535;
    std::uint64_t maxFileBytes = 1024ULL * 1024 * 1024;
};
class PcapWriter {
public:
    PcapWriter();
    ~PcapWriter();
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;
    OperationResult open(const std::filesystem::path& path,
                         const PcapWriteOptions& options);
    OperationResult write(const RawPacket& packet);
    OperationResult close();
};

enum class ProtocolFilter { All, IPv4, IPv6, Arp, Tcp, Udp, Dns, Other };
struct DisplayFilter {
    ProtocolFilter protocol = ProtocolFilter::All;
    std::optional<std::string> ipAddress;
    std::optional<std::uint16_t> port;
};
bool matchesDisplayFilter(const PacketRecord& record,
                          const DisplayFilter& filter);

struct ResourceSample {
    std::chrono::system_clock::time_point timestamp;
    std::optional<double> cpuPercent;  // 进程占整机总逻辑处理器能力，0..100
    std::optional<std::uint64_t> workingSetBytes;
    std::optional<std::uint64_t> processReadBytes;
    std::optional<std::uint64_t> processWriteBytes;
};
ResourceSample sampleResources();

} // namespace flowguard
