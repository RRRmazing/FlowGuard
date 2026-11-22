#pragma once
#include "core/packet_types.h"
#include <array>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>

namespace flowguard {
enum class AlertRule { Syn, Echo, PortScan, Udp, Arp };
constexpr std::size_t alertRuleCount = 5;
struct AlertRuleConfig {
    bool enabled = true;
    unsigned windowSeconds = 5;
    std::uint64_t threshold = 500; // Trigger at or above threshold.
    bool operator==(const AlertRuleConfig& b) const {
        return enabled == b.enabled && windowSeconds == b.windowSeconds && threshold == b.threshold;
    }
    bool operator!=(const AlertRuleConfig& b) const { return !(*this == b); }
};
using AlertRules = std::array<AlertRuleConfig, alertRuleCount>;
AlertRules defaultAlertRules();
struct AlertRecord {
    AlertRule rule = AlertRule::Syn;
    std::string key, sourceIp, targetIp;
    std::optional<std::uint16_t> targetPort;
    std::chrono::system_clock::time_point first, last;
    std::uint64_t peak = 0, current = 0, packetSequence = 0;
    AlertRuleConfig config;
    bool active = false;
    std::string evidence;
};
// One rule's bounded event-time window. Caller serializes access.
class AlertEngine {
public:
    AlertEngine(AlertRule rule, AlertRuleConfig config);
    void add(const PacketRecord&);
    void advance(std::chrono::system_clock::time_point);
    std::vector<AlertRecord> records() const;
    void discardInactive(); // Live rule edits re-evaluate the current window only.
    std::uint64_t latePackets() const { return late_; }
    std::uint64_t limited() const { return limited_; }
private:
    struct Event { std::chrono::system_clock::time_point time; std::string key; std::uint16_t port; };
    struct Group { std::uint64_t count = 0; std::map<std::uint16_t, unsigned> ports; };
    struct Mapping { std::string mac; std::chrono::system_clock::time_point last; };
    AlertRule rule_;
    AlertRuleConfig config_;
    std::optional<std::chrono::system_clock::time_point> now_, lastPacket_;
    std::deque<Event> events_;
    std::map<std::string, Group> groups_;
    std::map<std::string, AlertRecord> alerts_;
    std::map<std::string, Mapping> mappings_;
    std::uint64_t late_ = 0, limited_ = 0;
    void expireOne();
};
struct AlertSnapshot {
    std::uint64_t sessionId = 0, revision = 0, processedPackets = 0;
    AlertRules rules = defaultAlertRules();
    std::array<bool, alertRuleCount> rebuilding{};
    std::vector<AlertRecord> records;
    std::uint64_t latePackets = 0, limited = 0, ignoredPackets = 0;
    bool paused = false, file = false, finished = false;
    std::string error;
};
// Owns an independent cancellable PCAP rescan worker; never modifies normal statistics.
class AlertMonitor {
public:
    AlertMonitor();
    ~AlertMonitor();
    void begin(std::uint64_t session, const std::filesystem::path& file = {});
    void add(const PacketRecord&);
    void advance(std::chrono::system_clock::time_point);
    void finish();
    bool configure(const AlertRules&);
    void setPaused(bool);
    AlertSnapshot snapshot() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace flowguard
