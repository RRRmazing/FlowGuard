#include "alerts/alert_engine.h"
#include "core/module_contracts.h"
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace flowguard {
using Time = std::chrono::system_clock::time_point;
using Seconds = std::chrono::seconds;
AlertRules defaultAlertRules() {
    return {{{true,5,500},{true,5,300},{true,10,20},{true,5,1000},{true,60,1}}};
}
AlertEngine::AlertEngine(AlertRule rule, AlertRuleConfig config) : rule_(rule), config_(config) {}
void AlertEngine::expireOne() {
    const auto e = std::move(events_.front()); events_.pop_front();
    const auto found = groups_.find(e.key);
    if (found == groups_.end()) return;
    auto& g = found->second;
    --g.count;
    if (rule_ == AlertRule::PortScan) {
        auto p = g.ports.find(e.port);
        if (p != g.ports.end() && --p->second == 0) g.ports.erase(p);
    }
    const auto a = alerts_.find(e.key);
    if (a != alerts_.end()) {
        a->second.current = rule_ == AlertRule::PortScan ? g.ports.size() : g.count;
        a->second.active = a->second.current >= config_.threshold;
    }
    if (!g.count) groups_.erase(found);
}
void AlertEngine::advance(Time time) {
    if (now_ && time < *now_) return;
    now_ = time;
    while (!events_.empty() && events_.front().time <= time - Seconds(config_.windowSeconds)) expireOne();
}
void AlertEngine::add(const PacketRecord& r) {
    if (!config_.enabled) return;
    // The live idle clock may be ahead of a queued packet. Only packet-to-packet
    // timestamp rollback is disorder; a delayed packet inside the current window is valid.
    if (lastPacket_ && r.timestamp < *lastPacket_) { ++late_; return; }
    lastPacket_ = r.timestamp;
    advance(r.timestamp);
    if (now_ && r.timestamp <= *now_ - Seconds(config_.windowSeconds) && rule_ != AlertRule::Arp) return;
    if (r.status != ParseStatus::Complete) return;
    const bool syn = r.transport == TransportProtocol::Tcp && r.tcpFlags &&
        ((*r.tcpFlags & 0x17) == 0x02); // Initial SYN, excludes ACK/FIN/RST.
    std::string key, evidence;
    if (rule_ == AlertRule::Syn && syn && r.destinationPort) key = r.destinationIp + ":" + std::to_string(*r.destinationPort);
    if (rule_ == AlertRule::Echo && r.icmpCode == 0 &&
        ((r.transport == TransportProtocol::Icmp && r.icmpType == 8) ||
         (r.transport == TransportProtocol::Icmpv6 && r.icmpType == 128))) key = r.destinationIp;
    if (rule_ == AlertRule::PortScan && syn && r.destinationPort && !r.sourceIp.empty()) key = r.sourceIp + ">" + r.destinationIp;
    if (rule_ == AlertRule::Udp && r.transport == TransportProtocol::Udp && r.destinationPort) key = r.destinationIp + ":" + std::to_string(*r.destinationPort);
    if (rule_ == AlertRule::Arp && r.network == NetworkProtocol::Arp &&
        (r.arpOpcode == 1 || r.arpOpcode == 2) && !r.arpSenderMac.empty() &&
        !r.sourceIp.empty() && r.sourceIp != "0.0.0.0" && r.arpSenderMac != "00:00:00:00:00:00" &&
        r.arpSenderMac != "ff:ff:ff:ff:ff:ff") {
        for (auto i = mappings_.begin(); i != mappings_.end();) {
            if (i->second.last <= r.timestamp - Seconds(300)) i = mappings_.erase(i); else ++i;
        }
        const auto old = mappings_.find(r.sourceIp);
        if (old == mappings_.end()) {
            if (mappings_.size() >= 4096) { ++limited_; return; }
            mappings_[r.sourceIp] = {r.arpSenderMac,r.timestamp}; return;
        }
        if (old->second.mac != r.arpSenderMac) {
            key = r.sourceIp;
            evidence = old->second.mac + " -> " + r.arpSenderMac;
        }
        old->second = {r.arpSenderMac,r.timestamp};
    }
    if (key.empty() || (now_ && r.timestamp <= *now_ - Seconds(config_.windowSeconds))) return;
    if (groups_.find(key) == groups_.end() && groups_.size() >= 4096) { ++limited_; return; }
    if (events_.size() >= 100000) { expireOne(); ++limited_; }
    events_.push_back({r.timestamp,key,r.destinationPort.value_or(0)});
    auto& group = groups_[key]; ++group.count;
    if (rule_ == AlertRule::PortScan) ++group.ports[r.destinationPort.value_or(0)];
    const std::uint64_t value = rule_ == AlertRule::PortScan ? group.ports.size() : group.count;
    auto found = alerts_.find(key);
    if (found != alerts_.end()) {
        found->second.current = value;
        found->second.active = value >= config_.threshold;
    }
    if (value < config_.threshold) return;
    if (found == alerts_.end()) {
        if (alerts_.size() >= 1000) { ++limited_; return; }
        AlertRecord a; a.rule = rule_; a.key = key; a.first = r.timestamp; a.config = config_;
        a.sourceIp = rule_ == AlertRule::PortScan ? r.sourceIp : "";
        a.targetIp = rule_ == AlertRule::Arp ? r.sourceIp : r.destinationIp;
        if (rule_ == AlertRule::Syn || rule_ == AlertRule::Udp) a.targetPort = r.destinationPort;
        found = alerts_.emplace(key,std::move(a)).first;
    }
    auto& a = found->second; a.last = r.timestamp; a.current = value;
    a.peak = (std::max)(a.peak,value); a.active = true; a.packetSequence = r.sequence;
    if (!evidence.empty()) a.evidence = std::move(evidence);
}
std::vector<AlertRecord> AlertEngine::records() const {
    std::vector<AlertRecord> result;
    for (const auto& item : alerts_) result.push_back(item.second);
    return result;
}
void AlertEngine::discardInactive() {
    for(auto i=alerts_.begin();i!=alerts_.end();) if(!i->second.active)i=alerts_.erase(i);else ++i;
}

struct AlertMonitor::Impl {
    mutable std::mutex mutex;
    std::condition_variable wake;
    bool exiting = false;
    std::thread worker;
    AlertSnapshot state;
    std::filesystem::path path;
    std::uintmax_t fileSize = 0;
    std::filesystem::file_time_type fileTime{};
    std::array<std::unique_ptr<AlertEngine>,alertRuleCount> engines;
    std::deque<PacketRecord> recent;
    std::optional<Time> latest;
    std::uint64_t generation = 0;
    Impl() {
        resetEngines();
        worker = std::thread([this]{ run(); });
    }
    void resetEngines() {
        for (std::size_t i=0;i<alertRuleCount;++i) engines[i] = std::make_unique<AlertEngine>(AlertRule(i),state.rules[i]);
    }
    bool dirty() const { return std::any_of(state.rebuilding.begin(),state.rebuilding.end(),[](bool b){return b;}); }
    void schedule(const AlertRules& rules, bool force) {
        const auto old = state.rules;
        ++state.revision; state.rules = rules; state.error.clear();
        for (std::size_t i=0;i<alertRuleCount;++i) if (force || old[i]!=rules[i] || state.rebuilding[i]) {
            if (state.file && rules[i].enabled && state.processedPackets) state.rebuilding[i]=true;
            else {
                auto engine = std::make_unique<AlertEngine>(AlertRule(i),rules[i]);
                for (const auto& r : recent) engine->add(r);
                if (latest) engine->advance(*latest);
                engine->discardInactive();
                engines[i]=std::move(engine); state.rebuilding[i]=false;
            }
        }
        wake.notify_all();
    }
    void run() noexcept {
        for (;;) {
            std::unique_lock<std::mutex> lock(mutex);
            wake.wait(lock,[this]{return exiting || (dirty() && !state.paused);});
            if (exiting) return;
            const auto gen = generation, revision = state.revision;
            const auto scanPath = path;
            const auto affected = state.rebuilding;
            const auto rules = state.rules;
            const auto expectedSize = fileSize;
            const auto expectedTime = fileTime;
            lock.unlock();
            try {
                std::array<std::unique_ptr<AlertEngine>,alertRuleCount> rebuilt;
                for (std::size_t i=0;i<alertRuleCount;++i)
                    if (affected[i]) rebuilt[i] = std::make_unique<AlertEngine>(AlertRule(i),rules[i]);
                PcapReader reader;
                auto error = reader.open(scanPath);
                auto unchanged = [&] {
                    std::error_code ec;
                    const auto size = std::filesystem::file_size(scanPath,ec);
                    if(ec || size!=expectedSize) return false;
                    const auto time = std::filesystem::last_write_time(scanPath,ec);
                    return !ec && time==expectedTime;
                };
                if(error.ok() && !unchanged()) error={ErrorCode::IoError,"PCAP was changed or replaced; reopen the file before re-analysis"};
                std::uint64_t count = 0;
                bool cancelled = false;
                while (error.ok()) {
                    std::uint64_t target;
                    {
                        std::lock_guard<std::mutex> guard(mutex);
                        if (exiting || gen != generation || revision != state.revision) { cancelled = true; break; }
                        target = state.processedPackets;
                        if (count == target) {
                            if(!unchanged()) { error={ErrorCode::IoError,"PCAP changed during re-analysis; reopen the file"}; break; }
                            for (std::size_t i=0;i<alertRuleCount;++i) if (affected[i]) {
                                engines[i] = std::move(rebuilt[i]); state.rebuilding[i] = false;
                            }
                            state.error.clear();
                            break;
                        }
                    }
                    const auto batchEnd = (std::min)(target,count+256);
                    while (count < batchEnd) {
                        RawPacket raw;
                        const auto status = reader.readNext(raw,error);
                        if (status != ReadStatus::Packet) {
                            if (error.ok()) error = {ErrorCode::IoError,"PCAP ended before the previously processed packet count"};
                            break;
                        }
                        auto packet = parsePacket(raw,++count).record;
                        for (auto& engine : rebuilt) if (engine) engine->add(packet);
                    }
                }
                if (!cancelled && !error.ok()) {
                    std::lock_guard<std::mutex> guard(mutex);
                    if (gen == generation && revision == state.revision) {
                        state.error = error.message; state.rebuilding.fill(false);
                    }
                }
            } catch (const std::exception& error) {
                std::lock_guard<std::mutex> guard(mutex);
                if (gen == generation && revision == state.revision) { state.error = error.what(); state.rebuilding.fill(false); }
            }
        }
    }
};
AlertMonitor::AlertMonitor() : impl_(std::make_unique<Impl>()) {}
AlertMonitor::~AlertMonitor() {
    { std::lock_guard<std::mutex> lock(impl_->mutex); impl_->exiting=true; }
    impl_->wake.notify_all(); impl_->worker.join();
}
void AlertMonitor::begin(std::uint64_t session, const std::filesystem::path& file) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    ++impl_->generation;
    const auto rules = impl_->state.rules;
    impl_->state = {}; impl_->state.rules = rules; impl_->state.sessionId = session;
    impl_->path = file; impl_->state.file = !file.empty();
    if (!file.empty()) {
        std::error_code ec;
        impl_->fileSize = std::filesystem::file_size(file,ec);
        impl_->fileTime = std::filesystem::last_write_time(file,ec);
    }
    impl_->recent.clear(); impl_->latest.reset(); impl_->resetEngines(); impl_->wake.notify_all();
}
void AlertMonitor::add(const PacketRecord& r) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->state.processedPackets = r.sequence;
    if(r.status != ParseStatus::Complete) ++impl_->state.ignoredPackets;
    if (!impl_->latest || r.timestamp > *impl_->latest) impl_->latest = r.timestamp;
    if (!impl_->state.file) {
        // Keep all supported packet types even for disabled rules, so enabling can re-evaluate.
        if (r.timestamp >= *impl_->latest - Seconds(360)) {
            auto compact = r; compact.summary.clear(); compact.diagnostic.clear();
            impl_->recent.push_back(std::move(compact));
        }
        while (!impl_->recent.empty() && (impl_->recent.front().timestamp <= *impl_->latest - Seconds(360) || impl_->recent.size()>100000)) {
            if (impl_->recent.size()>100000) ++impl_->state.limited;
            impl_->recent.pop_front();
        }
    }
    if (!impl_->state.paused) for (auto& engine : impl_->engines) engine->add(r);
}
void AlertMonitor::advance(Time time) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state.file) return;
    if (!impl_->latest || time > *impl_->latest) impl_->latest = time;
    if (!impl_->state.paused) for (auto& engine : impl_->engines) engine->advance(time);
    while (!impl_->recent.empty() && impl_->recent.front().timestamp <= time - Seconds(360)) impl_->recent.pop_front();
}
void AlertMonitor::finish() {
    std::lock_guard<std::mutex> lock(impl_->mutex); impl_->state.finished = true;
}
bool AlertMonitor::configure(const AlertRules& rules) {
    for (std::size_t i=0;i<rules.size();++i) {
        const auto& r=rules[i];
        if (r.windowSeconds<1 || r.windowSeconds>60 || r.threshold<1 || r.threshold>(i==2?65536u:100000u)) return false;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->state.rules == rules && impl_->state.error.empty()) return true;
    impl_->schedule(rules,!impl_->state.error.empty()); return true;
}
void AlertMonitor::setPaused(bool paused) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if(impl_->state.paused == paused) return;
    impl_->state.paused = paused;
    if(paused) ++impl_->state.revision; // Cancel any in-flight publication.
    else impl_->schedule(impl_->state.rules,true); // Re-evaluate the retained live window / processed file prefix.
}
AlertSnapshot AlertMonitor::snapshot() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto result = impl_->state;
    for (const auto& engine : impl_->engines) {
        const auto records = engine->records(); result.records.insert(result.records.end(),records.begin(),records.end());
        result.latePackets += engine->latePackets(); result.limited += engine->limited();
    }
    std::sort(result.records.begin(),result.records.end(),[](const auto& a,const auto& b){return a.last>b.last;});
    return result;
}
} // namespace flowguard
