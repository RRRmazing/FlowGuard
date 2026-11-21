// Maintainer: He Junjie. AI-assisted stage-2 backend, no Qt dependencies.
#include "core/processing_session.h"
#include <algorithm>
#include <atomic>
#include <cmath>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace flowguard {
namespace {
using Steady = std::chrono::steady_clock;
using Wall = std::chrono::system_clock;
OperationResult invalid(const char* text) { return {ErrorCode::InvalidState, text}; }
template<class K> std::map<K, std::uint64_t> difference(
    const std::map<K, std::uint64_t>& a, const std::map<K, std::uint64_t>& b)
{
    auto result = a;
    for (auto& item : result) {
        const auto previous = b.find(item.first);
        if (previous != b.end()) item.second -= previous->second;
    }
    return result;
}
struct Bucket {
    std::uint64_t packets = 0, bytes = 0, dns = 0;
    std::map<NetworkProtocol, std::uint64_t> networks;
    std::map<TransportProtocol, std::uint64_t> transports;
};
}
struct ProcessingSession::Impl {
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::thread worker;
    std::atomic<bool> stopping{false};
    ProcessingSnapshot current;
    ProcessingOptions options;
    StatisticsEngine statistics;
    StatisticsSnapshot previous;
    std::deque<ParsedPacket> pending;
    std::deque<TimeSample> liveHistory;
    std::map<std::int64_t, Bucket> buckets;
    std::optional<std::int64_t> firstSecond, lastSecond;
    CaptureSession capture;
    PcapReader reader;
    PcapWriter writer;
    PcapFileInfo sourceInfo;
    bool infoKnown = false, writerOpen = false, wantSave = false;
    std::uint64_t saveRevision = 0, appliedRevision = 0;
    std::optional<std::filesystem::path> savePath;
    std::uint64_t saveLimit = 0;
    std::optional<std::filesystem::path> appliedPath;
    std::uint64_t appliedLimit = 0;
    Steady::time_point lastSample;
    std::uint64_t sequence = 0;

    bool active() const {
        std::lock_guard<std::mutex> lock(mutex);
        return current.state == ProcessingState::Running || current.state == ProcessingState::Paused;
    }
    OperationResult initialize(const ProcessingOptions& value, ProcessingSource source)
    {
        if (!std::isfinite(value.replaySpeed) || value.replaySpeed < 0.1 || value.replaySpeed > 100 ||
            value.pendingLimit < 1 || value.pendingLimit > 2000 || value.maxSavedBytes < 24 ||
            (value.savePath && value.savePath->empty()))
            return {ErrorCode::InvalidArgument, "invalid processing speed, buffer, or saving options"};
        std::lock_guard<std::mutex> lock(mutex);
        const auto id = current.sessionId + 1;
        current = {}; current.sessionId = id; current.source = source;
        current.state = ProcessingState::Running;
        statistics.reset(); sequence = 0; previous = {}; pending.clear(); liveHistory.clear(); buckets.clear();
        firstSecond.reset(); lastSecond.reset(); options = value;
        savePath = value.savePath; saveLimit = value.maxSavedBytes;
        ++saveRevision; appliedRevision = saveRevision - 1;
        current.savingRequested = savePath.has_value();
        writerOpen = false; wantSave = false; stopping = false;
        lastSample = Steady::now();
        return {};
    }
    OperationResult fail(OperationResult error)
    {
        std::lock_guard<std::mutex> lock(mutex);
        current.state = ProcessingState::Failed; current.error = std::move(error);
        return current.error;
    }
    void closeSave(OperationResult error = {})
    {
        if (writerOpen) {
            const auto closed = writer.close();
            if (error.ok()) error = closed;
        }
        writerOpen = false; wantSave = false;
        std::lock_guard<std::mutex> lock(mutex);
        current.savingActive = false; current.savingRequested = false;
        if (!error.ok()) current.savingError = std::move(error);
    }
    void savingCommands()
    {
        bool changed = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            if (saveRevision != appliedRevision) {
                appliedRevision = saveRevision; appliedPath = savePath; appliedLimit = saveLimit;
                changed = true;
            }
        }
        if (changed) {
            closeSave();
            wantSave = appliedPath.has_value();
            std::lock_guard<std::mutex> lock(mutex);
            current.savingError = {}; current.savingRequested = wantSave;
        }
        if (wantSave && !writerOpen && infoKnown) {
            PcapWriteOptions writeOptions;
            writeOptions.linkType = sourceInfo.linkType;
            writeOptions.snapshotLength = sourceInfo.snapshotLength;
            writeOptions.maxFileBytes = appliedLimit;
            const auto opened = writer.open(*appliedPath, writeOptions);
            if (!opened.ok()) closeSave(opened);
            else {
                writerOpen = true;
                std::lock_guard<std::mutex> lock(mutex);
                current.savingActive = true;
            }
        }
    }
    void process(RawPacket packet)
    {
        if (!infoKnown) {
            sourceInfo.linkType = packet.linkType; infoKnown = true;
        }
        savingCommands();
        auto parsed = parsePacket(packet, ++sequence);
        if (writerOpen) {
            const auto result = writer.write(packet);
            if (!result.ok()) closeSave(result);
            else { std::lock_guard<std::mutex> lock(mutex); ++current.savedPackets; }
        }
        std::lock_guard<std::mutex> lock(mutex);
        const auto& record = parsed.record;
        statistics.add(record);
        if (current.source == ProcessingSource::File) {
            const auto second = std::chrono::duration_cast<std::chrono::seconds>(record.timestamp.time_since_epoch()).count();
            if (!firstSecond || second < *firstSecond) firstSecond = second;
            if (!lastSecond || second > *lastSecond) lastSecond = second;
            const auto oldest = *lastSecond - 3599;
            while (!buckets.empty() && buckets.begin()->first < oldest) buckets.erase(buckets.begin());
            if (second < oldest) ++current.lateHistoryPackets;
            else {
                auto& bucket = buckets[second];
                ++bucket.packets; bucket.bytes += record.originalLength;
                if (record.isDns) ++bucket.dns;
                ++bucket.networks[record.network]; ++bucket.transports[record.transport];
            }
        }
        if (pending.size() == options.pendingLimit) { pending.pop_front(); ++current.displayDroppedPackets; }
        pending.push_back(std::move(parsed));
    }
    void sample(Steady::time_point now)
    {
        if (writerOpen) {
            const auto result = writer.flush();
            if (!result.ok()) closeSave(result);
        }
        std::lock_guard<std::mutex> lock(mutex);
        if (current.source != ProcessingSource::Live) { lastSample = now; return; }
        const double seconds = std::chrono::duration<double>(now - lastSample).count();
        if (seconds <= 0) return;
        auto totals = statistics.snapshot();
        current.rate = calculateRate(previous, totals, seconds);
        liveHistory.push_back({Wall::now(), seconds, current.rate,
            difference(totals.networkCounts, previous.networkCounts),
            difference(totals.transportCounts, previous.transportCounts)});
        if (liveHistory.size() > 3600) liveHistory.pop_front();
        totals.lengthFrequency.clear(); previous = std::move(totals); lastSample = now;
    }
    void run() noexcept
    {
        bool completed = false;
        try {
            std::optional<RawPacket> next;
            std::optional<Wall::time_point> firstTimestamp;
            double activeSeconds = 0;
            auto lastTick = Steady::now();
            bool wasPaused = false;
            for (;;) {
                const auto now = Steady::now();
                bool paused;
                { std::lock_guard<std::mutex> lock(mutex); paused = current.state == ProcessingState::Paused; }
                if (!paused && !wasPaused) activeSeconds += std::chrono::duration<double>(now - lastTick).count();
                lastTick = now; wasPaused = paused;
                savingCommands();
                if (stopping.load()) break;
                if (!paused) {
                    for (int i = 0; i < 500 && !stopping.load(); ++i) {
                        if (current.source == ProcessingSource::Live) {
                            RawPacket raw;
                            if (!capture.tryPop(raw)) break;
                            process(std::move(raw));
                        } else {
                            if (!next) {
                                RawPacket raw; OperationResult result;
                                const auto read = reader.readNext(raw, result);
                                if (read == ReadStatus::Error) { fail(result); stopping = true; break; }
                                if (read == ReadStatus::EndOfFile) { completed = true; stopping = true; break; }
                                next = std::move(raw);
                                if (!firstTimestamp) firstTimestamp = next->timestamp;
                            }
                            const auto due = std::chrono::duration<double>(next->timestamp - *firstTimestamp).count() / options.replaySpeed;
                            if (options.pacedReplay && due > activeSeconds) break;
                            process(std::move(*next)); next.reset();
                        }
                        { std::lock_guard<std::mutex> lock(mutex); if (current.state == ProcessingState::Paused) break; }
                    }
                }
                if (current.source == ProcessingSource::Live && capture.status().state == CaptureState::Failed) {
                    fail(capture.status().lastError); stopping = true;
                }
                if (now - lastSample >= std::chrono::seconds(1)) sample(now);
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait_for(lock, std::chrono::milliseconds(10));
            }
            if (current.source == ProcessingSource::Live) {
                capture.stop(); RawPacket raw;
                while (capture.tryPop(raw)) process(std::move(raw));
                sample(Steady::now());
            }
        } catch (const std::exception& error) {
            try { fail({ErrorCode::ResourceLimit, error.what()}); } catch (...) {}
        } catch (...) {
            try { fail({ErrorCode::InvalidState, "unexpected processing worker failure"}); } catch (...) {}
        }
        capture.stop(); reader.close(); closeSave();
        std::lock_guard<std::mutex> lock(mutex);
        if (current.state != ProcessingState::Failed)
            current.state = completed ? ProcessingState::Completed : ProcessingState::Stopped;
    }
};

ProcessingSession::ProcessingSession() : impl_(std::make_unique<Impl>()) {}
ProcessingSession::~ProcessingSession() { stop(); }
OperationResult ProcessingSession::startLive(const CaptureOptions& captureOptions, const ProcessingOptions& options)
{
    if (impl_->active()) return invalid("processing session is already active");
    stop();
    auto result = impl_->initialize(options, ProcessingSource::Live);
    if (!result.ok()) return result;
    result = impl_->capture.start(captureOptions);
    if (!result.ok()) return impl_->fail(result);
    impl_->infoKnown = false; impl_->sourceInfo.snapshotLength = captureOptions.snapshotLength;
    try { impl_->worker = std::thread([this] { impl_->run(); }); }
    catch (const std::exception& error) { impl_->capture.stop(); return impl_->fail({ErrorCode::ResourceLimit, error.what()}); }
    return {};
}
OperationResult ProcessingSession::startFile(const std::filesystem::path& path, const ProcessingOptions& options)
{
    if (impl_->active()) return invalid("processing session is already active");
    stop();
    auto result = impl_->initialize(options, ProcessingSource::File);
    if (!result.ok()) return result;
    result = impl_->reader.open(path);
    if (!result.ok()) return impl_->fail(result);
    impl_->sourceInfo = impl_->reader.info(); impl_->infoKnown = true;
    try { impl_->worker = std::thread([this] { impl_->run(); }); }
    catch (const std::exception& error) { impl_->reader.close(); return impl_->fail({ErrorCode::ResourceLimit, error.what()}); }
    return {};
}
OperationResult ProcessingSession::pause()
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->current.source != ProcessingSource::File ||
        (impl_->current.state != ProcessingState::Running && impl_->current.state != ProcessingState::Paused))
        return invalid("only active file playback can be paused");
    impl_->current.state = ProcessingState::Paused; impl_->wake.notify_all(); return {};
}
OperationResult ProcessingSession::resume()
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->current.source != ProcessingSource::File ||
        (impl_->current.state != ProcessingState::Running && impl_->current.state != ProcessingState::Paused))
        return invalid("only active file playback can resume");
    impl_->current.state = ProcessingState::Running; impl_->wake.notify_all(); return {};
}
OperationResult ProcessingSession::enableSaving(const std::filesystem::path& path, std::uint64_t maxBytes)
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->current.state != ProcessingState::Running && impl_->current.state != ProcessingState::Paused)
        return invalid("saving requires an active session");
    if (path.empty() || maxBytes < 24) return {ErrorCode::InvalidArgument, "invalid save path or limit"};
    impl_->savePath = path; impl_->saveLimit = maxBytes; ++impl_->saveRevision;
    impl_->wake.notify_all(); return {};
}
void ProcessingSession::disableSaving()
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->savePath.reset(); ++impl_->saveRevision; impl_->wake.notify_all();
}
void ProcessingSession::stop()
{
    impl_->stopping = true; impl_->wake.notify_all();
    if (impl_->worker.joinable()) impl_->worker.join();
}
ProcessingSnapshot ProcessingSession::snapshot() const
{
    std::unique_lock<std::mutex> lock(impl_->mutex);
    auto result = impl_->current; result.statistics = impl_->statistics.snapshot();
    if (result.source == ProcessingSource::Live) result.history.assign(impl_->liveHistory.begin(), impl_->liveHistory.end());
    else if (impl_->firstSecond && impl_->lastSecond) {
        const auto start = (std::max)(*impl_->firstSecond, *impl_->lastSecond - 3599);
        for (auto second = start; second <= *impl_->lastSecond; ++second) {
            TimeSample point; point.timestamp = Wall::time_point(std::chrono::seconds(second));
            const auto found = impl_->buckets.find(second);
            if (found != impl_->buckets.end()) {
                const auto& bucket = found->second;
                point.rate = {static_cast<double>(bucket.packets), static_cast<double>(bucket.bytes),
                    bucket.packets ? static_cast<double>(bucket.dns) / static_cast<double>(bucket.packets) : 0};
                point.networkCounts = bucket.networks; point.transportCounts = bucket.transports;
            }
            result.history.push_back(std::move(point));
        }
        if (!result.history.empty()) result.rate = result.history.back().rate;
    }
    lock.unlock();
    if (result.source == ProcessingSource::Live) result.capture = impl_->capture.status();
    return result;
}
PacketBatch ProcessingSession::takePackets(std::size_t maxPackets)
{
    std::lock_guard<std::mutex> lock(impl_->mutex);
    PacketBatch batch; batch.sessionId = impl_->current.sessionId;
    const auto count = (std::min)({maxPackets, std::size_t{500}, impl_->pending.size()});
    batch.packets.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        batch.packets.push_back(std::move(impl_->pending.front())); impl_->pending.pop_front();
    }
    return batch;
}
} // namespace flowguard
