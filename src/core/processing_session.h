// Maintainer: He Junjie. Stage-2 backend / stage-3 Qt handoff contract.
#pragma once
#include "core/module_contracts.h"

namespace flowguard {
enum class ProcessingState { Idle, Running, Paused, Stopped, Completed, Failed };
enum class ProcessingSource { None, Live, File };
struct ProcessingOptions {
    bool pacedReplay = false;
    double replaySpeed = 1.0;
    std::size_t pendingLimit = 2000;
    std::optional<std::filesystem::path> savePath;
    std::uint64_t maxSavedBytes = 1024ULL * 1024 * 1024;
};
struct TimeSample {
    std::chrono::system_clock::time_point timestamp;
    double intervalSeconds = 1;
    RateSample rate;
    std::map<NetworkProtocol, std::uint64_t> networkCounts;
    std::map<TransportProtocol, std::uint64_t> transportCounts;
};
struct ProcessingSnapshot {
    std::uint64_t sessionId = 0;
    ProcessingSource source = ProcessingSource::None;
    ProcessingState state = ProcessingState::Idle;
    StatisticsSnapshot statistics;
    RateSample rate;
    std::vector<TimeSample> history;
    CaptureStatus capture;
    OperationResult error;
    OperationResult savingError; // Saving failure does not stop analysis/capture.
    bool savingRequested = false;
    bool savingActive = false;
    std::uint64_t savedPackets = 0;
    std::uint64_t displayDroppedPackets = 0;
    std::uint64_t lateHistoryPackets = 0;
};
struct PacketBatch {
    std::uint64_t sessionId = 0;
    std::vector<ParsedPacket> packets;
};
class ProcessingSession {
public:
    ProcessingSession();
    ~ProcessingSession();
    ProcessingSession(const ProcessingSession&) = delete;
    ProcessingSession& operator=(const ProcessingSession&) = delete;
    OperationResult startLive(const CaptureOptions&, const ProcessingOptions& = {});
    OperationResult startFile(const std::filesystem::path&, const ProcessingOptions& = {});
    OperationResult pause();  // File source only; idempotent when already paused.
    OperationResult resume(); // File source only; idempotent when already running.
    OperationResult enableSaving(const std::filesystem::path&, std::uint64_t maxBytes = 1024ULL * 1024 * 1024);
    void disableSaving(); // Saving commands are acknowledged asynchronously in snapshot().
    void stop();          // Joins worker, drains live queue, flushes/closes writer.
    ProcessingSnapshot snapshot() const;
    PacketBatch takePackets(std::size_t maxPackets = 500);
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace flowguard
