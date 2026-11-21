// Maintainer: He Junjie. AI-assisted capture implementation.
#pragma once
#include "core/module_contracts.h"
#include <deque>
#include <mutex>
#include <utility>

namespace flowguard::capture_detail {
// Private to capture; a single lock makes counters and queue sizes consistent.
class CaptureBuffer {
public:
    void reset(std::size_t packets, std::size_t bytes)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.clear();
        status_ = {};
        maxPackets_ = packets;
        maxBytes_ = bytes;
    }
    void invalid()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++status_.receivedPackets;
        ++status_.invalidPackets;
    }
    bool push(RawPacket packet)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++status_.receivedPackets;
        if (packet.bytes.size() != packet.capturedLength ||
            packet.capturedLength > packet.originalLength) {
            ++status_.invalidPackets;
            return false;
        }
        const auto bytes = packet.bytes.size();
        if (queue_.size() >= maxPackets_ || bytes > maxBytes_ ||
            status_.queuedBytes > maxBytes_ - bytes) {
            ++status_.queueDroppedPackets;
            return false;
        }
        queue_.push_back(std::move(packet));
        ++status_.enqueuedPackets;
        status_.queuedBytes += bytes;
        status_.queuedPackets = queue_.size();
        return true;
    }
    bool pop(RawPacket& packet)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.empty()) return false;
        status_.queuedBytes -= queue_.front().bytes.size();
        packet = std::move(queue_.front());
        queue_.pop_front();
        status_.queuedPackets = queue_.size();
        return true;
    }
    CaptureStatus snapshot() const
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return status_;
    }
private:
    mutable std::mutex mutex_;
    std::deque<RawPacket> queue_;
    CaptureStatus status_;
    std::size_t maxPackets_ = 8192;
    std::size_t maxBytes_ = 64 * 1024 * 1024;
};
} // namespace flowguard::capture_detail
