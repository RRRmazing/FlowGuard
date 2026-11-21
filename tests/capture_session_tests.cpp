// Maintainer: He Junjie. AI-assisted deterministic capture tests.
#include "capture/capture_buffer.h"
#include <iostream>
#include <thread>
#include <atomic>

int main()
{
    int errors = 0;
    auto check = [&](bool value, const char* text) {
        if (!value) { ++errors; std::cerr << "FAIL: " << text << '\n'; }
    };
    auto packet = [](std::size_t size) {
        flowguard::RawPacket value;
        value.bytes.assign(size, 42);
        value.capturedLength = static_cast<std::uint32_t>(size);
        value.originalLength = value.capturedLength;
        return value;
    };
    flowguard::capture_detail::CaptureBuffer buffer;
    buffer.reset(2, 8);
    check(buffer.push(packet(4)), "first packet");
    check(buffer.push(packet(4)), "exact byte limit");
    check(!buffer.push(packet(1)), "packet limit drops newest");
    auto status = buffer.snapshot();
    check(status.queuedPackets == 2 && status.queuedBytes == 8 && status.queueDroppedPackets == 1,
          "queue limits and counters");
    flowguard::RawPacket output;
    check(buffer.pop(output) && output.bytes.size() == 4, "pop transfers owned bytes");
    check(buffer.pop(output) && !buffer.pop(output) && output.bytes.size() == 4,
          "empty pop leaves output untouched");
    buffer.reset(10, 6);
    check(buffer.push(packet(4)) && !buffer.push(packet(3)) && buffer.snapshot().queuedPackets == 1,
          "aggregate byte cap independent of packet cap");
    buffer.reset(10, 3);
    check(!buffer.push(packet(4)) && buffer.snapshot().queuedBytes == 0, "single oversize packet");
    auto bad = packet(1); bad.originalLength = 0;
    check(!buffer.push(std::move(bad)), "invalid lengths rejected");
    bad = packet(1); bad.capturedLength = 2; bad.originalLength = 2;
    check(!buffer.push(std::move(bad)), "byte storage and captured length must match");
    status = buffer.snapshot();
    check(status.receivedPackets == status.enqueuedPackets + status.queueDroppedPackets + status.invalidPackets,
          "received partition invariant");
    buffer.reset(32, 128);
    std::atomic<bool> done{false};
    std::uint64_t popped = 0;
    std::thread producer([&] { for (int i = 0; i < 10000; ++i) buffer.push(packet(4)); done = true; });
    while (!done || buffer.snapshot().queuedPackets) {
        if (buffer.pop(output)) ++popped; else std::this_thread::yield();
    }
    producer.join();
    status = buffer.snapshot();
    check(status.receivedPackets == 10000 && status.enqueuedPackets == popped &&
          status.enqueuedPackets + status.queueDroppedPackets == 10000 && status.queuedBytes == 0,
          "concurrent producer/consumer accounting");

    flowguard::CaptureSession session;
    session.stop(); session.stop();
    check(session.status().state == flowguard::CaptureState::Stopped, "idle stop is idempotent");
    flowguard::CaptureOptions options;
    check(session.start(options).code == flowguard::ErrorCode::InvalidArgument, "empty device rejected");
    options.deviceId = "unused"; options.maxQueueBytes = 0;
    check(session.start(options).code == flowguard::ErrorCode::InvalidArgument, "zero queue capacity rejected");
    options.maxQueueBytes = 4; options.snapshotLength = 0;
    check(session.start(options).code == flowguard::ErrorCode::InvalidArgument, "zero snapshot rejected");
    if (!errors) std::cout << "Capture buffer and lifecycle unit tests passed.\n";
    return errors ? 1 : 0;
}
