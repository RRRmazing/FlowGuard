// Maintainer: He Junjie. AI-assisted real Npcap loopback integration tests.
#include <winsock2.h>
#include "core/module_contracts.h"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>

int main()
{
    using namespace flowguard;
    using namespace std::chrono;
    const auto devices = enumerateDevices();
    if (!devices.result.ok()) { std::cerr << devices.result.message << '\n'; return 1; }
    auto device = std::find_if(devices.devices.begin(), devices.devices.end(),
                              [](const auto& d) { return d.loopback; });
    if (device == devices.devices.end()) { std::cout << "SKIP: no loopback adapter\n"; return 77; }
    WSADATA winsock{};
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return 1;
    struct SocketScope {
        SOCKET receiver = INVALID_SOCKET, sender = INVALID_SOCKET;
        ~SocketScope() {
            if (receiver != INVALID_SOCKET) closesocket(receiver);
            if (sender != INVALID_SOCKET) closesocket(sender);
            WSACleanup();
        }
    } sockets;
    sockets.receiver = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockets.sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in target{}; target.sin_family = AF_INET; target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (sockets.receiver == INVALID_SOCKET || sockets.sender == INVALID_SOCKET ||
        bind(sockets.receiver, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != 0) return 1;
    int targetLength = sizeof(target);
    if (getsockname(sockets.receiver, reinterpret_cast<sockaddr*>(&target), &targetLength) != 0) return 1;
    int errors = 0;
    auto check = [&](bool value, const char* text) {
        if (!value) { ++errors; std::cerr << "FAIL: " << text << '\n'; }
    };
    CaptureOptions options; options.deviceId = device->id;
    options.bpfExpression = "udp and dst port " + std::to_string(ntohs(target.sin_port));
    const std::string marker = "FlowGuard-owned-loopback-test-20261121";
    auto sendTraffic = [&] {
        for (int i = 0; i < 16; ++i) {
            check(sendto(sockets.sender, marker.data(), static_cast<int>(marker.size()), 0,
                reinterpret_cast<sockaddr*>(&target), sizeof(target)) == static_cast<int>(marker.size()),
                "send test traffic only to owned localhost UDP socket");
            std::this_thread::sleep_for(milliseconds(5));
        }
    };
    CaptureSession session;
    auto start = session.start(options);
    if (!start.ok()) { std::cerr << start.message << '\n'; return 1; }
    check(session.start(options).code == ErrorCode::InvalidState, "duplicate start");
    sendTraffic();
    const auto deadline = steady_clock::now() + seconds(2);
    while (!session.status().enqueuedPackets && steady_clock::now() < deadline)
        std::this_thread::sleep_for(milliseconds(10));
    session.stop(); session.stop();
    RawPacket packet;
    std::size_t count = 0;
    while (session.tryPop(packet)) {
        ++count;
        check(packet.bytes.size() == packet.capturedLength && packet.capturedLength <= packet.originalLength,
              "actual lengths and owned bytes");
        check(packet.timestamp.time_since_epoch() > system_clock::duration::zero() &&
              packet.timestamp < system_clock::now() + seconds(10), "actual timestamp");
        check(std::search(packet.bytes.begin(), packet.bytes.end(), marker.begin(), marker.end()) != packet.bytes.end(),
              "BPF matched our own payload, without parsing protocols");
    }
    check(count > 0 && session.status().state == CaptureState::Stopped, "capture and drain after stop");

    start = session.start(options);
    check(start.ok() && session.status().receivedPackets == 0 && !session.tryPop(packet), "restart resets queue/counters");
    auto before = steady_clock::now(); session.stop();
    const auto stopMs = duration_cast<milliseconds>(steady_clock::now() - before).count();
    check(stopMs < 2000, "idle stop under two seconds");

    auto bad = options; bad.bpfExpression = "udp and (";
    check(session.start(bad).code == ErrorCode::FilterError, "invalid BPF rejected");
    bad = options; bad.deviceId = "\\Device\\NPF_{00000000-0000-0000-0000-000000000000}";
    check(session.start(bad).code == ErrorCode::DeviceError, "invalid adapter rejected");

    options.maxQueuePackets = 1;
    check(session.start(options).ok(), "recovery after failed start");
    sendTraffic(); std::this_thread::sleep_for(milliseconds(100)); session.stop();
    auto status = session.status();
    check(status.queuedPackets == 1 && status.queueDroppedPackets > 0, "live packet cap and drop counter");
    check(status.receivedPackets == status.enqueuedPackets + status.queueDroppedPackets + status.invalidPackets,
          "live counter partition");
    options.maxQueuePackets = 100; options.maxQueueBytes = 1;
    check(session.start(options).ok(), "byte cap start");
    sendTraffic(); std::this_thread::sleep_for(milliseconds(100)); session.stop();
    status = session.status();
    check(status.queuedBytes == 0 && status.enqueuedPackets == 0 && status.queueDroppedPackets > 0,
          "live byte cap drops oversize packets");
    { CaptureSession scoped; check(scoped.start(options).ok(), "destructor stop start"); }
    std::cout << "Captured owned loopback packets: " << count << "; idle stop ms: " << stopMs
              << "; failures: " << errors << '\n';
    return errors ? 1 : 0;
}
