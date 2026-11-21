// Maintainer: He Junjie. AI-assisted real Npcap loopback integration tests.
#include <winsock2.h>
#include "core/module_contracts.h"
#include "parser/packet_parser.h"
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
        const auto parsed=parsePacket(packet,count);
        check(parsed.record.sequence==count && parsed.record.timestamp==packet.timestamp &&
              parsed.record.originalLength==packet.originalLength && parsed.record.capturedLength==packet.capturedLength,
              "shared API retains capture metadata");
        if (packet.linkType==1) {
            check(parsed.record.status==ParseStatus::Complete && parsed.record.transport==TransportProtocol::Udp &&
                  parsed.record.destinationPort==ntohs(target.sin_port), "Ethernet live UDP parsed correctly");
        } else {
            check(parsed.record.status==ParseStatus::Unsupported && parsed.fields.empty(),
                  "unsupported loopback DLT is explicit, never guessed as Ethernet");
        }
        if (count==1) std::cout << "Actual loopback DLT=" << packet.linkType << "; parse status=" << static_cast<int>(parsed.record.status) << '\n';
        check(packet.bytes.size() == packet.capturedLength && packet.capturedLength <= packet.originalLength,
              "actual lengths and owned bytes");
        check(packet.timestamp.time_since_epoch() > system_clock::duration::zero() &&
              packet.timestamp < system_clock::now() + seconds(10), "actual timestamp");
        check(std::search(packet.bytes.begin(), packet.bytes.end(), marker.begin(), marker.end()) != packet.bytes.end(),
              "BPF matched our own payload, without parsing protocols");
    }
    check(count > 0 && session.status().state == CaptureState::Stopped, "capture and drain after stop");

    std::cout << "Capture/parser integration failures: " << errors << '\n';
    return errors ? 1 : 0;
}
