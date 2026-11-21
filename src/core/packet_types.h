#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace flowguard {

// Own the bytes: Npcap's temporary buffer must never cross a thread boundary.
struct RawPacket {
    std::chrono::system_clock::time_point timestamp;
    std::uint32_t originalLength = 0;
    std::uint32_t capturedLength = 0;
    std::uint32_t linkType = 1; // DLT_EN10MB; other link types need explicit handling.
    std::vector<std::uint8_t> bytes;
};

enum class NetworkProtocol { Other, Arp, IPv4, IPv6 };
enum class TransportProtocol { Other, Tcp, Udp, Icmp, Icmpv6 };
enum class ParseStatus { Complete, Truncated, Unsupported, Malformed };

// Missing fields stay empty; zero is a valid field value, not an error marker.
struct PacketRecord {
    std::uint64_t sequence = 0;
    std::chrono::system_clock::time_point timestamp;
    std::uint32_t originalLength = 0;
    std::uint32_t capturedLength = 0;
    NetworkProtocol network = NetworkProtocol::Other;
    TransportProtocol transport = TransportProtocol::Other;
    ParseStatus status = ParseStatus::Unsupported;
    std::string sourceMac;
    std::string destinationMac;
    std::optional<std::uint16_t> etherType;
    std::string sourceIp;
    std::string destinationIp;
    std::optional<std::uint8_t> ipVersion;
    std::optional<std::uint8_t> ttlOrHopLimit;
    std::optional<std::uint8_t> ipProtocol;
    std::optional<std::uint16_t> sourcePort;
    std::optional<std::uint16_t> destinationPort;
    std::optional<std::uint8_t> tcpFlags;
    bool isDns = false;
    std::string summary;
    std::string diagnostic;
};

} // namespace flowguard
