#include "parser/packet_parser.h"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace flowguard {
namespace {
struct Failure { ParseStatus status; const char* message; };
struct Reader {
    const std::vector<std::uint8_t>& b;
    std::size_t end;
    void need(std::size_t p, std::size_t n) const {
        if (p > end || n > end - p) throw Failure{ParseStatus::Truncated, "captured bytes end inside header or payload"};
    }
    unsigned u8(std::size_t p) const { need(p, 1); return b[p]; }
    unsigned u16(std::size_t p) const { need(p, 2); return (b[p] << 8) | b[p + 1]; }
};
void malformed(const char* message) { throw Failure{ParseStatus::Malformed, message}; }
std::string mac(const Reader& r, std::size_t p) {
    r.need(p, 6); std::ostringstream s;
    for (unsigned i = 0; i < 6; ++i) { if (i) s << ':'; s << std::hex << std::setfill('0') << std::setw(2) << r.u8(p+i); }
    return s.str();
}
std::string ip(const Reader& r, std::size_t p, bool v6) {
    r.need(p, v6 ? 16 : 4); std::ostringstream s;
    for (unsigned i = 0; i < (v6 ? 8u : 4u); ++i) {
        if (i) s << (v6 ? ':' : '.');
        if (v6) s << std::hex << r.u16(p + i*2); else s << r.u8(p+i);
    }
    return s.str();
}
// Validate DNS names, including compression pointers, without recursive calls.
std::size_t name(const Reader& r, std::size_t p, std::size_t base) {
    std::size_t next = p, expanded = 0;
    bool jumped = false;
    for (std::size_t steps = 0; steps <= r.end - base; ++steps) {
        const auto n = r.u8(p++);
        if (!n) return jumped ? next : p;
        if ((n & 0xc0) == 0xc0) {
            const auto target = ((n & 0x3f) << 8) | r.u8(p++);
            if (base + target >= p - 2) malformed("DNS pointer must refer to a prior name");
            if (!jumped) next = p;
            jumped = true; p = base + target;
        } else {
            if (n & 0xc0) malformed("invalid DNS label");
            expanded += n + 1;
            if (expanded > 254) malformed("DNS name exceeds 255 bytes");
            r.need(p, n); p += n;
        }
    }
    malformed("DNS compression loop"); return p;
}
void dns(const Reader& r, std::size_t base, PacketRecord& out) {
    r.need(base, 12);
    if (r.u16(base+2) & 0x0040) malformed("reserved DNS flag is set");
    auto p = base + 12;
    const auto questions = r.u16(base+4);
    const auto records = r.u16(base+6) + r.u16(base+8) + r.u16(base+10);
    for (unsigned i = 0; i < questions; ++i) { p = name(r,p,base); r.need(p,4); p += 4; }
    for (unsigned i = 0; i < records; ++i) {
        p = name(r,p,base); r.need(p,10); const auto size = r.u16(p+8); p += 10; r.need(p,size); p += size;
    }
    if (p != r.end) malformed("unexpected trailing DNS bytes");
    out.isDns = true;
}
void transport(Reader r, std::size_t p, std::size_t end, unsigned protocol, bool fragmented, PacketRecord& out) {
    r.end = std::min(r.end,end);
    if (protocol == 6) {
        out.transport = TransportProtocol::Tcp; r.need(p,20);
        const auto size = (r.u8(p+12) >> 4)*4;
        if (size < 20) malformed("TCP data offset is below 20 bytes");
        if (!fragmented && size > end-p) malformed("TCP header exceeds IP payload");
        r.need(p,size);
        out.sourcePort = static_cast<std::uint16_t>(r.u16(p)); out.destinationPort = static_cast<std::uint16_t>(r.u16(p+2));
        out.tcpFlags = static_cast<std::uint8_t>(r.u8(p+13)); p += size;
    } else if (protocol == 17) {
        out.transport = TransportProtocol::Udp; r.need(p,8);
        const auto size = r.u16(p+4);
        if (size < 8 || (!fragmented && size > end-p)) malformed("invalid UDP length");
        out.sourcePort = static_cast<std::uint16_t>(r.u16(p)); out.destinationPort = static_cast<std::uint16_t>(r.u16(p+2));
        end = p + size; r.end = std::min(r.end,end); p += 8;
    } else {
        if (protocol == 1 || protocol == 58) {
            out.transport = protocol == 1 ? TransportProtocol::Icmp : TransportProtocol::Icmpv6;
            r.need(p,4);
        } else if (protocol != 59) { out.status = ParseStatus::Unsupported; out.diagnostic = "unsupported IP protocol"; }
        return;
    }
    if (fragmented) return;
    if (out.sourcePort != 53 && out.destinationPort != 53) return;
    if (protocol == 6) {
        if (p == end) return; // ACK-only TCP segment is not a DNS message.
        r.need(p,2); const auto size = r.u16(p); p += 2;
        if (size != end-p) { out.status = ParseStatus::Unsupported; out.diagnostic = "DNS over TCP requires one complete message; stream reassembly is not available"; return; }
    }
    dns(r,p,out);
}
}
PacketRecord parsePacket(const RawPacket& packet, std::uint64_t sequence) {
    PacketRecord out;
    out.sequence = sequence; out.timestamp = packet.timestamp;
    out.originalLength = packet.originalLength; out.capturedLength = packet.capturedLength;
    try {
        if (packet.bytes.size() != packet.capturedLength || packet.capturedLength > packet.originalLength) malformed("inconsistent RawPacket lengths");
        if (packet.linkType != 1) throw Failure{ParseStatus::Unsupported,"only Ethernet link type is supported"};
        Reader r{packet.bytes,packet.bytes.size()}; r.need(0,14);
        out.destinationMac = mac(r,0); out.sourceMac = mac(r,6);
        auto type = r.u16(12); std::size_t p = 14;
        unsigned tags = 0;
        while (type == 0x8100 || type == 0x88a8) {
            if (++tags > 8) throw Failure{ParseStatus::Unsupported,"too many VLAN tags"};
            r.need(p,4); type = r.u16(p+2); p += 4;
        }
        out.etherType = static_cast<std::uint16_t>(type); out.status = ParseStatus::Complete;
        if (type == 0x0806) {
            out.network = NetworkProtocol::Arp; r.need(p,8);
            const auto h = r.u8(p+4), a = r.u8(p+5); r.need(p+8,2*(h+a));
            if (r.u16(p) != 1 || r.u16(p+2) != 0x0800 || h != 6 || a != 4) throw Failure{ParseStatus::Unsupported,"unsupported ARP address format"};
            out.sourceIp = ip(r,p+14,false); out.destinationIp = ip(r,p+24,false);
            out.summary = "ARP opcode=" + std::to_string(r.u16(p+6));
        } else if (type == 0x0800 || type == 0x86dd) {
            const bool v6 = type == 0x86dd; const auto start = p;
            out.network = v6 ? NetworkProtocol::IPv6 : NetworkProtocol::IPv4;
            r.need(p,v6 ? 40 : 20);
            const auto version = r.u8(p) >> 4;
            if (version != (v6 ? 6u : 4u)) malformed("EtherType and IP version disagree");
            out.ipVersion = static_cast<std::uint8_t>(version);
            std::size_t end; unsigned protocol; bool fragmented = false, nonFirst = false;
            if (!v6) {
                const auto size = (r.u8(p)&15)*4, total = r.u16(p+2);
                if (size < 20 || total < size) malformed("invalid IPv4 header or total length");
                r.need(p,size); end = start+total;
                out.sourceIp = ip(r,p+12,false); out.destinationIp = ip(r,p+16,false);
                out.ttlOrHopLimit = static_cast<std::uint8_t>(r.u8(p+8)); protocol = r.u8(p+9);
                const auto flags = r.u16(p+6); fragmented = (flags & 0x3fff) != 0; nonFirst = (flags & 0x1fff) != 0;
                p += size;
            } else {
                const auto payload = r.u16(p+4);
                end = start+40+payload; protocol = r.u8(p+6);
                out.sourceIp = ip(r,p+8,true); out.destinationIp = ip(r,p+24,true);
                out.ttlOrHopLimit = static_cast<std::uint8_t>(r.u8(p+7)); p += 40;
                r.end = std::min(r.end,end);
                while (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 44 || protocol == 51) {
                    r.need(p,2); const auto next = r.u8(p);
                    const auto size = protocol == 44 ? 8u : protocol == 51 ? (r.u8(p+1)+2)*4 : (r.u8(p+1)+1)*8;
                    if (size > end-p) malformed("IPv6 extension exceeds payload length");
                    r.need(p,size);
                    if (protocol == 44) { const auto f = r.u16(p+2); nonFirst = (f & 0xfff8) != 0; fragmented = nonFirst || (f & 1); }
                    p += size; protocol = next; if (nonFirst) break;
                }
            }
            out.ipProtocol = static_cast<std::uint8_t>(protocol);
            if (end > packet.originalLength) malformed("IP length exceeds original frame length");
            if (nonFirst) { out.status = ParseStatus::Unsupported; out.diagnostic = "non-initial IP fragment; reassembly required"; }
            else {
                // Distinguish a structurally short datagram from a capture cut short.
                const auto minimum = protocol == 6 ? 20u : protocol == 17 ? 8u : (protocol == 1 || protocol == 58) ? 4u : 0u;
                if (minimum > end-p) malformed("IP payload too short for transport header");
                transport(r,p,end,protocol,fragmented,out);
                if (fragmented) { out.status = ParseStatus::Unsupported; out.diagnostic = "initial IP fragment; payload reassembly required"; }
            }
            if (end > packet.capturedLength) throw Failure{ParseStatus::Truncated,"IP packet was cut short during capture"};
        } else throw Failure{ParseStatus::Unsupported,"unsupported EtherType"};
        if (out.summary.empty()) out.summary = out.sourceIp + " -> " + out.destinationIp;
    } catch (const Failure& error) { out.status = error.status; out.diagnostic = error.message; }
    return out;
}
}
