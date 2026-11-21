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
    if (!v6) {
        for (unsigned i=0;i<4;++i) { if (i) s << '.'; s << r.u8(p+i); }
        return s.str();
    }
    unsigned best=8, length=0;
    for (unsigned i=0;i<8;) {
        if (r.u16(p+2*i)) { ++i; continue; }
        const auto start=i;
        while (i<8 && !r.u16(p+2*i)) ++i;
        if (i-start > length && i-start >= 2) { best=start; length=i-start; }
    }
    for (unsigned i=0;i<8;) {
        if (i==best) { s << "::"; i+=length; }
        else { if (i && i!=best+length) s << ':'; s << std::hex << r.u16(p+2*i); ++i; }
    }
    return s.str();
}
// Validate DNS names, including compression pointers, without recursive calls.
std::size_t name(const Reader& r, std::size_t p, std::size_t base, std::string* decoded = nullptr) {
    std::size_t next = p, expanded = 0;
    bool jumped = false;
    unsigned jumps = 0;
    for (std::size_t steps = 0; steps <= r.end - base; ++steps) {
        const auto n = r.u8(p++);
        if (!n) return jumped ? next : p;
        if ((n & 0xc0) == 0xc0) {
            if (++jumps > 16) malformed("DNS compression exceeds 16 jumps");
            const auto target = ((n & 0x3f) << 8) | r.u8(p++);
            if (base + target >= p - 2) malformed("DNS pointer must refer to a prior name");
            if (!jumped) next = p;
            jumped = true; p = base + target;
        } else {
            if (n & 0xc0) malformed("invalid DNS label");
            expanded += n + 1;
            if (expanded > 254) malformed("DNS name exceeds 255 bytes");
            r.need(p, n);
            if (decoded) {
                if (!decoded->empty()) *decoded += '.';
                for (unsigned i=0;i<n;++i) {
                    const auto c=r.u8(p+i);
                    if (c>=33 && c<=126 && c!='.' && c!='\\') *decoded+=static_cast<char>(c);
                    else { *decoded+='\\'; *decoded+=std::to_string(c); }
                }
            }
            p += n;
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
        if (size > end-p) { out.status = ParseStatus::Unsupported; out.diagnostic = "DNS over TCP requires one complete message; stream reassembly is not available"; return; }
    }
    if (protocol == 6) r.end = p + r.u16(p-2);
    dns(r,p,out);
}
}
static PacketRecord parseRecord(const RawPacket& packet, std::uint64_t sequence) {
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
            if (++tags > 2) throw Failure{ParseStatus::Unsupported,"too many VLAN tags"};
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
                end = start+total;
                if (end > packet.originalLength) malformed("IP length exceeds original frame length");
                r.need(p,size);
                out.sourceIp = ip(r,p+12,false); out.destinationIp = ip(r,p+16,false);
                out.ttlOrHopLimit = static_cast<std::uint8_t>(r.u8(p+8)); protocol = r.u8(p+9);
                const auto flags = r.u16(p+6); fragmented = (flags & 0x3fff) != 0; nonFirst = (flags & 0x1fff) != 0;
                p += size;
            } else {
                const auto payload = r.u16(p+4);
                end = start+40+payload;
                if (end > packet.originalLength) malformed("IP length exceeds original frame length");
                protocol = r.u8(p+6);
                out.sourceIp = ip(r,p+8,true); out.destinationIp = ip(r,p+24,true);
                out.ttlOrHopLimit = static_cast<std::uint8_t>(r.u8(p+7)); p += 40;
                r.end = std::min(r.end,end);
                unsigned extensions=0;
                while (protocol == 0 || protocol == 43 || protocol == 60 || protocol == 44 || protocol == 51) {
                    if (++extensions>8) throw Failure{ParseStatus::Unsupported,"IPv6 extension chain exceeds eight headers"};
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
            if (fragmented) {
                if (protocol==6) out.transport=TransportProtocol::Tcp;
                else if (protocol==17) out.transport=TransportProtocol::Udp;
            }
            if (nonFirst || fragmented) { out.status = ParseStatus::Unsupported; out.diagnostic = "IP fragment; reassembly required"; }
            else {
                // Distinguish a structurally short datagram from a capture cut short.
                const auto minimum = protocol == 6 ? 20u : protocol == 17 ? 8u : (protocol == 1 || protocol == 58) ? 4u : 0u;
                if (minimum > end-p) malformed("IP payload too short for transport header");
                transport(r,p,end,protocol,fragmented,out);
            }
            if (end > packet.capturedLength) throw Failure{ParseStatus::Truncated,"IP packet was cut short during capture"};
        } else throw Failure{ParseStatus::Unsupported,"unsupported EtherType"};
        if (out.summary.empty()) out.summary = out.sourceIp + " -> " + out.destinationIp;
    } catch (const Failure& error) { out.status = error.status; out.diagnostic = error.message; }
    if (packet.capturedLength < packet.originalLength && out.status != ParseStatus::Malformed) {
        out.status = ParseStatus::Truncated;
        if (out.diagnostic.empty()) out.diagnostic = "captured length is below original length";
    }
    return out;
}
namespace {
ProtocolField field(std::string name, std::string value) { return {std::move(name),std::move(value),{}}; }
std::string number(unsigned value) { return std::to_string(value); }
// All trees have a fixed maximum shape: at most two VLAN groups, no payload
// text or unbounded DNS record expansion. A final budget check protects future additions.
std::vector<ProtocolField> fields(const RawPacket& packet, const PacketRecord& record) {
    std::vector<ProtocolField> result;
    Reader r{packet.bytes,packet.bytes.size()};
    if (packet.linkType != 1 || packet.bytes.size() != packet.capturedLength) return result;
    try {
        r.need(0,14);
        result.push_back({"Ethernet", "", {field("Source MAC",record.sourceMac),field("Destination MAC",record.destinationMac),field("EtherType",number(r.u16(12)))}});
        auto type=r.u16(12); std::size_t p=14;
        for (unsigned tags=0;(type==0x8100 || type==0x88a8) && tags<2;++tags) {
            r.need(p,4); const auto tci=r.u16(p); type=r.u16(p+2);
            result.push_back({"VLAN","",{field("ID",number(tci&4095)),field("Priority",number(tci>>13)),field("DEI",number((tci>>12)&1)),field("EtherType",number(type))}}); p+=4;
        }
        if (type==0x0806) {
            r.need(p,8);
            ProtocolField arp{"ARP","",{field("Hardware type",number(r.u16(p))),field("Protocol type",number(r.u16(p+2))),field("Opcode",number(r.u16(p+6)))}};
            if (r.u8(p+4)==6 && r.u8(p+5)==4 && p+28<=r.end) {
                arp.children.push_back(field("Sender MAC",mac(r,p+8))); arp.children.push_back(field("Target MAC",mac(r,p+18)));
                arp.children.push_back(field("Sender IP",record.sourceIp)); arp.children.push_back(field("Target IP",record.destinationIp));
            }
            result.push_back(std::move(arp)); return result;
        }
        if (!record.ipVersion) return result;
        const bool v6=*record.ipVersion==6;
        ProtocolField network{v6 ? "IPv6" : "IPv4","",{field("Source IP",record.sourceIp),field("Destination IP",record.destinationIp),field("Version",number(*record.ipVersion))}};
        if (record.ttlOrHopLimit) network.children.push_back(field(v6 ? "Hop limit" : "TTL",number(*record.ttlOrHopLimit)));
        if (record.ipProtocol) network.children.push_back(field("Protocol",number(*record.ipProtocol)));
        result.push_back(std::move(network));
        unsigned protocol=0; bool nonFirst=false;
        if (v6) {
            r.need(p,40); const auto end=p+40+r.u16(p+4); protocol=r.u8(p+6); p+=40; r.end=std::min(r.end,end);
            unsigned extensions=0;
            while (protocol==0 || protocol==43 || protocol==60 || protocol==44 || protocol==51) {
                if (++extensions>8) return result;
                r.need(p,2); const auto next=r.u8(p); const auto size=protocol==44 ? 8u : protocol==51 ? (r.u8(p+1)+2)*4 : (r.u8(p+1)+1)*8;
                r.need(p,size); if (protocol==44) nonFirst=(r.u16(p+2)&0xfff8)!=0;
                p+=size; protocol=next; if (nonFirst) break;
            }
        } else {
            r.need(p,20); nonFirst=(r.u16(p+6)&0x1fff)!=0; protocol=r.u8(p+9); const auto end=p+r.u16(p+2); p+=(r.u8(p)&15)*4; r.end=std::min(r.end,end);
        }
        if (nonFirst || !record.sourcePort || !record.destinationPort) return result;
        ProtocolField layer{protocol==6 ? "TCP" : "UDP","",{field("Source port",number(*record.sourcePort)),field("Destination port",number(*record.destinationPort))}};
        if (record.tcpFlags) {
            ProtocolField flags{"Flags",number(*record.tcpFlags),{}};
            const char* names[]={"FIN","SYN","RST","PSH","ACK","URG","ECE","CWR"};
            for (unsigned i=0;i<8;++i) flags.children.push_back(field(names[i],(*record.tcpFlags & (1u<<i)) ? "1" : "0"));
            layer.children.push_back(std::move(flags));
        }
        result.push_back(std::move(layer));
        if (!record.isDns) return result;
        p+=protocol==6 ? (r.u8(p+12)>>4)*4+2 : 8;
        r.need(p,12);
        result.push_back({"DNS","",{field("Transaction ID",number(r.u16(p))),field("Flags",number(r.u16(p+2))),field("Questions",number(r.u16(p+4))),field("Answers",number(r.u16(p+6))),field("Authority records",number(r.u16(p+8))),field("Additional records",number(r.u16(p+10)))}});
        if (r.u16(p+4)) {
            std::string question; const auto q=name(r,p+12,p,&question);
            result.back().children.push_back(field("Question name",question.empty() ? "." : question));
            result.back().children.push_back(field("Question type",number(r.u16(q))));
            result.back().children.push_back(field("Question class",number(r.u16(q+2))));
        }
    } catch (const Failure&) { /* Keep only safely available nodes on short input. */ }
    return result;
}
}
ParsedPacket parsePacket(const RawPacket& packet, std::uint64_t sequence) {
    ParsedPacket parsed; parsed.record=parseRecord(packet,sequence);
    parsed.fields=fields(packet,parsed.record);
    std::size_t nodes=0, text=0;
    const auto count=[&](const auto& self,const std::vector<ProtocolField>& list,unsigned depth)->bool {
        if (depth>16) return false;
        for (const auto& f:list) {
            ++nodes; text+=f.name.size()+f.value.size();
            if (nodes>256 || text>16*1024 || !self(self,f.children,depth+1)) return false;
        }
        return true;
    };
    if (!count(count,parsed.fields,1)) { parsed.fields.clear(); parsed.record.diagnostic+="; field tree resource limit"; }
    return parsed;
}

}
