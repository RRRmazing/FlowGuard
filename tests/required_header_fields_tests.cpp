// Maintainer: He Junjie. Local acceptance additions; no parser classification changes.
#include "core/module_contracts.h"
#include <iostream>
#include <stdexcept>

using namespace flowguard;
namespace {
std::size_t checks = 0;
void check(bool value, const char* message) { ++checks; if (!value) throw std::runtime_error(message); }
const ProtocolField* find(const std::vector<ProtocolField>& fields, const std::string& name)
{
    for (const auto& field : fields) {
        if (field.name == name) return &field;
        if (const auto* nested = find(field.children, name)) return nested;
    }
    return nullptr;
}
const ProtocolField& layer(const ParsedPacket& packet, const std::string& name)
{
    for (const auto& field : packet.fields) if (field.name == name) return field;
    throw std::runtime_error("missing layer: " + name);
}
void value(const ProtocolField& parent, const std::string& name, const std::string& expected)
{
    const auto* field = find(parent.children, name);
    check(field && field->value == expected, (parent.name + ": " + name + " expected " + expected).c_str());
}
unsigned u16(const RawPacket& p, std::size_t at) { return (unsigned(p.bytes.at(at)) << 8) | p.bytes.at(at+1); }
std::uint32_t u32(const RawPacket& p, std::size_t at) { return (std::uint32_t(u16(p,at)) << 16) | u16(p,at+2); }
void put(RawPacket& p, std::size_t at, unsigned v) { p.bytes.at(at)=std::uint8_t(v>>8); p.bytes.at(at+1)=std::uint8_t(v); }
void resizeMetadata(RawPacket& p) { p.originalLength=p.capturedLength=static_cast<std::uint32_t>(p.bytes.size()); }
std::vector<RawPacket> load(const std::filesystem::path& path)
{
    PcapReader reader; check(reader.open(path).ok(), "open corpus");
    std::vector<RawPacket> result;
    for (;;) {
        RawPacket packet; OperationResult error;
        auto status=reader.readNext(packet,error);
        check(error.ok(), "read corpus");
        if (status==ReadStatus::EndOfFile) return result;
        result.push_back(std::move(packet));
    }
}
}
int wmain(int argc, wchar_t** argv)
{
    if (argc!=2) return 2;
    try {
        auto packets=load(std::filesystem::path(argv[1]));
        check(packets.size()==18, "18 known corpus records");
        for (std::size_t index=0; index<packets.size(); ++index) {
            const auto& raw=packets[index];
            const auto parsed=parsePacket(raw,index+1);
            check(parsed.record.status==(index==17 ? ParseStatus::Unsupported : ParseStatus::Complete), "preserve statuses");
            std::size_t p=14; auto type=u16(raw,12);
            while (type==0x8100 || type==0x88a8) { type=u16(raw,p+2);p+=4; }
            if (type==0x0800) {
                const auto& ip=layer(parsed,"IPv4");
                value(ip,"IHL",std::to_string(raw.bytes[p]&15));
                value(ip,"Header length",std::to_string((raw.bytes[p]&15)*4));
                value(ip,"DSCP",std::to_string(raw.bytes[p+1]>>2));
                value(ip,"ECN",std::to_string(raw.bytes[p+1]&3));
                value(ip,"Total length",std::to_string(u16(raw,p+2)));
                value(ip,"Identification",std::to_string(u16(raw,p+4)));
                value(ip,"Fragment offset",std::to_string(u16(raw,p+6)&8191));
                check(find(ip.children,"Header checksum")!=nullptr, "IPv4 checksum present");
                if ((raw.bytes[p]&15)>5) check(find(ip.children,"Options (raw)")!=nullptr, "IP options present");
                p+=(raw.bytes[p]&15)*4;
            } else if (type==0x86dd) {
                const auto& ip=layer(parsed,"IPv6");
                value(ip,"Traffic class",std::to_string((u32(raw,p)>>20)&255));
                value(ip,"Flow label",std::to_string(u32(raw,p)&0xfffff));
                value(ip,"Payload length",std::to_string(u16(raw,p+4)));
                value(ip,"Next header",std::to_string(raw.bytes[p+6]));
                unsigned next=raw.bytes[p+6];p+=40;
                while (next==0 || next==43 || next==60 || next==44 || next==51) {
                    const unsigned size=next==44 ? 8 : next==51 ? (raw.bytes[p+1]+2)*4 : (raw.bytes[p+1]+1)*8;
                    next=raw.bytes[p];p+=size;
                }
            } else if (type==0x0806) {
                value(layer(parsed,"ARP"),"Hardware address length","6");
                value(layer(parsed,"ARP"),"Protocol address length","4");
            }
            if (parsed.record.transport==TransportProtocol::Tcp) {
                const auto& tcp=layer(parsed,"TCP");
                value(tcp,"Sequence number",std::to_string(u32(raw,p+4)));
                value(tcp,"Acknowledgment number",std::to_string(u32(raw,p+8)));
                value(tcp,"Data offset",std::to_string(raw.bytes[p+12]>>4));
                value(tcp,"Window size",std::to_string(u16(raw,p+14)));
                value(tcp,"Urgent pointer",std::to_string(u16(raw,p+18)));
                check(find(tcp.children,"Checksum")!=nullptr, "TCP checksum present");
            } else if (parsed.record.transport==TransportProtocol::Udp) {
                value(layer(parsed,"UDP"),"Length",std::to_string(u16(raw,p+4)));
                check(find(layer(parsed,"UDP").children,"Checksum")!=nullptr, "UDP checksum present");
            }
        }
        auto tcp=packets[1]; const std::size_t ip=14, transport=34;
        tcp.bytes[transport+4]=0xfe;tcp.bytes[transport+5]=0xdc;tcp.bytes[transport+6]=0xba;tcp.bytes[transport+7]=0x98;
        tcp.bytes[transport+8]=0x89;tcp.bytes[transport+9]=0xab;tcp.bytes[transport+10]=0xcd;tcp.bytes[transport+11]=0xef;
        tcp.bytes.insert(tcp.bytes.begin()+transport+20,{1,1,0,0});
        tcp.bytes[transport+12]=0x61; // 24-byte header and NS bit
        put(tcp,ip+2,u16(tcp,ip+2)+4);resizeMetadata(tcp);
        auto parsed=parsePacket(tcp,1);
        check(parsed.record.status==ParseStatus::Complete,"TCP options retain valid status");
        value(layer(parsed,"TCP"),"Sequence number","4275878552");
        value(layer(parsed,"TCP"),"Acknowledgment number","2309737967");
        value(layer(parsed,"TCP"),"NS","1");
        value(layer(parsed,"TCP"),"Options (raw)","01 01 00 00");
        auto v6=packets[4];
        v6.bytes[14]=0x6a;v6.bytes[15]=0xba;v6.bytes[16]=0xbc;v6.bytes[17]=0xde;
        parsed=parsePacket(v6,1);
        value(layer(parsed,"IPv6"),"Traffic class","171");
        value(layer(parsed,"IPv6"),"Flow label","703710");
        v6.bytes[20]=51;put(v6,18,u16(v6,18)+12);
        v6.bytes.insert(v6.bytes.begin()+54,{17,1,0,0,0xde,0xad,0xbe,0xef,0x80,0,0,1});resizeMetadata(v6);
        parsed=parsePacket(v6,1);
        value(layer(parsed,"IPv6 extension"),"SPI","3735928559");
        value(layer(parsed,"IPv6 extension"),"Sequence number","2147483649");
        auto icmp=packets[0];icmp.bytes[23]=1;
        icmp.bytes.resize(34);icmp.bytes.insert(icmp.bytes.end(),{8,0,0x12,0x34,0xab,0xcd,0x12,0x34});
        put(icmp,16,28);resizeMetadata(icmp);
        parsed=parsePacket(icmp,1);
        value(layer(parsed,"ICMP"),"Type","8");
        value(layer(parsed,"ICMP"),"Checksum","0x1234");
        value(layer(parsed,"ICMP"),"Identifier","43981");
        value(layer(parsed,"ICMP"),"Sequence number","4660");
        std::cout << "Required header field checks passed: " << checks << '\n';return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n';return 1; }
}
