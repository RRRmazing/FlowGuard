#include "parser/packet_parser.h"
#include <cstdlib>
#include <iostream>
using namespace flowguard;
using Bytes = std::vector<std::uint8_t>;
int checks = 0;
void check(bool condition, const char* message) {
    ++checks; if (!condition) { std::cerr << "FAILED: " << message << '\n'; std::exit(1); }
}
void put(Bytes& b, std::size_t p, unsigned v) { b[p] = static_cast<std::uint8_t>(v >> 8); b[p+1] = static_cast<std::uint8_t>(v); }
RawPacket raw(Bytes b) { RawPacket p; p.bytes = std::move(b); p.originalLength = p.capturedLength = static_cast<std::uint32_t>(p.bytes.size()); return p; }
Bytes frame(bool v6, unsigned protocol, Bytes payload) {
    Bytes b(14 + (v6 ? 40 : 20)); put(b,12,v6 ? 0x86dd : 0x0800);
    b[0]=0xaa; b[6]=0xbb; b[14]=v6 ? 0x60 : 0x45;
    if (v6) { put(b,18,static_cast<unsigned>(payload.size())); b[20]=static_cast<std::uint8_t>(protocol); b[21]=64; b[37]=1; b[53]=2; }
    else { put(b,16,static_cast<unsigned>(20+payload.size())); b[22]=64; b[23]=static_cast<std::uint8_t>(protocol); b[26]=192; b[29]=1; b[30]=10; b[33]=2; }
    b.insert(b.end(),payload.begin(),payload.end()); return b;
}
Bytes udp(Bytes body = {}, unsigned port = 80) {
    Bytes b(8); put(b,0,1234); put(b,2,port); put(b,4,static_cast<unsigned>(8+body.size())); b.insert(b.end(),body.begin(),body.end()); return b;
}
int main() {
    auto b = frame(false,17,udp()); auto p = raw(b); auto r = parsePacket(p,42);
    check(r.status==ParseStatus::Complete && r.sequence==42,"IPv4 UDP complete");
    check(r.sourceIp=="192.0.0.1" && r.destinationIp=="10.0.0.2" && r.sourcePort==1234 && r.destinationPort==80,"IPv4 addresses and ports");
    check(r.sourceMac=="bb:00:00:00:00:00" && r.ttlOrHopLimit==64 && r.ipProtocol==17,"Ethernet and IP fields");
    auto v6 = frame(true,17,udp()); r=parsePacket(raw(v6));
    check(r.status==ParseStatus::Complete && r.sourceIp=="0:0:0:0:0:0:0:1" && r.network==NetworkProtocol::IPv6,"IPv6 UDP");
    Bytes tcp(24); put(tcp,0,0); put(tcp,2,443); tcp[12]=0x60; tcp[13]=0x12;
    r=parsePacket(raw(frame(false,6,tcp))); check(r.status==ParseStatus::Complete && r.sourcePort==0 && r.tcpFlags==0x12,"TCP options, zero port, flags");
    tcp[12]=0x40; check(parsePacket(raw(frame(false,6,tcp))).status==ParseStatus::Malformed,"bad TCP offset");
    auto bad=b; put(bad,38,7); check(parsePacket(raw(bad)).status==ParseStatus::Malformed,"UDP length below header");
    bad=b; put(bad,38,100); check(parsePacket(raw(bad)).status==ParseStatus::Malformed,"UDP exceeds IP");
    bad=b; bad[14]=0x44; check(parsePacket(raw(bad)).status==ParseStatus::Malformed,"IPv4 IHL");
    bad=b; put(bad,16,19); check(parsePacket(raw(bad)).status==ParseStatus::Malformed,"IPv4 total length");
    bad=b; bad[14]=0x65; check(parsePacket(raw(bad)).status==ParseStatus::Malformed,"version mismatch");
    p=raw(b); p.capturedLength--; check(parsePacket(p).status==ParseStatus::Malformed,"metadata mismatch");
    p=raw(b); p.originalLength--; check(parsePacket(p).status==ParseStatus::Malformed,"capture exceeds original");
    p=raw(b); p.linkType=113; check(parsePacket(p).status==ParseStatus::Unsupported,"link type");
    bad=b; put(bad,12,0x1234); check(parsePacket(raw(bad)).status==ParseStatus::Unsupported,"EtherType");
    // Every prefix of real packets is checked, including headers and payloads.
    for (const auto& sample : {b,v6,frame(false,6,Bytes(20,0))}) {
        for (std::size_t n=0;n<sample.size();++n) {
            p=raw(sample); p.bytes.resize(n); p.capturedLength=static_cast<std::uint32_t>(n);
            check(parsePacket(p).status==ParseStatus::Truncated,"capture prefix safely truncated");
        }
    }
    bad=b; put(bad,20,1); r=parsePacket(raw(bad)); check(r.status==ParseStatus::Unsupported && !r.sourcePort,"noninitial IPv4 fragment");
    bad=b; put(bad,20,0x2000); check(parsePacket(raw(bad)).status==ParseStatus::Unsupported,"first IPv4 fragment");
    Bytes ext(8); ext[0]=17; auto u=udp(); ext.insert(ext.end(),u.begin(),u.end());
    check(parsePacket(raw(frame(true,0,ext))).status==ParseStatus::Complete,"IPv6 extension");
    ext[1]=10; check(parsePacket(raw(frame(true,0,ext))).status==ParseStatus::Malformed,"IPv6 extension length");
    ext[1]=0; put(ext,2,8); r=parsePacket(raw(frame(true,44,ext))); check(r.status==ParseStatus::Unsupported && !r.sourcePort,"IPv6 noninitial fragment");
    auto vlan=b; put(vlan,12,0x8100); vlan.insert(vlan.begin()+14,{0,1,8,0}); check(parsePacket(raw(vlan)).status==ParseStatus::Complete,"VLAN");
    Bytes arp(42); put(arp,12,0x0806); put(arp,14,1); put(arp,16,0x0800); arp[18]=6; arp[19]=4; put(arp,20,1); arp[28]=192; arp[31]=1; arp[38]=10; arp[41]=2;
    r=parsePacket(raw(arp)); check(r.status==ParseStatus::Complete && r.network==NetworkProtocol::Arp && r.sourceIp=="192.0.0.1" && r.destinationIp=="10.0.0.2","ARP request");
    put(arp,20,2); check(parsePacket(raw(arp)).summary=="ARP opcode=2","ARP reply");
    Bytes query(12); put(query,0,0x1234); put(query,2,0x0100); put(query,4,1); query.insert(query.end(),{1,'a',3,'c','o','m',0,0,1,0,1});
    r=parsePacket(raw(frame(false,17,udp(query,53)))); check(r.isDns && r.status==ParseStatus::Complete,"DNS query");
    auto answer=query; put(answer,2,0x8180); put(answer,6,1); answer.insert(answer.end(),{0xc0,12,0,1,0,1,0,0,0,60,0,4,1,2,3,4});
    check(parsePacket(raw(frame(true,17,udp(answer,53)))).isDns,"DNS compressed answer");
    auto loop=query; loop[12]=0xc0; loop[13]=12; check(parsePacket(raw(frame(false,17,udp(loop,53)))).status==ParseStatus::Malformed,"DNS pointer loop");
    query.pop_back(); r=parsePacket(raw(frame(false,17,udp(query,53)))); check(!r.isDns && r.status==ParseStatus::Truncated,"short DNS question");
    Bytes dnsTcp(20); dnsTcp[12]=0x50; put(dnsTcp,2,53); dnsTcp.push_back(0); dnsTcp.push_back(static_cast<std::uint8_t>(answer.size())); dnsTcp.insert(dnsTcp.end(),answer.begin(),answer.end());
    check(parsePacket(raw(frame(false,6,dnsTcp))).isDns,"TCP DNS length prefix");
    dnsTcp.pop_back(); check(parsePacket(raw(frame(false,6,dnsTcp))).status==ParseStatus::Unsupported,"TCP DNS reassembly required");
    // Deterministic arbitrary inputs exercise bounds without live capture or personal data.
    unsigned state=7;
    for (unsigned n=0;n<4096;++n) {
        Bytes bytes(n%256); for (auto& byte:bytes) { state=state*1664525u+1013904223u; byte=static_cast<std::uint8_t>(state>>24); }
        parsePacket(raw(bytes)); ++checks;
    }
    std::cout << checks << " parser checks passed\n";
}
