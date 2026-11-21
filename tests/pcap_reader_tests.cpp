#include "storage/pcap_reader.h"
#include "parser/packet_parser.h"
#include <fstream>
#include <iostream>
#include <cstdlib>
using namespace flowguard;
using Bytes=std::vector<std::uint8_t>;
int checks=0;
void check(bool ok,const char* text) { ++checks; if (!ok) { std::cerr << "FAILED: " << text << '\n'; std::exit(1); } }
void integer(Bytes& b,std::uint32_t v,unsigned n,bool little) {
    for (unsigned i=0;i<n;++i) b.push_back(static_cast<std::uint8_t>(v>>(8*(little ? i : n-1-i))));
}
Bytes header(bool little,bool nano,std::uint32_t snap=65535,std::uint32_t link=1) {
    Bytes b; integer(b,nano ? 0xa1b23c4d : 0xa1b2c3d4,4,little); integer(b,2,2,little); integer(b,4,2,little);
    integer(b,0,4,little); integer(b,0,4,little); integer(b,snap,4,little); integer(b,link,4,little); return b;
}
void append(Bytes& b,const Bytes& payload,bool little,std::uint32_t fraction=123456,std::uint32_t original=42) {
    integer(b,1700000000,4,little); integer(b,fraction,4,little); integer(b,static_cast<std::uint32_t>(payload.size()),4,little); integer(b,original,4,little);
    b.insert(b.end(),payload.begin(),payload.end());
}
int main() {
    // Use a unique Unicode directory inside the CTest working directory.
    auto dir=std::filesystem::current_path()/std::filesystem::path(u8"读取测试");
    dir+=std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    check(std::filesystem::create_directory(dir),"create test directory");
    struct Cleanup { std::filesystem::path p; ~Cleanup() { std::error_code ec; std::filesystem::remove(p/std::filesystem::path(u8"固定样本.pcap"),ec); std::filesystem::remove(p,ec); } } cleanup{dir};
    const auto path=dir/std::filesystem::path(u8"固定样本.pcap");
    auto write=[&](const Bytes& b) { std::ofstream f(path,std::ios::binary|std::ios::trunc); f.write(reinterpret_cast<const char*>(b.data()),static_cast<std::streamsize>(b.size())); f.close(); check(!f.fail(),"write fixture"); };
    Bytes packet(42); packet[12]=8; packet[14]=0x45; packet[17]=28; packet[22]=64; packet[23]=17; packet[26]=192; packet[29]=1; packet[30]=10; packet[33]=2; packet[34]=4; packet[35]=0xd2; packet[37]=80; packet[39]=8;
    PcapReader reader; RawPacket out; out.originalLength=777; OperationResult result;
    check(reader.readNext(out,result)==ReadStatus::Error && result.code==ErrorCode::InvalidState && out.originalLength==777,"closed reader preserves output");
    check(!reader.open(dir/"missing").ok(),"missing file");
    for (bool little:{false,true}) for (bool nano:{false,true}) {
        auto b=header(little,nano); append(b,packet,little,nano ? 123456789 : 123456); append(b,packet,little,0); write(b);
        check(reader.open(path).ok(),"open all endian/precision combinations and Unicode path");
        check(reader.info().nanosecondPrecision==nano && reader.info().linkType==1,"file info");
        check(reader.open(path).code==ErrorCode::InvalidState,"duplicate open");
        check(reader.readNext(out,result)==ReadStatus::Packet && result.ok() && out.bytes==packet && out.originalLength==42,"read owned packet bytes and lengths");
        const auto expected=std::chrono::seconds(1700000000)+std::chrono::nanoseconds(nano ? 123456789 : 123456000);
        check(out.timestamp.time_since_epoch()==std::chrono::duration_cast<std::chrono::system_clock::duration>(expected),"timestamp precision conversion");
        check(parsePacket(out,1).record.destinationPort==80,"reader to parser shared API");
        check(reader.readNext(out,result)==ReadStatus::Packet,"second packet");
        out.originalLength=777;
        check(reader.readNext(out,result)==ReadStatus::EndOfFile && result.ok() && out.originalLength==777,"normal EOF preserves output");
        check(reader.readNext(out,result)==ReadStatus::EndOfFile,"repeated EOF"); reader.close(); reader.close();
    }
    write(header(true,false)); check(reader.open(path).ok(),"valid empty file"); check(reader.readNext(out,result)==ReadStatus::EndOfFile,"empty file EOF"); reader.close();
    for (unsigned n=0;n<24;++n) { auto h=header(true,false); h.resize(n); write(h); check(!reader.open(path).ok(),"truncated global header"); }
    write({0x0a,0x0d,0x0d,0x0a}); check(reader.open(path).code==ErrorCode::Unsupported,"PCAPNG");
    auto h=header(true,false); h[4]=3; write(h); check(reader.open(path).code==ErrorCode::Unsupported,"unsupported version");
    write(header(true,false,0)); check(!reader.open(path).ok(),"zero snaplen");
    for (unsigned n=1;n<16+packet.size();++n) {
        auto b=header(true,false); append(b,packet,true); b.resize(24+n); write(b); check(reader.open(path).ok(),"open truncated record fixture");
        out.originalLength=777; check(reader.readNext(out,result)==ReadStatus::Error && !result.ok() && out.originalLength==777,"partial record is error, preserves output");
        check(reader.readNext(out,result)==ReadStatus::Error,"failed reader cannot continue"); reader.close();
    }
    auto invalid=[&](Bytes b,ErrorCode code) { write(b); check(reader.open(path).ok(),"open invalid-record fixture"); check(reader.readNext(out,result)==ReadStatus::Error && result.code==code,"invalid record validation"); reader.close(); };
    auto b=header(true,false); append(b,packet,true,1000000); invalid(b,ErrorCode::InvalidArgument);
    b=header(true,true); append(b,packet,true,1000000000); invalid(b,ErrorCode::InvalidArgument);
    b=header(true,false); append(b,packet,true,0,1); invalid(b,ErrorCode::InvalidArgument);
    b=header(true,false,10); append(b,packet,true); invalid(b,ErrorCode::InvalidArgument);
    b=header(true,false,32*1024*1024); integer(b,0,4,true); integer(b,0,4,true); integer(b,17*1024*1024,4,true); integer(b,17*1024*1024,4,true); invalid(b,ErrorCode::ResourceLimit);
    b=header(true,false,65535,113); append(b,{},true,0,0); write(b); check(reader.open(path).ok(),"unknown DLT retained"); check(reader.readNext(out,result)==ReadStatus::Packet && parsePacket(out,1).record.status==ParseStatus::Unsupported,"unknown DLT not Ethernet"); reader.close();
    std::cout << checks << " PCAP reader checks passed\n";
}
