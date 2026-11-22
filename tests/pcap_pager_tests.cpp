#include "ui/pcap_pager.h"
#include <QTemporaryDir>
#include <fstream>
#include <iostream>
#include <limits>

int wmain(int argc,wchar_t **argv) {
    using namespace flowguard;
    if (argc!=2) return 2;
    int failures=0;
    auto check=[&](bool good,const char *name) { if(!good) {std::cerr<<"FAIL "<<name<<'\n'; ++failures;} };
    QTemporaryDir temporary;
    check(temporary.isValid(),"create isolated test directory");
    const auto root=std::filesystem::path(temporary.path().toStdWString());
    PcapReader source;
    check(source.open(std::filesystem::path(argv[1])).ok(),"open corpus");
    RawPacket udp; OperationResult result;
    while(source.readNext(udp,result)==ReadStatus::Packet) {
        if(parsePacket(udp,1).record.transport==TransportProtocol::Udp) break;
    }
    check(parsePacket(udp,1).record.transport==TransportProtocol::Udp,"known UDP fixture selected");
    PcapWriter writer;
    PcapWriteOptions options; options.linkType=udp.linkType;
    const auto path=root/L"分页-4501包.pcap";
    check(writer.open(path,options).ok(),"open output");
    for(int i=0;i<4501;++i) check(writer.write(udp).ok(),"write fixture record");
    check(writer.close().ok(),"close output");
    std::atomic_bool cancel{false};
    PcapPager pager;
    check(pager.index(path,{},cancel).ok(),"index all packets");
    auto first=pager.load(0,cancel);
    check(first.result.ok() && first.pageCount==3 && first.totalPackets==4501 && first.matchedPackets==4501 &&
          first.packets.size()==2000 && first.packets.front().record.sequence==1 && first.packets.back().record.sequence==2000,
          "first page contains full prefix");
    auto second=pager.load(1,cancel);
    check(second.result.ok() && second.packets.size()==2000 && second.packets.front().record.sequence==2001 &&
          second.packets.back().record.sequence==4000,"middle page contains continuous records");
    auto last=pager.load(999,cancel);
    check(last.result.ok() && last.page==2 && last.packets.size()==501 && last.packets.front().record.sequence==4001 &&
          last.packets.back().record.sequence==4501,"last page includes all tail records and clamps page number");
    check(pager.load(0,cancel).packets.front().record.sequence==1,"can seek backwards without losing prefix");
    DisplayFilter filter; filter.protocol=ProtocolFilter::Tcp;
    check(pager.index(path,filter,cancel).ok(),"index globally filtered file");
    auto empty=pager.load(0,cancel);
    check(empty.result.ok() && empty.totalPackets==4501 && empty.matchedPackets==0 && empty.packets.empty(),
          "global filter with no matches preserves total");
    filter.protocol=ProtocolFilter::Udp;
    check(pager.index(path,filter,cancel).ok() && pager.load(2,cancel).packets.size()==501,
          "matching filter reaches beyond first 2000 records");
    cancel=true;
    check(!pager.index(path,{},cancel).ok() && !pager.load(0,cancel).result.ok(),"cancelled index never exposes stale pages");
    cancel=false;
    check(pager.index(path,{},cancel).ok(),"rebuild after cancellation");
    {std::ofstream changed(path,std::ios::binary|std::ios::app); changed.put('\0');}
    check(!pager.load(0,cancel).result.ok(),"modified file rejected rather than browsing stale offsets");
    check(!pager.index(path,{},cancel).ok(),"truncated record rejected instead of silently omitting tail");
    const auto emptyPath=root/L"空文件.pcap";
    check(writer.open(emptyPath,options).ok() && writer.close().ok(),"write empty PCAP");
    check(pager.index(emptyPath,{},cancel).ok(),"empty PCAP indexed");
    auto noPackets=pager.load(0,cancel);
    check(noPackets.result.ok() && noPackets.totalPackets==0 && noPackets.packets.empty(),"empty page is valid");
    PcapReader seek;
    check(seek.open(emptyPath).ok(),"open seek test");
    check(!seek.seekRecord(23).ok() && !seek.seekRecord(std::numeric_limits<std::uint64_t>::max()).ok(),"invalid seek rejected");
    check(seek.seekRecord(24).ok() && seek.readNext(udp,result)==ReadStatus::EndOfFile,"header end is valid empty boundary");
    std::cout<<"PCAP_PAGER "<<(failures ? "FAIL" : "PASS")<<'\n';
    return failures ? 1 : 0;
}
