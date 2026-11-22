#include "core/processing_session.h"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
using namespace flowguard;
using namespace std::chrono;
namespace {
int checks=0;
void check(bool ok,const char* label){++checks;if(!ok)throw std::runtime_error(label);}
template<class F> void wait(F predicate,const char* label){const auto end=steady_clock::now()+seconds(6);while(!predicate()&&steady_clock::now()<end)std::this_thread::sleep_for(milliseconds(2));check(predicate(),label);}
PacketRecord packet(double secondsValue,TransportProtocol transport=TransportProtocol::Tcp,unsigned port=443){
    PacketRecord r;r.status=ParseStatus::Complete;r.timestamp=system_clock::time_point(milliseconds(std::int64_t(secondsValue*1000)));
    r.transport=transport;r.sourceIp="192.0.2.1";r.destinationIp="198.51.100.2";r.sourcePort=1234;r.destinationPort=std::uint16_t(port);r.tcpFlags=2;return r;
}
void put(std::vector<std::uint8_t>& b,std::size_t p,unsigned value){b[p]=std::uint8_t(value>>8);b[p+1]=std::uint8_t(value);}
RawPacket raw(unsigned protocol,unsigned port,unsigned flags,unsigned type,unsigned index,bool v6=false){
    const std::size_t offset=v6?54:34;const auto length=protocol==6?20u:8u;
    RawPacket r;r.timestamp=system_clock::time_point(seconds(1700000000)+milliseconds(index*10));
    r.bytes.resize(offset+length);auto& b=r.bytes;put(b,12,v6?0x86dd:0x0800);b[14]=v6?0x60:0x45;
    if(v6){put(b,18,length);b[20]=std::uint8_t(protocol);b[21]=64;b[37]=1;b[53]=2;}
    else{put(b,16,20+length);b[22]=64;b[23]=std::uint8_t(protocol);b[26]=192;b[28]=2;b[29]=1;b[30]=198;b[31]=51;b[32]=100;b[33]=2;}
    if(protocol==6 || protocol==17){put(b,offset,1234);put(b,offset+2,port);if(protocol==6){b[offset+12]=0x50;b[offset+13]=std::uint8_t(flags);}else put(b,offset+4,8);}
    else b[offset]=std::uint8_t(type);
    r.capturedLength=r.originalLength=std::uint32_t(b.size());return r;
}
bool rescanning(const AlertSnapshot& s){return std::any_of(s.rebuilding.begin(),s.rebuilding.end(),[](bool b){return b;});}
std::size_t count(const AlertSnapshot& s,AlertRule rule){return std::count_if(s.records.begin(),s.records.end(),[rule](const auto& a){return a.rule==rule;});}
}
int main(int argc,char** argv){try{
    if(argc!=2)return 2;
    AlertEngine syn(AlertRule::Syn,{true,5,3});
    auto r=packet(0);syn.add(r);r=packet(1);syn.add(r);r=packet(2);syn.add(r);
    check(syn.records().size()==1&&syn.records()[0].peak==3,"SYN threshold equality triggers");
    r=packet(2.1);r.tcpFlags=0x12;syn.add(r);check(syn.records()[0].peak==3,"SYN ACK excluded");
    r=packet(2.2);r.tcpFlags=0x03;syn.add(r);check(syn.records()[0].peak==3,"SYN FIN excluded");
    syn.advance(system_clock::time_point(seconds(5)));check(!syn.records()[0].active&&syn.records()[0].current==2,"left boundary excluded and recovery");
    syn.add(packet(1));check(syn.latePackets()==1,"timestamp rollback counted");
    syn.add(packet(6.1));check(!syn.records()[0].active&&syn.records()[0].current==2,"recovered alert current count includes new packet below threshold");
    AlertEngine delayed(AlertRule::Syn,{true,5,2});delayed.add(packet(0));delayed.advance(system_clock::time_point(seconds(1)));
    delayed.add(packet(.5));check(delayed.latePackets()==0&&delayed.records().size()==1,"live idle clock does not reject delayed chronological packets");
    delayed.advance(system_clock::time_point(seconds(10)));delayed.add(packet(2));
    check(delayed.latePackets()==0&&delayed.records()[0].current==0,"expired queued packet cannot reactivate alert");
    AlertEngine scan(AlertRule::PortScan,{true,10,3});
    for(unsigned p:{80u,80u,443u,8080u})scan.add(packet(1,TransportProtocol::Tcp,p));
    check(scan.records().size()==1&&scan.records()[0].peak==3,"scan distinct ports not packet count");
    auto other=packet(2,TransportProtocol::Tcp,22);other.sourceIp="192.0.2.9";scan.add(other);check(scan.records().size()==1,"scan source isolation");
    AlertEngine echo(AlertRule::Echo,{true,5,2});
    auto e=packet(0,TransportProtocol::Icmp);e.icmpType=8;e.icmpCode=0;echo.add(e);e.timestamp+=milliseconds(1);e.icmpType=0;echo.add(e);
    check(echo.records().empty(),"echo replies excluded");e.icmpType=8;echo.add(e);check(echo.records().size()==1,"IPv4 echo request detection");
    AlertEngine echo6(AlertRule::Echo,{true,5,1});e.transport=TransportProtocol::Icmpv6;e.icmpType=129;echo6.add(e);check(echo6.records().empty(),"IPv6 echo reply excluded");e.icmpType=128;echo6.add(e);check(echo6.records().size()==1,"IPv6 echo request detection");
    AlertEngine arp(AlertRule::Arp,{true,60,1});auto a=packet(1);a.network=NetworkProtocol::Arp;a.arpOpcode=2;a.arpSenderMac="02:00:00:00:00:01";arp.add(a);arp.add(a);check(arp.records().empty(),"ARP baseline and repeats are normal");a.timestamp+=seconds(1);a.arpSenderMac="02:00:00:00:00:02";arp.add(a);check(arp.records().size()==1&&arp.records()[0].targetIp==a.sourceIp,"ARP payload mapping change");
    auto parsed=parsePacket(raw(1,0,0,8,0),1).record;check(parsed.icmpType==8&&parsed.icmpCode==0&&parsed.status==ParseStatus::Complete,"ICMP fields parsed");
    parsed=parsePacket(raw(58,0,0,128,0,true),1).record;check(parsed.icmpType==128&&parsed.transport==TransportProtocol::Icmpv6,"ICMPv6 fields parsed");
    auto shortEcho=raw(1,0,0,8,0);shortEcho.bytes.resize(38);shortEcho.capturedLength=38;check(parsePacket(shortEcho,1).record.status==ParseStatus::Truncated,"short echo header rejected");
    AlertMonitor live;auto rules=defaultAlertRules();rules[0].threshold=3;check(live.configure(rules),"configure live before begin");live.begin(1);
    for(unsigned i=0;i<3;++i){auto p=packet(i);p.sequence=i+1;live.add(p);}check(count(live.snapshot(),AlertRule::Syn)==1,"live monitor detects");
    rules[0].threshold=4;live.configure(rules);check(count(live.snapshot(),AlertRule::Syn)==0,"raising live threshold removes alert");rules[0].threshold=2;live.configure(rules);check(count(live.snapshot(),AlertRule::Syn)==1,"lowering live threshold adds alert");
    rules[0].enabled=false;live.configure(rules);check(count(live.snapshot(),AlertRule::Syn)==0,"disabling removes own alerts");rules[0].enabled=true;live.configure(rules);check(count(live.snapshot(),AlertRule::Syn)==1,"enabling re-evaluates retained live data");
    live.setPaused(true);auto pausedPacket=packet(2.5);pausedPacket.sequence=4;live.add(pausedPacket);
    check(live.snapshot().records[0].peak==3,"pause freezes detection result");
    live.setPaused(false);check(live.snapshot().records[0].peak==4,"resume re-evaluates retained data");
    live.setPaused(true);live.advance(system_clock::time_point(seconds(20)));
    check(live.snapshot().records[0].active,"paused idle clock does not mutate displayed alert");
    live.setPaused(false);check(live.snapshot().records.empty(),"resume after idle cannot resurrect expired live traffic");
    auto invalidRules=rules;invalidRules[0].windowSeconds=0;check(!live.configure(invalidRules),"invalid window rejected");
    AlertMonitor liveArp;liveArp.begin(2);auto mapping=a;mapping.timestamp=system_clock::time_point(seconds(0));mapping.sequence=1;mapping.arpSenderMac="02:00:00:00:00:01";liveArp.add(mapping);
    mapping.timestamp+=seconds(200);mapping.sequence=2;mapping.arpSenderMac="02:00:00:00:00:02";liveArp.add(mapping);
    auto arpRules=defaultAlertRules();arpRules[4].threshold=2;liveArp.configure(arpRules);check(count(liveArp.snapshot(),AlertRule::Arp)==0,"ARP threshold raise removes mapping alert");
    arpRules[4].threshold=1;liveArp.configure(arpRules);check(count(liveArp.snapshot(),AlertRule::Arp)==1,"live ARP re-evaluation retains older baseline");
    live.advance(system_clock::time_point(seconds(100)));check(live.snapshot().records.empty(),"idle live window stays empty");
    AlertEngine bounded(AlertRule::Syn,{true,5,100000});
    for(unsigned i=0;i<100001;++i)bounded.add(packet(1));
    check(bounded.limited()==1&&bounded.records()[0].peak==100000,"event capacity is bounded and reported");
    AlertEngine grouped(AlertRule::Syn,{true,5,100000});for(unsigned i=0;i<4097;++i)grouped.add(packet(1,TransportProtocol::Tcp,i));
    check(grouped.limited()==1&&grouped.records().empty(),"group capacity is bounded and reported");
    AlertEngine alertBound(AlertRule::Syn,{true,5,1});for(unsigned i=0;i<1001;++i)alertBound.add(packet(1,TransportProtocol::Tcp,i));
    check(alertBound.limited()==1&&alertBound.records().size()==1000,"alert capacity is bounded and reported");
    auto path=std::filesystem::u8path(argv[1]);
    path += "-"+std::to_string(steady_clock::now().time_since_epoch().count())+".pcap";
    struct Cleanup { std::filesystem::path path; ~Cleanup(){std::error_code ec;std::filesystem::remove(path,ec);} } cleanup{path};
    PcapWriter writer;check(writer.open(path,{}).ok(),"create owned PCAP fixture");
    for(unsigned i=0;i<10;++i)check(writer.write(raw(6,100+i,2,0,i)).ok(),"write SYN fixture");
    for(unsigned i=10;i<13;++i)check(writer.write(raw(17,9999,0,0,i)).ok(),"write UDP fixture");
    check(writer.close().ok(),"close fixture");
    ProcessingSession session;rules=defaultAlertRules();for(auto& rule:rules)rule.threshold=2;
    session.configureAlerts(rules);check(session.startFile(path).ok(),"start file analysis");wait([&]{return session.snapshot().state==ProcessingState::Completed;},"file completed");
    auto initial=session.alertSnapshot();check(initial.records.size()==2&&count(initial,AlertRule::PortScan)==1&&count(initial,AlertRule::Udp)==1,"offline scan and UDP detected");
    const auto totals=session.snapshot().statistics;const auto udp=std::find_if(initial.records.begin(),initial.records.end(),[](const auto& a){return a.rule==AlertRule::Udp;});
    const auto udpLast=udp->last;
    rules[2].threshold=20;check(session.configureAlerts(rules).ok(),"change scan threshold");wait([&]{return !rescanning(session.alertSnapshot());},"rescan completed");
    auto updated=session.alertSnapshot();check(updated.error.empty()&&count(updated,AlertRule::PortScan)==0&&count(updated,AlertRule::Udp)==1,"rescan replaces only affected rule");
    check(session.snapshot().statistics.totalPackets==totals.totalPackets&&session.snapshot().statistics.totalBytes==totals.totalBytes,"rescan does not alter normal statistics");
    check(std::find_if(updated.records.begin(),updated.records.end(),[](const auto& a){return a.rule==AlertRule::Udp;})->last==udpLast,"unaffected rule evidence retained");
    rules[2].threshold=1;session.configureAlerts(rules);rules[2].threshold=30;session.configureAlerts(rules);rules[2].threshold=2;session.configureAlerts(rules);
    wait([&]{return !rescanning(session.alertSnapshot());},"latest rescan completed");check(count(session.alertSnapshot(),AlertRule::PortScan)==1,"latest configuration wins");
    ProcessingSession paced; paced.configureAlerts(rules);ProcessingOptions options;options.pacedReplay=true;options.replaySpeed=100;check(paced.startFile(path,options).ok(),"start paced replay");wait([&]{return paced.snapshot().state==ProcessingState::Completed;},"paced replay completed");
    check(paced.alertSnapshot().records.size()==session.alertSnapshot().records.size(),"replay speed does not alter alerts");
    ProcessingSession prefix;prefix.configureAlerts(rules);options.replaySpeed=.1;
    check(prefix.startFile(path,options).ok(),"start slow replay for prefix isolation");
    wait([&]{return prefix.snapshot().statistics.totalPackets>=1;},"slow replay processed first packet");
    check(prefix.pause().ok(),"pause slow replay");
    const auto seen=prefix.snapshot().statistics.totalPackets;
    check(seen<13,"slow replay pauses before EOF");
    auto prefixRules=rules;prefixRules[2].threshold=1;prefix.configureAlerts(prefixRules);
    wait([&]{return !rescanning(prefix.alertSnapshot());},"paused prefix rescan completed");
    const auto prefixResult=prefix.alertSnapshot();
    check(prefixResult.processedPackets==seen&&prefix.snapshot().statistics.totalPackets==seen,"rescan does not consume unplayed packets");
    check(std::all_of(prefixResult.records.begin(),prefixResult.records.end(),[seen](const auto& a){return a.packetSequence<=seen;}),"prefix alert evidence cannot refer to future packets");
    prefix.stop();
    rules[3].enabled=false;session.configureAlerts(rules);check(count(session.alertSnapshot(),AlertRule::Udp)==0,"disable file rule removes results immediately");
    AlertMonitor pausedFile;pausedFile.configure(rules);pausedFile.begin(42,path);pausedFile.setPaused(true);
    {PcapReader reader;check(reader.open(path).ok(),"open paused analysis source");RawPacket input;OperationResult error;std::uint64_t sequence=0;
        while(reader.readNext(input,error)==ReadStatus::Packet)pausedFile.add(parsePacket(input,++sequence).record);}
    pausedFile.finish();check(pausedFile.snapshot().records.empty(),"paused file detection remains frozen through EOF");
    pausedFile.setPaused(false);wait([&]{return !rescanning(pausedFile.snapshot());},"resume after EOF completes automatic scan");
    check(pausedFile.snapshot().finished&&count(pausedFile.snapshot(),AlertRule::PortScan)==1,"resume after EOF evaluates full processed file");
    // Rescan failure preserves results and is visible, never changes statistics.
    {std::ofstream changed(path,std::ios::binary|std::ios::app);changed.put('x');}
    rules[2].threshold=3;session.configureAlerts(rules);wait([&]{return !rescanning(session.alertSnapshot());},"changed-file rescan finishes");
    check(!session.alertSnapshot().error.empty()&&count(session.alertSnapshot(),AlertRule::PortScan)==1,"changed source file error preserves original alerts");
    // Starting a new session cancels old rescan publications.
    rules[2].threshold=4;session.configureAlerts(rules);session.startFile(path);wait([&]{auto state=session.snapshot().state;return state==ProcessingState::Completed||state==ProcessingState::Failed;},"replacement session settled");
    check(session.alertSnapshot().sessionId==session.snapshot().sessionId,"new session isolates scan results");
    std::cout<<checks<<" alert checks passed\n";return 0;
}catch(const std::exception& e){std::cerr<<"FAIL "<<e.what()<<'\n';return 1;}}
