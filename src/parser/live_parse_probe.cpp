// Stage-1 integration/verification tool, not the later application PCAP writer.
#include "parser/packet_console.h"
#include <pcap.h>
#include <windows.h>
#include <algorithm>
#include <charconv>
#include <filesystem>
#include <memory>
#include <thread>

using namespace flowguard;
namespace {
struct Evidence {
    std::unique_ptr<pcap_t,decltype(&pcap_close)> dead{nullptr,pcap_close};
    std::unique_ptr<pcap_dumper_t,decltype(&pcap_dump_close)> dump{nullptr,pcap_dump_close};
    std::uint32_t link=0;
    bool write(const RawPacket& packet,const std::filesystem::path& path) {
        if (!dump) {
            dead.reset(pcap_open_dead(static_cast<int>(packet.linkType),65535));
            if (!dead) return false;
            // CREATE_NEW refuses overwrite, including races; pcap takes handle ownership.
            const auto handle=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
            if (handle==INVALID_HANDLE_VALUE) { std::cerr << "Cannot create evidence file (existing file is never overwritten)\n"; return false; }
            dump.reset(pcap_dump_hopen(dead.get(),reinterpret_cast<intptr_t>(handle)));
            if (!dump) { CloseHandle(handle); return false; }
            link=packet.linkType;
        }
        if (link!=packet.linkType) return false;
        const auto micros=std::chrono::duration_cast<std::chrono::microseconds>(packet.timestamp.time_since_epoch()).count();
        pcap_pkthdr h{}; h.ts.tv_sec=static_cast<long>(micros/1000000); h.ts.tv_usec=static_cast<long>(micros%1000000);
        h.len=packet.originalLength; h.caplen=packet.capturedLength;
        pcap_dump(reinterpret_cast<u_char*>(dump.get()),&h,packet.bytes.data());
        return pcap_dump_flush(dump.get())==0;
    }
};
}
int main(int argc,char** argv) {
    CaptureOptions options;
    int seconds=5;
    std::filesystem::path evidence;
    for (int i=1;i<argc;i+=2) {
        if (i+1>=argc) return 2;
        const std::string key=argv[i], value=argv[i+1];
        if (key=="--device") options.deviceId=value;
        else if (key=="--bpf") options.bpfExpression=value;
        else if (key=="--output") evidence=std::filesystem::u8path(value);
        else if (key=="--seconds") {
            const auto result=std::from_chars(value.data(),value.data()+value.size(),seconds);
            if (result.ec!=std::errc{} || result.ptr!=value.data()+value.size() || seconds<1 || seconds>60) return 2;
        } else return 2;
    }
    if (options.deviceId.empty() || options.bpfExpression.empty()) {
        std::cerr << "Usage: flowguard_live_parse_probe --device ID --bpf EXPR [--seconds 1..60] [--output new.pcap]\n";
        return 2;
    }
    CaptureSession session;
    const auto started=session.start(options);
    if (!started.ok()) { std::cerr << started.message << '\n'; return 1; }
    Evidence writer;
    std::uint64_t count=0;
    bool ok=true;
    auto drain=[&](std::size_t limit) {
        RawPacket packet;
        for (std::size_t batch=0;batch<limit && session.tryPop(packet);++batch) {
            ++count;
            // Keep the verification output and evidence bounded even on a busy adapter.
            if (count>256) continue;
            console::print(parsePacket(packet,count),true);
            if (!evidence.empty() && !writer.write(packet,evidence)) ok=false;
        }
    };
    const auto deadline=std::chrono::steady_clock::now()+std::chrono::seconds(seconds);
    while (ok && std::chrono::steady_clock::now()<deadline && session.status().state==CaptureState::Running) {
        drain(500); std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    session.stop(); drain(options.maxQueuePackets);
    const auto status=session.status();
    std::cerr << "Processed=" << count << " exported=" << (std::min)(count,std::uint64_t{256}) << " dropped=" << status.queueDroppedPackets << '\n';
    if (!status.lastError.ok()) { std::cerr << status.lastError.message << '\n'; ok=false; }
    return ok && count>0 ? 0 : 1;
}
