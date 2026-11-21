#include "storage/pcap_reader.h"
#include <fstream>
#include <array>
#include <limits>

namespace flowguard {
struct PcapReader::Impl {
    std::ifstream stream;
    PcapFileInfo info;
    bool little = false;
    bool failed = false;
    std::uint32_t value(const std::uint8_t* p, unsigned count=4) const {
        std::uint32_t v=0;
        for (unsigned i=0;i<count;++i) v=(v<<8)|p[little ? count-1-i : i];
        return v;
    }
};
namespace {
OperationResult error(ErrorCode code, const char* message) { return {code,message}; }
}
PcapReader::PcapReader() : impl_(std::make_unique<Impl>()) {}
PcapReader::~PcapReader() = default;
OperationResult PcapReader::open(const std::filesystem::path& path) {
    auto& s=*impl_;
    if (s.stream.is_open()) return error(ErrorCode::InvalidState,"reader is already open");
    s.info={}; s.failed=false; s.stream.clear();
    s.stream.open(path,std::ios::binary);
    if (!s.stream) return error(ErrorCode::IoError,"cannot open PCAP file");
    const auto reject=[&](ErrorCode code,const char* message) { close(); return error(code,message); };
    std::array<std::uint8_t,24> h{};
    s.stream.read(reinterpret_cast<char*>(h.data()),4);
    if (s.stream.gcount()!=4) return reject(ErrorCode::IoError,"missing or incomplete PCAP magic");
    if (h[0]==0x0a && h[1]==0x0d && h[2]==0x0d && h[3]==0x0a) return reject(ErrorCode::Unsupported,"PCAPNG is not supported");
    const std::array<std::uint8_t,4> magic{h[0],h[1],h[2],h[3]};
    if (magic==std::array<std::uint8_t,4>{0xd4,0xc3,0xb2,0xa1}) { s.little=true; s.info.nanosecondPrecision=false; }
    else if (magic==std::array<std::uint8_t,4>{0xa1,0xb2,0xc3,0xd4}) { s.little=false; s.info.nanosecondPrecision=false; }
    else if (magic==std::array<std::uint8_t,4>{0x4d,0x3c,0xb2,0xa1}) { s.little=true; s.info.nanosecondPrecision=true; }
    else if (magic==std::array<std::uint8_t,4>{0xa1,0xb2,0x3c,0x4d}) { s.little=false; s.info.nanosecondPrecision=true; }
    else return reject(ErrorCode::Unsupported,"unrecognized PCAP format");
    s.stream.read(reinterpret_cast<char*>(h.data()+4),20);
    if (s.stream.gcount()!=20) return reject(ErrorCode::IoError,"incomplete PCAP global header");
    if (s.value(h.data()+4,2)!=2 || s.value(h.data()+6,2)!=4) return reject(ErrorCode::Unsupported,"only PCAP version 2.4 is supported");
    s.info.snapshotLength=s.value(h.data()+16); s.info.linkType=s.value(h.data()+20);
    if (!s.info.snapshotLength) return reject(ErrorCode::InvalidArgument,"PCAP snapshot length is zero");
    // Upper link-type bits describe extra metadata in newer PCAP variants.
    if (s.info.linkType>65535) return reject(ErrorCode::Unsupported,"PCAP link-type metadata flags are not supported");
    return {};
}
PcapFileInfo PcapReader::info() const { return impl_->info; }
ReadStatus PcapReader::readNext(RawPacket& packet, OperationResult& result) {
    auto& s=*impl_;
    if (!s.stream.is_open() || s.failed) { result=error(ErrorCode::InvalidState,"reader is closed or failed; close and reopen it"); return ReadStatus::Error; }
    const auto fail=[&](ErrorCode code,const char* message) { s.failed=true; result=error(code,message); return ReadStatus::Error; };
    std::array<std::uint8_t,16> h{};
    s.stream.read(reinterpret_cast<char*>(h.data()),16);
    const auto count=s.stream.gcount();
    if (!count && s.stream.eof() && !s.stream.bad()) { result={}; return ReadStatus::EndOfFile; }
    if (count!=16) return fail(ErrorCode::IoError,"incomplete PCAP record header");
    const auto seconds=s.value(h.data()), fraction=s.value(h.data()+4);
    const auto captured=s.value(h.data()+8), original=s.value(h.data()+12);
    if (fraction >= (s.info.nanosecondPrecision ? 1000000000u : 1000000u)) return fail(ErrorCode::InvalidArgument,"invalid timestamp fraction");
    if (captured>original || captured>s.info.snapshotLength) return fail(ErrorCode::InvalidArgument,"invalid captured/original/snapshot lengths");
    if (captured>16u*1024*1024) return fail(ErrorCode::ResourceLimit,"PCAP record exceeds 16 MiB");
    RawPacket next;
    next.linkType=s.info.linkType; next.capturedLength=captured; next.originalLength=original;
    const auto time=std::chrono::seconds(seconds)+std::chrono::nanoseconds(static_cast<std::int64_t>(fraction)*(s.info.nanosecondPrecision ? 1 : 1000));
    next.timestamp=std::chrono::system_clock::time_point(std::chrono::duration_cast<std::chrono::system_clock::duration>(time));
    next.bytes.resize(captured);
    if (captured) {
        s.stream.read(reinterpret_cast<char*>(next.bytes.data()),captured);
        if (s.stream.gcount()!=captured) return fail(ErrorCode::IoError,"incomplete PCAP record bytes");
    }
    packet=std::move(next); result={}; return ReadStatus::Packet;
}
void PcapReader::close() { if (impl_->stream.is_open()) impl_->stream.close(); impl_->stream.clear(); impl_->failed=false; impl_->info={}; }
}
