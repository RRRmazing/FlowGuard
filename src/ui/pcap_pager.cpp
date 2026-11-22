#include "ui/pcap_pager.h"
#include <algorithm>

namespace flowguard {
namespace {
OperationResult cancelled() { return {ErrorCode::InvalidState,"file browsing cancelled"}; }
}
OperationResult PcapPager::index(const std::filesystem::path &path, const DisplayFilter &filter,
                               const std::atomic_bool &cancel) {
    ready_=false; pages_.clear(); total_=0; matched_=0; reader_.close();
    path_=path; filter_=filter;
    std::error_code ec;
    bytes_=std::filesystem::file_size(path_,ec);
    if (ec) return {ErrorCode::IoError,"cannot inspect PCAP size"};
    modified_=std::filesystem::last_write_time(path_,ec);
    if (ec) return {ErrorCode::IoError,"cannot inspect PCAP modification time"};
    auto result=reader_.open(path_);
    if (!result.ok()) return result;
    while (!cancel.load()) {
        const auto offset=reader_.recordPosition();
        RawPacket raw;
        const auto status=reader_.readNext(raw,result);
        if (status==ReadStatus::EndOfFile) { ready_=true; return {}; }
        if (status==ReadStatus::Error) return result;
        if (!offset) return {ErrorCode::IoError,"cannot locate PCAP record"};
        auto packet=parsePacket(raw,++total_);
        if (matchesDisplayFilter(packet.record,filter_)) {
            if (matched_%pageSize==0) pages_.push_back({*offset,total_});
            ++matched_;
        }
    }
    return cancelled();
}
PcapPage PcapPager::load(std::uint64_t page, const std::atomic_bool &cancel) {
    PcapPage out; out.totalPackets=total_; out.matchedPackets=matched_;
    out.pageCount=std::max<std::uint64_t>(1,pages_.size()); out.page=std::min(page,out.pageCount-1);
    if (!ready_) { out.result={ErrorCode::InvalidState,"file index is not ready"}; return out; }
    std::error_code ec;
    const auto bytes=std::filesystem::file_size(path_,ec);
    if (ec || bytes!=bytes_) { out.result={ErrorCode::IoError,"PCAP changed; reopen the file"}; return out; }
    const auto modified=std::filesystem::last_write_time(path_,ec);
    if (ec || modified!=modified_) { out.result={ErrorCode::IoError,"PCAP changed; reopen the file"}; return out; }
    if (pages_.empty()) return out;
    const auto boundary=pages_[static_cast<std::size_t>(out.page)];
    out.result=reader_.seekRecord(boundary.offset);
    if (!out.result.ok()) return out;
    auto sequence=boundary.sequence;
    while (out.packets.size()<pageSize && !cancel.load()) {
        RawPacket raw; OperationResult result;
        const auto status=reader_.readNext(raw,result);
        if (status==ReadStatus::EndOfFile) break;
        if (status==ReadStatus::Error) { out.result=result; out.packets.clear(); return out; }
        auto packet=parsePacket(raw,sequence++);
        if (matchesDisplayFilter(packet.record,filter_)) out.packets.push_back(std::move(packet));
    }
    if (cancel.load()) { out.result=cancelled(); out.packets.clear(); }
    return out;
}
}
