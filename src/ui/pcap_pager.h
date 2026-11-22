// He Junjie: bounded file-backed browsing; live retention does not limit offline access.
#pragma once
#include "core/module_contracts.h"
#include <atomic>

namespace flowguard {
struct PcapPage {
    OperationResult result;
    std::vector<ParsedPacket> packets;
    std::uint64_t page = 0, pageCount = 1, totalPackets = 0, matchedPackets = 0;
};
class PcapPager {
public:
    static constexpr std::size_t pageSize = 2000;
    OperationResult index(const std::filesystem::path &, const DisplayFilter &, const std::atomic_bool &cancel);
    PcapPage load(std::uint64_t page, const std::atomic_bool &cancel);
private:
    struct Boundary { std::uint64_t offset, sequence; };
    std::vector<Boundary> pages_;
    PcapReader reader_;
    std::filesystem::path path_;
    std::filesystem::file_time_type modified_{};
    std::uintmax_t bytes_ = 0;
    DisplayFilter filter_;
    std::uint64_t total_ = 0, matched_ = 0;
    bool ready_ = false;
};
}
