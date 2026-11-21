// Maintainer: He Junjie. AI-assisted stage-2 statistics.
#include "core/module_contracts.h"
#include <algorithm>
#include <cmath>

namespace flowguard {
void StatisticsEngine::reset() { totals_ = {}; }
void StatisticsEngine::add(const PacketRecord& record)
{
    ++totals_.totalPackets;
    totals_.totalBytes += record.originalLength;
    ++totals_.lengthFrequency[(std::min)(record.originalLength, std::uint32_t{65536})];
    ++totals_.lengthGroups[record.originalLength <= 46 ? 0 : record.originalLength <= 1500 ? 1 : 2];
    ++totals_.networkCounts[record.network];
    ++totals_.transportCounts[record.transport];
    ++totals_.parseCounts[record.status];
    if (record.isDns) ++totals_.dnsPackets;
}
StatisticsSnapshot StatisticsEngine::snapshot() const { return totals_; }
RateSample calculateRate(const StatisticsSnapshot& previous, const StatisticsSnapshot& current,
                         double elapsedSeconds)
{
    if (!std::isfinite(elapsedSeconds) || elapsedSeconds <= 0 ||
        current.totalPackets < previous.totalPackets || current.totalBytes < previous.totalBytes ||
        current.dnsPackets < previous.dnsPackets) return {};
    const auto packets = current.totalPackets - previous.totalPackets;
    const auto dns = current.dnsPackets - previous.dnsPackets;
    if (dns > packets) return {};
    return {static_cast<double>(packets) / elapsedSeconds,
            static_cast<double>(current.totalBytes - previous.totalBytes) / elapsedSeconds,
            packets ? static_cast<double>(dns) / static_cast<double>(packets) : 0};
}
} // namespace flowguard
