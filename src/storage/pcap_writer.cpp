// Maintainer: He Junjie. AI-assisted stage-2 PCAP writer (Windows x64).
#include "core/module_contracts.h"
#include <windows.h>
#include <array>
#include <algorithm>
#include <limits>

namespace flowguard {
struct PcapWriter::Impl {
    HANDLE handle = INVALID_HANDLE_VALUE;
    PcapWriteOptions options;
    std::uint64_t bytes = 0;
    bool failed = false;
    std::chrono::steady_clock::time_point lastFlush;
    OperationResult put(const std::uint8_t* data, std::size_t count)
    {
        while (count) {
            DWORD written = 0;
            const auto chunk = static_cast<DWORD>((std::min)(count, std::size_t{1024 * 1024}));
            if (!WriteFile(handle, data, chunk, &written, nullptr) || !written) {
                failed = true;
                return {ErrorCode::IoError, "PCAP write failed (Windows error " + std::to_string(GetLastError()) + ")"};
            }
            bytes += written; data += written; count -= written;
        }
        return {};
    }
};
namespace {
void little(std::uint8_t* target, std::uint32_t value, unsigned size = 4)
{
    for (unsigned i = 0; i < size; ++i) target[i] = static_cast<std::uint8_t>(value >> (8 * i));
}
}
PcapWriter::PcapWriter() : impl_(std::make_unique<Impl>()) {}
PcapWriter::~PcapWriter() { close(); }
OperationResult PcapWriter::open(const std::filesystem::path& path, const PcapWriteOptions& options)
{
    auto& s = *impl_;
    if (s.handle != INVALID_HANDLE_VALUE) return {ErrorCode::InvalidState, "writer is already open"};
    if (path.empty() || options.linkType > 65535 || !options.snapshotLength ||
        options.snapshotLength > 16 * 1024 * 1024 || options.maxFileBytes < 24)
        return {ErrorCode::InvalidArgument, "invalid PCAP path or writer limits"};
    s.handle = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (s.handle == INVALID_HANDLE_VALUE)
        return {ErrorCode::IoError, "cannot create PCAP file; existing files are never overwritten (Windows error " +
                                  std::to_string(GetLastError()) + ")"};
    s.options = options; s.bytes = 0; s.failed = false;
    s.lastFlush = std::chrono::steady_clock::now();
    std::array<std::uint8_t, 24> header{};
    little(header.data(), 0xa1b2c3d4); little(header.data() + 4, 2, 2); little(header.data() + 6, 4, 2);
    little(header.data() + 16, options.snapshotLength); little(header.data() + 20, options.linkType);
    const auto result = s.put(header.data(), header.size());
    if (!result.ok()) { close(); return result; }
    return {};
}
OperationResult PcapWriter::write(const RawPacket& packet)
{
    auto& s = *impl_;
    if (s.handle == INVALID_HANDLE_VALUE || s.failed) return {ErrorCode::InvalidState, "writer is closed or failed"};
    if (packet.bytes.size() != packet.capturedLength || packet.capturedLength > packet.originalLength ||
        packet.capturedLength > s.options.snapshotLength || packet.linkType != s.options.linkType)
        return {ErrorCode::InvalidArgument, "inconsistent PCAP packet lengths or link type"};
    const auto micros = std::chrono::duration_cast<std::chrono::microseconds>(packet.timestamp.time_since_epoch()).count();
    if (packet.timestamp.time_since_epoch() < std::chrono::system_clock::duration::zero() ||
        micros / 1000000 > (std::numeric_limits<std::uint32_t>::max)())
        return {ErrorCode::InvalidArgument, "timestamp outside classic PCAP range"};
    const auto recordBytes = std::uint64_t{16} + packet.capturedLength;
    if (recordBytes > s.options.maxFileBytes - s.bytes)
        return {ErrorCode::ResourceLimit, "PCAP file size limit reached; next packet not written"};
    std::array<std::uint8_t, 16> header{};
    little(header.data(), static_cast<std::uint32_t>(micros / 1000000));
    little(header.data() + 4, static_cast<std::uint32_t>(micros % 1000000));
    little(header.data() + 8, packet.capturedLength); little(header.data() + 12, packet.originalLength);
    auto result = s.put(header.data(), header.size());
    if (result.ok()) result = s.put(packet.bytes.data(), packet.bytes.size());
    if (result.ok() && std::chrono::steady_clock::now() - s.lastFlush >= std::chrono::seconds(1)) result = flush();
    return result;
}
OperationResult PcapWriter::flush()
{
    auto& s = *impl_;
    if (s.handle == INVALID_HANDLE_VALUE || s.failed) return {ErrorCode::InvalidState, "writer is closed or failed"};
    if (!FlushFileBuffers(s.handle)) {
        s.failed = true;
        return {ErrorCode::IoError, "PCAP flush failed"};
    }
    s.lastFlush = std::chrono::steady_clock::now();
    return {};
}
OperationResult PcapWriter::close()
{
    auto& s = *impl_;
    if (s.handle == INVALID_HANDLE_VALUE) return {};
    auto result = s.failed ? OperationResult{ErrorCode::IoError, "closing failed PCAP writer"} : flush();
    if (!CloseHandle(s.handle) && result.ok()) result = {ErrorCode::IoError, "PCAP close failed"};
    s.handle = INVALID_HANDLE_VALUE;
    return result;
}
} // namespace flowguard
