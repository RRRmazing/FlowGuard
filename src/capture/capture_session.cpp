// Maintainer: He Junjie. AI-assisted capture implementation; see capture tests.
#include "capture/device_enumerator_detail.h"
#include "capture/capture_buffer.h"
#include <atomic>
#include <condition_variable>
#include <thread>

namespace flowguard {
namespace {
struct ClosePcap { void operator()(pcap_t* value) const { pcap_close(value); } };
using PcapHandle = std::unique_ptr<pcap_t, ClosePcap>;
std::string nativeError(const char* text)
{
    // Npcap default encoding is the Windows ANSI code page.
    if (!text || !*text) return "Npcap operation failed";
    const int n = MultiByteToWideChar(CP_ACP, 0, text, -1, nullptr, 0);
    if (!n) return "Cannot decode Npcap diagnostic";
    std::wstring wide(static_cast<std::size_t>(n), L'\0');
    MultiByteToWideChar(CP_ACP, 0, text, -1, wide.data(), n);
    const int m = WideCharToMultiByte(CP_UTF8, 0, wide.data(), -1, nullptr, 0, nullptr, nullptr);
    if (!m) return "Cannot encode Npcap diagnostic";
    std::string result(static_cast<std::size_t>(m), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), -1, result.data(), m, nullptr, nullptr);
    result.pop_back();
    return result;
}
} // namespace

struct CaptureSession::Impl {
    capture_detail::CaptureBuffer buffer;
    mutable std::mutex infoMutex;
    CaptureState state = CaptureState::Stopped;
    OperationResult error;
    std::optional<std::uint64_t> received, dropped, interfaceDropped;
    PcapHandle handle;
    std::thread worker;
    std::atomic<bool> stopping{false};
    std::mutex waitMutex;
    std::condition_variable wake;
    std::uint32_t linkType = 0, snapshotLength = 0;

    OperationResult fail(ErrorCode code, std::string message)
    {
        std::lock_guard<std::mutex> lock(infoMutex);
        error = {code, std::move(message)};
        state = CaptureState::Failed;
        return error;
    }
    void driverStats()
    {
        pcap_stat stats{};
        if (pcap_stats(handle.get(), &stats) == 0) {
            std::lock_guard<std::mutex> lock(infoMutex);
            received = stats.ps_recv;
            dropped = stats.ps_drop;
            interfaceDropped = stats.ps_ifdrop;
        }
    }
    void run() noexcept
    {
        try {
            auto nextStats = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            while (!stopping.load()) {
                pcap_pkthdr* header = nullptr;
                const u_char* data = nullptr;
                const int result = pcap_next_ex(handle.get(), &header, &data);
                if (result == 1) {
                    if (!header || (header->caplen && !data) ||
                        header->caplen > header->len || header->caplen > snapshotLength ||
                        header->ts.tv_usec < 0 || header->ts.tv_usec >= 1000000) {
                        buffer.invalid();
                    } else {
                        RawPacket packet;
                        packet.timestamp = std::chrono::system_clock::time_point(
                            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                                std::chrono::seconds(header->ts.tv_sec) +
                                std::chrono::microseconds(header->ts.tv_usec)));
                        packet.originalLength = header->len;
                        packet.capturedLength = header->caplen;
                        packet.linkType = linkType;
                        if (header->caplen) packet.bytes.assign(data, data + header->caplen);
                        buffer.push(std::move(packet));
                    }
                } else if (result == 0) {
                    std::unique_lock<std::mutex> lock(waitMutex);
                    wake.wait_for(lock, std::chrono::milliseconds(10), [this] { return stopping.load(); });
                } else {
                    if (!stopping.load()) fail(ErrorCode::DeviceError, nativeError(pcap_geterr(handle.get())));
                    break;
                }
                if (std::chrono::steady_clock::now() >= nextStats) {
                    driverStats();
                    nextStats = std::chrono::steady_clock::now() + std::chrono::seconds(1);
                }
            }
            driverStats();
        } catch (const std::exception& exception) {
            try { fail(ErrorCode::ResourceLimit, exception.what()); } catch (...) {}
        } catch (...) {
            try { fail(ErrorCode::DeviceError, "Unexpected capture worker failure"); } catch (...) {}
        }
        handle.reset(); // Only the worker reads/closes an active handle.
    }
};

CaptureSession::CaptureSession() : impl_(std::make_unique<Impl>()) {}
CaptureSession::~CaptureSession() { stop(); }

OperationResult CaptureSession::start(const CaptureOptions& options)
{
    {
        std::lock_guard<std::mutex> lock(impl_->infoMutex);
        if (impl_->state == CaptureState::Running) {
            return {ErrorCode::InvalidState, "Capture is already running"};
        }
    }
    stop(); // Reap a previous failed worker before reusing state.
    if (options.deviceId.empty() || options.deviceId.find('\0') != std::string::npos ||
        options.bpfExpression.find('\0') != std::string::npos ||
        !options.snapshotLength || options.snapshotLength > 16 * 1024 * 1024 ||
        options.readTimeoutMs <= 0 || !options.maxQueuePackets || !options.maxQueueBytes) {
        return impl_->fail(ErrorCode::InvalidArgument, "Invalid capture device or capture limits");
    }
    try {
        char errors[PCAP_ERRBUF_SIZE]{};
        PcapHandle handle(pcap_create(options.deviceId.c_str(), errors));
        if (!handle) return impl_->fail(ErrorCode::DeviceError, nativeError(errors));
        if (pcap_set_snaplen(handle.get(), static_cast<int>(options.snapshotLength)) != 0 ||
            pcap_set_promisc(handle.get(), options.promiscuous ? 1 : 0) != 0 ||
            pcap_set_timeout(handle.get(), options.readTimeoutMs) != 0 ||
            pcap_set_tstamp_precision(handle.get(), PCAP_TSTAMP_PRECISION_MICRO) != 0 ||
            pcap_set_immediate_mode(handle.get(), 1) != 0) {
            return impl_->fail(ErrorCode::DeviceError, nativeError(pcap_geterr(handle.get())));
        }
        const int activated = pcap_activate(handle.get());
        if (activated < 0) return impl_->fail(ErrorCode::DeviceError, nativeError(pcap_geterr(handle.get())));
        const int link = pcap_datalink(handle.get());
        if (link < 0) return impl_->fail(ErrorCode::DeviceError, nativeError(pcap_geterr(handle.get())));
        if (!options.bpfExpression.empty()) {
            bpf_program program{};
            if (pcap_compile(handle.get(), &program, options.bpfExpression.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
                return impl_->fail(ErrorCode::FilterError, nativeError(pcap_geterr(handle.get())));
            }
            const int installed = pcap_setfilter(handle.get(), &program);
            pcap_freecode(&program);
            if (installed != 0) return impl_->fail(ErrorCode::FilterError, nativeError(pcap_geterr(handle.get())));
        }
        // Nonblocking reads plus an interruptible wait guarantee idle stop does not
        // depend on the next packet or on a driver's read-timeout interpretation.
        if (pcap_setnonblock(handle.get(), 1, errors) != 0) {
            return impl_->fail(ErrorCode::DeviceError, nativeError(errors));
        }
        impl_->buffer.reset(options.maxQueuePackets, options.maxQueueBytes);
        impl_->linkType = static_cast<std::uint32_t>(link);
        impl_->snapshotLength = options.snapshotLength;
        impl_->handle = std::move(handle);
        impl_->stopping = false;
        {
            std::lock_guard<std::mutex> lock(impl_->infoMutex);
            impl_->state = CaptureState::Running;
            impl_->error = {};
            impl_->received.reset(); impl_->dropped.reset(); impl_->interfaceDropped.reset();
        }
        impl_->worker = std::thread([this] { impl_->run(); });
        return {};
    } catch (const std::exception& exception) {
        impl_->handle.reset();
        return impl_->fail(ErrorCode::ResourceLimit, exception.what());
    }
}

void CaptureSession::stop()
{
    impl_->stopping = true;
    impl_->wake.notify_all();
    if (impl_->worker.joinable()) impl_->worker.join();
    impl_->handle.reset();
    std::lock_guard<std::mutex> lock(impl_->infoMutex);
    if (impl_->state != CaptureState::Failed) impl_->state = CaptureState::Stopped;
}
bool CaptureSession::tryPop(RawPacket& packet) { return impl_->buffer.pop(packet); }
CaptureStatus CaptureSession::status() const
{
    std::lock_guard<std::mutex> lock(impl_->infoMutex);
    auto result = impl_->buffer.snapshot();
    result.state = impl_->state;
    result.lastError = impl_->error;
    result.driverReceived = impl_->received;
    result.driverDropped = impl_->dropped;
    result.interfaceDropped = impl_->interfaceDropped;
    return result;
}
} // namespace flowguard
