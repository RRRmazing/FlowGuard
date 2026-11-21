// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "core/module_contracts.h"
#include <algorithm>
#include <mutex>
#include <windows.h>

// psapi.h requires Windows declarations; keep this include after windows.h.
#include <psapi.h>

namespace flowguard
{
ResourceSample sampleResources()
{
    // Calls are serialized; CPU is measured against elapsed monotonic time.
    static std::mutex mutex;
    static std::optional<std::uint64_t> previousCpu;
    static std::chrono::steady_clock::time_point previousTime;
    std::lock_guard<std::mutex> lock(mutex);
    ResourceSample result;
    result.timestamp = std::chrono::system_clock::now();
    const auto now = std::chrono::steady_clock::now();
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user))
    {
        auto ticks = [](FILETIME t) { return (std::uint64_t(t.dwHighDateTime) << 32) | t.dwLowDateTime; };
        const auto total = ticks(kernel) + ticks(user);
        const auto processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        const double elapsed = std::chrono::duration<double>(now - previousTime).count();
        if (previousCpu && total >= *previousCpu && elapsed > 0 && processors)
            result.cpuPercent = std::clamp(double(total - *previousCpu) / 1e7 / elapsed / processors * 100., 0., 100.);
        previousCpu = total;
        previousTime = now;
    }
    else
        previousCpu.reset();
    PROCESS_MEMORY_COUNTERS memory{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &memory, sizeof(memory)))
        result.workingSetBytes = memory.WorkingSetSize;
    IO_COUNTERS io{};
    if (GetProcessIoCounters(GetCurrentProcess(), &io))
    {
        result.processReadBytes = io.ReadTransferCount;
        result.processWriteBytes = io.WriteTransferCount;
    }
    return result;
}
} // namespace flowguard
