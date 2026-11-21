// Maintainer: He Junjie. AI-assisted implementation; see accompanying tests.
#include "capture/device_enumerator_detail.h"

#include <ws2tcpip.h>
#include <windows.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#include <utility>

namespace flowguard {
namespace {

// Without pcap_init(PCAP_CHAR_ENC_UTF_8), Npcap uses the Windows local code page.
// Convert at the boundary without changing libpcap's process-wide configuration.
std::string systemTextToUtf8(const char* text)
{
    if (!text || !*text) return {};
    const auto length = std::strlen(text);
    if (length > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        throw std::runtime_error("Npcap text is too long");
    }
    const int inputLength = static_cast<int>(length);
    const int wideLength = MultiByteToWideChar(CP_ACP, 0, text, inputLength, nullptr, 0);
    if (!wideLength) throw std::runtime_error("Cannot decode Npcap system text");
    std::wstring wide(static_cast<std::size_t>(wideLength), L'\0');
    if (!MultiByteToWideChar(CP_ACP, 0, text, inputLength, wide.data(), wideLength)) {
        throw std::runtime_error("Cannot decode Npcap system text");
    }
    const int utf8Length = WideCharToMultiByte(CP_UTF8, 0, wide.data(), wideLength,
                                             nullptr, 0, nullptr, nullptr);
    if (!utf8Length) throw std::runtime_error("Cannot encode Npcap text as UTF-8");
    std::string utf8(static_cast<std::size_t>(utf8Length), '\0');
    if (!WideCharToMultiByte(CP_UTF8, 0, wide.data(), wideLength, utf8.data(),
                             utf8Length, nullptr, nullptr)) {
        throw std::runtime_error("Cannot encode Npcap text as UTF-8");
    }
    return utf8;
}

std::string addressToText(const sockaddr* address)
{
    if (!address) return {};
    char text[INET6_ADDRSTRLEN]{};
    if (address->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        if (!InetNtopA(AF_INET, &ipv4->sin_addr, text, sizeof(text))) {
            throw std::runtime_error("Cannot format an IPv4 adapter address");
        }
        return text;
    }
    if (address->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        if (!InetNtopA(AF_INET6, &ipv6->sin6_addr, text, sizeof(text))) {
            throw std::runtime_error("Cannot format an IPv6 adapter address");
        }
        std::string result(text);
        if (ipv6->sin6_scope_id) result += "%" + std::to_string(ipv6->sin6_scope_id);
        return result;
    }
    return {}; // Not every pcap address is IPv4/IPv6.
}

} // namespace

DeviceListResult capture_detail::enumerateDevicesWith(FindAllDevices findDevices,
                                                      FreeAllDevices freeDevices)
{
    DeviceListResult result;
    pcap_if_t* rawDevices = nullptr;
    char errorBuffer[PCAP_ERRBUF_SIZE]{};
    const int status = findDevices(&rawDevices, errorBuffer);
    // Free even a partial list on backend failure and on conversion exceptions.
    const std::unique_ptr<pcap_if_t, FreeAllDevices> devices(rawDevices, freeDevices);
    try {
        if (status != 0) {
            result.result = {ErrorCode::DeviceError, systemTextToUtf8(errorBuffer)};
            if (result.result.message.empty()) {
                result.result.message = "Npcap adapter enumeration failed";
            }
            return result;
        }
        for (const auto* current = devices.get(); current; current = current->next) {
            if (!current->name || !*current->name) continue; // No selectable ID.
            CaptureDevice device;
            device.id = systemTextToUtf8(current->name);
            device.description = systemTextToUtf8(current->description);
            device.loopback = (current->flags & PCAP_IF_LOOPBACK) != 0;
            for (const auto* entry = current->addresses; entry; entry = entry->next) {
                auto address = addressToText(entry->addr);
                if (!address.empty() && std::find(device.addresses.begin(),
                    device.addresses.end(), address) == device.addresses.end()) {
                    device.addresses.push_back(std::move(address));
                }
            }
            result.devices.push_back(std::move(device));
        }
    } catch (const std::exception& error) {
        result.devices.clear();
        result.result = {ErrorCode::DeviceError, error.what()};
    }
    return result;
}

DeviceListResult enumerateDevices()
{
    return capture_detail::enumerateDevicesWith(&pcap_findalldevs, &pcap_freealldevs);
}

} // namespace flowguard
