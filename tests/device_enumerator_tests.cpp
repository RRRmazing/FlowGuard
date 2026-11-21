// Maintainer: He Junjie. AI-assisted tests using a simulated Npcap backend.
#include "capture/device_enumerator_detail.h"
#include <cstdio>
#include <iostream>

namespace {
struct BackendState {
    pcap_if_t* root = nullptr;
    int status = 0;
    const char* error = "";
    int finds = 0;
    int frees = 0;
    pcap_if_t* freed = nullptr;
} backend;
int failures = 0;

void check(bool condition, const char* message)
{
    if (!condition) {
        ++failures;
        std::cerr << "FAIL: " << message << '\n';
    }
}
int fakeFind(pcap_if_t** devices, char* error)
{
    ++backend.finds;
    *devices = backend.root;
    std::snprintf(error, PCAP_ERRBUF_SIZE, "%s", backend.error);
    return backend.status;
}
void fakeFree(pcap_if_t* devices)
{
    ++backend.frees;
    backend.freed = devices;
}
flowguard::DeviceListResult enumerateFake()
{
    return flowguard::capture_detail::enumerateDevicesWith(&fakeFind, &fakeFree);
}

void emptyListAndFailures()
{
    backend = {};
    auto result = enumerateFake();
    check(result.result.ok() && result.devices.empty(), "empty list is a successful result");
    check(backend.finds == 1 && backend.frees == 0, "empty list needs no free");

    backend = {};
    backend.status = -1;
    backend.error = "synthetic backend failure";
    result = enumerateFake();
    check(result.result.code == flowguard::ErrorCode::DeviceError && result.devices.empty(),
          "backend failure produces an error and no partial output");
    check(result.result.message == backend.error, "backend diagnostics are preserved");

    pcap_if_t partial{};
    backend = {};
    backend.root = &partial;
    backend.status = -1;
    result = enumerateFake();
    check(!result.result.ok() && !result.result.message.empty(), "missing error text gets a fallback");
    check(backend.frees == 1 && backend.freed == &partial, "partial failure list freed once");
}

void conversionAndOwnership()
{
    char firstName[] = "adapter-1";
    char firstDescription[] = "Test adapter";
    char secondName[] = "adapter-2";
    pcap_if_t second{};
    second.name = secondName; // null description and no addresses are valid
    pcap_if_t first{};
    first.name = firstName;
    first.description = firstDescription;
    first.flags = PCAP_IF_LOOPBACK;
    first.next = &second;

    sockaddr_in ipv4{};
    ipv4.sin_family = AF_INET;
    ipv4.sin_addr.S_un.S_addr = htonl(0xC0000201UL); // 192.0.2.1, no network I/O
    sockaddr_in6 ipv6{};
    ipv6.sin6_family = AF_INET6;
    reinterpret_cast<unsigned char*>(&ipv6.sin6_addr)[15] = 1;
    sockaddr_in6 scoped{};
    scoped.sin6_family = AF_INET6;
    auto* scopedBytes = reinterpret_cast<unsigned char*>(&scoped.sin6_addr);
    scopedBytes[0] = 0xfe;
    scopedBytes[1] = 0x80;
    scopedBytes[15] = 1;
    scoped.sin6_scope_id = 12;
    sockaddr unknown{};
    unknown.sa_family = AF_UNSPEC;

    pcap_addr_t nullAddress{};
    pcap_addr_t unsupported{};
    unsupported.addr = &unknown;
    unsupported.next = &nullAddress;
    pcap_addr_t scopeEntry{};
    scopeEntry.addr = reinterpret_cast<sockaddr*>(&scoped);
    scopeEntry.next = &unsupported;
    pcap_addr_t duplicate{};
    duplicate.addr = reinterpret_cast<sockaddr*>(&ipv4);
    duplicate.next = &scopeEntry;
    pcap_addr_t v6Entry{};
    v6Entry.addr = reinterpret_cast<sockaddr*>(&ipv6);
    v6Entry.next = &duplicate;
    pcap_addr_t v4Entry{};
    v4Entry.addr = reinterpret_cast<sockaddr*>(&ipv4);
    v4Entry.next = &v6Entry;
    first.addresses = &v4Entry;

    backend = {};
    backend.root = &first;
    const auto result = enumerateFake();
    check(result.result.ok() && result.devices.size() == 2, "convert multiple linked devices");
    check(backend.frees == 1 && backend.freed == &first, "successful list freed once");
    if (result.devices.size() != 2) return;
    const auto& a = result.devices[0];
    const auto& b = result.devices[1];
    check(a.id == "adapter-1" && a.description == "Test adapter" && a.loopback,
          "copy device ID, description and loopback flag");
    check(b.description.empty() && b.addresses.empty() && !b.loopback,
          "null description and absent addresses stay empty");
    check(a.addresses.size() == 3, "ignore null/non-IP addresses and deduplicate");
    if (a.addresses.size() == 3) {
        check(a.addresses[0] == "192.0.2.1", "format IPv4");
        check(a.addresses[1] == "::1", "format IPv6");
        check(a.addresses[2] == "fe80::1%12", "retain IPv6 interface scope");
    }
    firstName[0] = 'X';
    firstDescription[0] = 'X';
    check(a.id == "adapter-1" && a.description == "Test adapter", "output owns strings independently");
}

void unselectableDevices()
{
    char empty[] = "";
    pcap_if_t second{};
    second.name = empty;
    pcap_if_t first{};
    first.next = &second;
    backend = {};
    backend.root = &first;
    const auto result = enumerateFake();
    check(result.result.ok() && result.devices.empty(), "skip devices without usable IDs");
    check(backend.frees == 1, "skipped entries still freed");
}
} // namespace

int main()
{
    emptyListAndFailures();
    conversionAndOwnership();
    unselectableDevices();
    if (failures) return 1;
    std::cout << "All device enumeration tests passed (simulated backend, no capture).\n";
    return 0;
}
