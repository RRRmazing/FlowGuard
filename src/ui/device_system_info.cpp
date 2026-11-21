// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "ui/device_selector.h"
// clang-format off
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <ipifcons.h>
// clang-format on
#include <vector>

namespace flowguard
{
QMap<QString, DeviceSystemInfo> systemDeviceInfo()
{
    // AdapterName is the GUID used by Npcap; Qt's Windows interface ID may differ.
    ULONG size = 16384;
    std::vector<unsigned char> buffer(size);
    ULONG result = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempt)
    {
        buffer.resize(size);
        result = GetAdaptersAddresses(AF_UNSPEC,
                                      GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_SKIP_ANYCAST |
                                          GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                      nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()), &size);
    }
    QMap<QString, DeviceSystemInfo> records;
    if (result != NO_ERROR)
        return records; // Metadata failure must not hide Npcap devices.
    for (auto *adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()); adapter; adapter = adapter->Next)
    {
        DeviceSystemInfo info;
        info.matched = true;
        if (adapter->FriendlyName)
            info.name = QString::fromWCharArray(adapter->FriendlyName);
        info.running = adapter->OperStatus == IfOperStatusUp;
        MIB_IF_ROW2 row{};
        row.InterfaceLuid = adapter->Luid;
        info.enabled = GetIfEntry2(&row) == NO_ERROR ? row.AdminStatus == NET_IF_ADMIN_STATUS_UP : true;
        if (adapter->IfType == IF_TYPE_IEEE80211)
            info.type = QNetworkInterface::Wifi;
        else if (adapter->IfType == IF_TYPE_ETHERNET_CSMACD)
            info.type = QNetworkInterface::Ethernet;
        else if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            info.type = QNetworkInterface::Loopback;
        const QString id = QString::fromLatin1(adapter->AdapterName).remove('{').remove('}').toCaseFolded();
        records.insert(id, info);
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            records.insert("\\device\\npf_loopback", info);
    }
    return records;
}
} // namespace flowguard
