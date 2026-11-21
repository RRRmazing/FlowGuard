// Maintainer: He Junjie. AI-assisted implementation; see accompanying tests.
#pragma once

// Private test seam. Module consumers include core/module_contracts.h instead.
#include <winsock2.h>
#include <pcap.h>
#include "core/module_contracts.h"

namespace flowguard::capture_detail {

using FindAllDevices = decltype(&pcap_findalldevs);
using FreeAllDevices = decltype(&pcap_freealldevs);

DeviceListResult enumerateDevicesWith(FindAllDevices findDevices,
                                     FreeAllDevices freeDevices);

} // namespace flowguard::capture_detail
