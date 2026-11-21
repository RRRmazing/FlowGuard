// Maintainer: He Junjie. AI-assisted compile checks for the public contract.
#include "core/module_contracts.h"
#include "core/module_contracts.h"
#include <type_traits>

static_assert(std::is_copy_constructible_v<flowguard::RawPacket>);
static_assert(std::is_copy_constructible_v<flowguard::ParsedPacket>);
static_assert(!std::is_copy_constructible_v<flowguard::CaptureSession>);
static_assert(std::is_same_v<decltype(flowguard::enumerateDevices()), flowguard::DeviceListResult>);
static_assert(std::is_same_v<decltype(flowguard::parsePacket(flowguard::RawPacket{}, 1)),
                             flowguard::ParsedPacket>);
// Do not instantiate modules whose implementations belong to later tasks.
