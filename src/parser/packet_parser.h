#pragma once
#include "core/packet_types.h"

namespace flowguard {
// Pure, stateless parser. Input bytes are never modified or retained.
PacketRecord parsePacket(const RawPacket& packet, std::uint64_t sequence = 0);
}
