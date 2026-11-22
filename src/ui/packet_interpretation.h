#pragma once
#include "core/module_contracts.h"
#include <QString>

namespace flowguard {
// Uses only parsed fields; does not infer connection history or validate checksums.
QString packetInterpretation(const ParsedPacket &packet);
}
