#pragma once
#include "parser/packet_parser.h"
#include <iomanip>
#include <iostream>

namespace flowguard::console {
inline const char* statusName(ParseStatus status) {
    const char* names[]={"Complete","Truncated","Unsupported","Malformed"};
    return names[static_cast<unsigned>(status)];
}
inline void quoted(const std::string& value) {
    std::cout << '"';
    for (const unsigned char c:value) {
        if (c=='"' || c=='\\') std::cout << '\\' << c;
        else if (c<32) std::cout << "\\u00" << std::hex << std::setfill('0') << std::setw(2) << unsigned(c) << std::dec;
        else std::cout << c;
    }
    std::cout << '"';
}
inline void tree(const std::vector<ProtocolField>& fields, unsigned depth=0) {
    for (const auto& f:fields) {
        std::cout << std::string(depth*2,' ') << f.name << ": " << f.value << '\n';
        tree(f.children,depth+1);
    }
}
inline void jsonTree(const std::vector<ProtocolField>& fields) {
    std::cout << '[';
    bool first=true;
    for (const auto& f:fields) {
        if (!first) std::cout << ',';
        first=false;
        std::cout << "{\"name\":"; quoted(f.name); std::cout << ",\"value\":"; quoted(f.value);
        std::cout << ",\"children\":"; jsonTree(f.children); std::cout << '}';
    }
    std::cout << ']';
}
template<class T> inline void optional(const std::optional<T>& value) {
    if (value) std::cout << static_cast<unsigned>(*value); else std::cout << "null";
}
inline void print(const ParsedPacket& parsed, bool json) {
    const auto& r=parsed.record;
    if (!json) {
        std::cout << "Packet " << r.sequence << " length=" << r.originalLength << " captured=" << r.capturedLength
                  << " status=" << statusName(r.status) << '\n';
        std::cout << "timestamp_us=" << std::chrono::duration_cast<std::chrono::microseconds>(r.timestamp.time_since_epoch()).count() << '\n';
        tree(parsed.fields);
        if (!r.diagnostic.empty()) std::cout << "Diagnostic: " << r.diagnostic << '\n';
        return;
    }
    std::cout << "{\"sequence\":" << r.sequence << ",\"originalLength\":" << r.originalLength << ",\"capturedLength\":" << r.capturedLength;
    std::cout << ",\"timestamp_ns\":" << std::chrono::duration_cast<std::chrono::nanoseconds>(r.timestamp.time_since_epoch()).count();
    std::cout << ",\"status\":"; quoted(statusName(r.status));
    for (const auto& pair:{std::pair<const char*,const std::string&>{"sourceMac",r.sourceMac},{"destinationMac",r.destinationMac},{"sourceIp",r.sourceIp},{"destinationIp",r.destinationIp},{"diagnostic",r.diagnostic}}) {
        std::cout << ','; quoted(pair.first); std::cout << ':'; quoted(pair.second);
    }
    std::cout << ",\"etherType\":"; optional(r.etherType);
    std::cout << ",\"ipVersion\":"; optional(r.ipVersion);
    std::cout << ",\"ttlOrHopLimit\":"; optional(r.ttlOrHopLimit);
    std::cout << ",\"ipProtocol\":"; optional(r.ipProtocol);
    std::cout << ",\"sourcePort\":"; optional(r.sourcePort);
    std::cout << ",\"destinationPort\":"; optional(r.destinationPort);
    std::cout << ",\"tcpFlags\":"; optional(r.tcpFlags);
    std::cout << ",\"isDns\":" << (r.isDns ? "true" : "false") << ",\"fields\":";
    jsonTree(parsed.fields); std::cout << "}\n";
}
}
