#include "parser/packet_parser.h"
#include "storage/pcap_reader.h"
#include <cstdlib>
#include <iostream>

using namespace flowguard;
namespace {
std::size_t checks=0;
void check(bool value,const char* message) {
    ++checks;
    if (!value) { std::cerr << "FAILED: " << message << '\n'; std::exit(1); }
}
void budget(const ParsedPacket& parsed) {
    std::size_t nodes=0,text=0;
    const auto visit=[&](const auto& self,const std::vector<ProtocolField>& fields,unsigned depth)->void {
        for (const auto& f:fields) {
            check(depth<=16,"field tree depth bound");
            ++nodes; text+=f.name.size()+f.value.size();
            self(self,f.children,depth+1);
        }
    };
    visit(visit,parsed.fields,1);
    check(nodes<=256 && text<=16*1024,"field tree count and text bounds");
}
}
int main(int argc,char** argv) {
    if (argc!=2) return 2;
    PcapReader reader;
    check(reader.open(std::filesystem::u8path(argv[1])).ok(),"open protocol corpus");
    RawPacket raw;
    OperationResult result;
    std::size_t count=0;
    for (;;) {
        const auto status=reader.readNext(raw,result);
        if (status==ReadStatus::EndOfFile) break;
        check(status==ReadStatus::Packet && result.ok(),"read corpus record");
        ++count;
        const auto snapshot=raw.bytes;
        const auto parsed=parsePacket(raw,count);
        check(parsed.record.status==(count==18 ? ParseStatus::Unsupported : ParseStatus::Complete),"expected protocol corpus status");
        budget(parsed);
        check(raw.bytes==snapshot,"parser does not alter source bytes");
        // Prefixes exercise EVERY protocol, including DNS/ARP/VLAN and all tree paths.
        for (std::size_t n=0;n<snapshot.size();++n) {
            auto prefix=raw;
            prefix.bytes.resize(n); prefix.capturedLength=static_cast<std::uint32_t>(n);
            const auto shortPacket=parsePacket(prefix,count);
            check(shortPacket.record.status==ParseStatus::Truncated,"every capture prefix is explicitly truncated");
            budget(shortPacket);
        }
        // Both shorter and longer original metadata must never be silently accepted.
        auto invalid=raw; invalid.originalLength=raw.capturedLength-1;
        check(parsePacket(invalid,count).record.status==ParseStatus::Malformed,"invalid original length");
        invalid=raw; ++invalid.capturedLength;
        check(parsePacket(invalid,count).record.status==ParseStatus::Malformed,"invalid captured length");
        invalid=raw; invalid.linkType=0;
        check(parsePacket(invalid,count).record.status==ParseStatus::Unsupported,"non-Ethernet link remains unsupported");
        // Mutating a valid protocol seed reaches deeper parser paths than random bytes alone.
        for (std::size_t offset=0;offset<snapshot.size();++offset) {
            for (unsigned mask:{1u,0x80u,0xffu}) {
                auto mutated=raw; mutated.bytes[offset]^=static_cast<std::uint8_t>(mask);
                const auto output=parsePacket(mutated,count);
                check(output.record.sequence==count && output.record.timestamp==raw.timestamp,"mutated input preserves metadata");
                budget(output);
            }
        }
    }
    check(count==18,"all 18 protocol cases were exercised");
    std::cout << count << " protocol seeds; " << checks << " boundary/mutation/tree checks passed\n";
}
