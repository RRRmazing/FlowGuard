#include "ui/packet_interpretation.h"
#include <iostream>

using namespace flowguard;
static int failures = 0;
static void check(bool ok, const char *message) {
    if (!ok) { std::cerr << "FAIL: " << message << '\n'; ++failures; }
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    PcapReader reader;
    if (!reader.open(argv[1]).ok()) return 2;
    RawPacket raw; OperationResult result;
    std::uint64_t seq = 0;
    bool syn = false, arp = false, dns = false, udp = false, ipv6 = false;
    while (reader.readNext(raw, result) == ReadStatus::Packet) {
        auto packet = parsePacket(raw, ++seq);
        const auto text = packetInterpretation(packet);
        if (seq == 2) {
            check(text.contains(QStringLiteral("ACK 未置位")) && text.contains(QStringLiteral("序列号（报文原始值）")), "SYN explains raw sequence and invalid acknowledgment");
            check(text.contains(QStringLiteral("TCP 载荷长度：0 字节")), "SYN payload excludes both IP and TCP headers");
            check(text.contains(QStringLiteral("未应用窗口缩放")), "window is explicitly unscaled");
            syn = true;
        }
        if (seq == 8) {
            check(text.contains(QStringLiteral("ARP 应答")) && text.contains(QStringLiteral("发送方 MAC")) && text.contains(QStringLiteral("目标 MAC（ARP 载荷）")), "ARP mapping and target are explained");
            arp = true;
        }
        if (seq == 9) {
            check(text.contains(QStringLiteral("DNS 查询")) && text.contains(QStringLiteral("查询名称")) && text.contains(QStringLiteral("首个问题")), "DNS uses decoded fields and states record parsing limit");
            dns = true;
        }
        if (seq == 1) {
            check(text.contains(QStringLiteral("UDP 声明载荷长度：")), "UDP includes payload length"); udp = true;
        }
        if (seq == 5) {
            check(text.contains(QStringLiteral("IPv6 基本首部长度：40 字节")) && text.contains("Hop Limit"), "IPv6 uses correct header and hop semantics"); ipv6 = true;
        }
    }
    check(result.ok() && syn && arp && dns && udp && ipv6, "all fixture scenarios were inspected");
    ParsedPacket packet;
    packet.record.status = ParseStatus::Complete;
    packet.record.originalLength = packet.record.capturedLength = 60;
    packet.fields = {{"IPv4", "", {{"Total length", "40", {}}, {"Header length", "20", {}},
        {"Fragment offset (bytes)", "0", {}}, {"Flags", "1", {{"MF", "1", {}}}}}},
        {"TCP", "", {{"Header length", "20", {}}}}};
    check(packetInterpretation(packet).contains(QStringLiteral("这是 IP 分片")) &&
          !packetInterpretation(packet).contains(QStringLiteral("TCP 载荷长度：")), "no complete TCP payload inference from fragmented IP");
    packet.fields[0].children.back().children[0].value = "0";
    packet.record.status = ParseStatus::Truncated;
    packet.record.capturedLength = 30;
    check(packetInterpretation(packet).contains(QStringLiteral("发生抓包截断")) &&
          !packetInterpretation(packet).contains(QStringLiteral("TCP 载荷长度：")), "no full payload inference on incomplete capture");
    packet.fields = {{"ICMP", "", {{"Type", "8", {}}, {"Code", "0", {}},
        {"Identifier", "19578", {}}, {"Sequence number", "12", {}}}}};
    check(packetInterpretation(packet).contains(QStringLiteral("回声请求")) && packetInterpretation(packet).contains("19578"), "ICMP echo includes identifier");
    packet.fields = {{"IPv6", "", {{"Payload length", "36", {}}}},
        {"IPv6 extension", "60", {{"Header length", "8", {}}}},
        {"TCP", "", {{"Header length", "20", {}}}}};
    packet.record.status = ParseStatus::Complete;
    check(packetInterpretation(packet).contains(QStringLiteral("TCP 载荷长度：8 字节")), "IPv6 TCP payload excludes extension header");
    packet.fields = {{"DNS", "", {{"Flags", "33283", {}}, {"Answers", "0", {}}, {"Question name", "<test>", {}}}}};
    const auto dnsText = packetInterpretation(packet);
    check(dnsText.contains(QStringLiteral("域名不存在")) && dnsText.contains(QStringLiteral("DNS TC 已置位")) && dnsText.contains("<test>"), "DNS flags explain NXDOMAIN and distinguish server truncation");
    packet = {};
    check(packetInterpretation(packet).contains(QStringLiteral("不支持的协议")) &&
          !packetInterpretation(packet).contains(QStringLiteral("TCP 载荷长度：")), "unsupported packets do not fabricate transport fields");
    return failures ? 1 : 0;
}
