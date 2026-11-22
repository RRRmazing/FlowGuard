#include "ui/packet_interpretation.h"
#include <QStringList>

namespace flowguard {
namespace {
const ProtocolField *find(const std::vector<ProtocolField> &fields, const char *name) {
    for (const auto &f : fields) if (f.name == name) return &f;
    return nullptr;
}
const ProtocolField *child(const ProtocolField *parent, const char *name) {
    return parent ? find(parent->children, name) : nullptr;
}
QString value(const ProtocolField *parent, const char *name) {
    const auto *f = child(parent, name);
    return f ? QString::fromStdString(f->value) : QString();
}
std::optional<qulonglong> number(const ProtocolField *parent, const char *name) {
    bool ok = false;
    const auto n = value(parent, name).toULongLong(&ok);
    return ok ? std::optional<qulonglong>(n) : std::nullopt;
}
void append(QStringList &lines, const QString &label, const ProtocolField *layer,
            const char *name, const QString &suffix = {}) {
    const auto v = value(layer, name);
    if (!v.isEmpty()) lines << label + QStringLiteral("：") + v + suffix;
}
QString endpoint(const std::string &ip, const std::optional<std::uint16_t> &port) {
    auto address = QString::fromStdString(ip);
    if (address.isEmpty()) return QStringLiteral("未解析");
    if (!port) return address;
    if (address.contains(':')) address = '[' + address + ']';
    return address + ':' + QString::number(*port);
}
QString dnsType(qulonglong type) {
    switch (type) {
    case 1: return "A（IPv4 地址）";
    case 28: return "AAAA（IPv6 地址）";
    case 5: return "CNAME（别名）";
    case 15: return "MX（邮件交换）";
    case 2: return "NS（名称服务器）";
    case 12: return "PTR（反向查询）";
    case 16: return "TXT（文本）";
    default: return QString::number(type);
    }
}
}

QString packetInterpretation(const ParsedPacket &packet) {
    const auto &r = packet.record;
    const auto *arp = find(packet.fields, "ARP");
    const auto *tcp = find(packet.fields, "TCP");
    const auto *udp = find(packet.fields, "UDP");
    const auto *icmp = find(packet.fields, "ICMP");
    if (!icmp) icmp = find(packet.fields, "ICMPv6");
    const auto *dns = find(packet.fields, "DNS");
    const auto *ip = find(packet.fields, "IPv4");
    const bool v6 = !ip && find(packet.fields, "IPv6");
    if (v6) ip = find(packet.fields, "IPv6");
    QStringList purpose, control, structure, network, quality;
    QString title = QStringLiteral("报文解读");
    if (arp) {
        const auto opcode = number(arp, "Opcode");
        title = opcode == 1 ? QStringLiteral("ARP 请求") : opcode == 2 ? QStringLiteral("ARP 应答") : QStringLiteral("ARP 报文");
        if (opcode == 1) purpose << QStringLiteral("询问哪个接口拥有目标 IP，以获取该 IP 对应的 MAC 地址。");
        if (opcode == 2) purpose << QStringLiteral("发送方向接收方声明自己的 IP 与 MAC 对应关系。");
        append(control, QStringLiteral("发送方 IP"), arp, "Sender IP");
        append(control, QStringLiteral("发送方 MAC"), arp, "Sender MAC");
        append(control, QStringLiteral("目标 IP"), arp, "Target IP");
        append(control, QStringLiteral("目标 MAC（ARP 载荷）"), arp, "Target MAC");
        append(control, QStringLiteral("操作码"), arp, "Opcode");
        append(control, QStringLiteral("硬件类型（1 为 Ethernet）"), arp, "Hardware type");
        append(control, QStringLiteral("协议类型（2048 为 IPv4）"), arp, "Protocol type");
        append(structure, QStringLiteral("硬件地址长度"), arp, "Hardware address length", QStringLiteral(" 字节"));
        append(structure, QStringLiteral("协议地址长度"), arp, "Protocol address length", QStringLiteral(" 字节"));
        quality << QStringLiteral("单条 ARP 报文不能证明地址映射发生变化或存在欺骗，需结合其他报文与预警结果判断。");
    } else {
        if (!r.sourceIp.empty() || !r.destinationIp.empty())
            control << QStringLiteral("通信方向：%1 → %2").arg(endpoint(r.sourceIp, r.sourcePort), endpoint(r.destinationIp, r.destinationPort));
        if (tcp) {
            title = QStringLiteral("TCP 报文");
            if (r.tcpFlags) {
                const auto flags = *r.tcpFlags;
                QStringList active;
                const char *names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
                for (unsigned i = 0; i < 8; ++i) if (flags & (1u << i)) active << names[i];
                control << QStringLiteral("标志位：") + (active.isEmpty() ? QStringLiteral("均未置位") : active.join("、"));
                if (flags & 4) purpose << QStringLiteral("RST 已置位：表示复位或拒绝连接；单包不能确定具体原因。");
                if (flags & 2) purpose << ((flags & 16) ? QStringLiteral("SYN、ACK 已置位：通常是对连接请求的回应，同时同步本端序列号。")
                                                          : QStringLiteral("SYN 已置位、ACK 未置位：通常用于发起 TCP 连接请求。"));
                if (flags & 1) purpose << QStringLiteral("FIN 已置位：发送方表示该方向不再发送数据，完整关闭过程需结合后续报文。");
                if (flags & 8) purpose << QStringLiteral("PSH 已置位：请求接收端及时将数据交付应用。");
                if (flags & 16) purpose << QStringLiteral("ACK 已置位：确认号有效，表示期望收到的下一个序列号。");
                append(control, QStringLiteral("序列号（报文原始值）"), tcp, "Sequence number");
                if (flags & 16) append(control, QStringLiteral("确认号（报文原始值）"), tcp, "Acknowledgment number");
                else control << QStringLiteral("ACK 未置位，确认号不作为有效确认信息。");
                if (flags & 32) append(control, QStringLiteral("紧急指针（URG 已置位）"), tcp, "Urgent pointer");
            }
            append(control, QStringLiteral("接收窗口原始值（未应用窗口缩放）"), tcp, "Window size");
            append(structure, QStringLiteral("TCP 首部长度"), tcp, "Header length", QStringLiteral(" 字节"));
            append(control, QStringLiteral("TCP 选项（原始十六进制）"), tcp, "Options (raw)");
            append(control, QStringLiteral("TCP 校验和字段"), tcp, "Checksum");
            quality << QStringLiteral("单条 TCP 报文不用于断定握手成功、重传或 SYN 泛洪。");
        } else if (udp) {
            title = QStringLiteral("UDP 数据报");
            purpose << QStringLiteral("通过源、目的端口传送数据；UDP 本身不执行连接握手，也不提供送达确认。");
            append(structure, QStringLiteral("UDP 总长度（包含 8 字节首部）"), udp, "Length", QStringLiteral(" 字节"));
            const auto length = number(udp, "Length");
            if (length && *length >= 8) structure << QStringLiteral("UDP 声明载荷长度：%1 字节").arg(*length - 8);
            append(control, QStringLiteral("UDP 校验和字段"), udp, "Checksum");
            if (value(udp, "Checksum") == "0x0000")
                quality << (v6 ? QStringLiteral("IPv6 UDP 校验和为零：通常不符合要求；当前未进行完整校验验证。")
                               : QStringLiteral("IPv4 UDP 校验和为零，表示发送方未使用 UDP 校验和。"));
        } else if (icmp) {
            title = v6 ? QStringLiteral("ICMPv6 报文") : QStringLiteral("ICMP 报文");
            const auto type = number(icmp, "Type"), code = number(icmp, "Code");
            if (type && code == 0 && *type == (v6 ? 128u : 8u)) purpose << QStringLiteral("回声请求：请求目标返回回声应答，常用于测试网络可达性。");
            else if (type && code == 0 && *type == (v6 ? 129u : 0u)) purpose << QStringLiteral("回声应答：对回声请求作出回应；请求与应答可通过标识符和序号辅助配对。");
            else if (type == (v6 ? 1u : 3u)) purpose << QStringLiteral("目的不可达通知：具体原因由代码字段表示；需结合被引用的原始报文判断。");
            else if (type == (v6 ? 3u : 11u)) purpose << QStringLiteral("超时通知：可能与转发跳数耗尽或分片重组超时有关，具体由代码区分。");
            else purpose << QStringLiteral("网络控制或差错通知，具体语义由类型与代码共同确定。");
            append(control, QStringLiteral("类型（Type）"), icmp, "Type");
            append(control, QStringLiteral("代码（Code）"), icmp, "Code");
            if (code && type == (v6 ? 1u : 3u)) {
                if (*code == (v6 ? 4u : 3u)) control << QStringLiteral("代码含义：目的端口不可达。");
                else if (*code == (v6 ? 0u : 0u)) control << QStringLiteral("代码含义：目标网络不可达／无路由。");
            }
            if (code && type == (v6 ? 3u : 11u) && *code <= 1)
                control << (*code == 0 ? QStringLiteral("代码含义：转发跳数耗尽。") : QStringLiteral("代码含义：分片重组超时。"));
            append(control, QStringLiteral("标识符（用于辅助配对）"), icmp, "Identifier");
            append(control, QStringLiteral("序号"), icmp, "Sequence number");
            append(control, QStringLiteral("校验和字段"), icmp, "Checksum");
        } else {
            title = ip ? (v6 ? QStringLiteral("IPv6 报文") : QStringLiteral("IPv4 报文")) : QStringLiteral("链路层报文");
            purpose << QStringLiteral("展示当前安全解析出的字段；未解析出的上层内容不作推断。");
        }
    }
    if (dns) {
        title = QStringLiteral("DNS 报文（%1）").arg(tcp ? "TCP" : "UDP");
        bool ok = false;
        const auto flags = value(dns, "Flags").toUInt(&ok);
        if (ok) {
            purpose.prepend(flags & 0x8000 ? QStringLiteral("DNS 响应：返回名称查询的处理结果。") : QStringLiteral("DNS 查询：请求解析名称或查找指定类型的记录。"));
            control << QStringLiteral("DNS 操作码：%1；响应码：%2").arg((flags >> 11) & 15).arg(flags & 15);
            if (flags & 0x8000) {
                const QStringList responses{QStringLiteral("无错误"), QStringLiteral("格式错误"), QStringLiteral("服务器失败"), QStringLiteral("域名不存在"), QStringLiteral("不支持的操作"), QStringLiteral("拒绝处理")};
                if ((flags & 15) < unsigned(responses.size())) control << QStringLiteral("DNS 响应状态：") + responses[flags & 15];
            }
            control << QStringLiteral("DNS 标志：AA=%1，TC=%2，RD=%3，RA=%4")
                .arg((flags >> 10) & 1).arg((flags >> 9) & 1).arg((flags >> 8) & 1).arg((flags >> 7) & 1);
            if (flags & 0x200) quality << QStringLiteral("DNS TC 已置位：发送方表示响应内容被截短；这与抓包截断是不同情况。");
        }
        append(control, QStringLiteral("DNS 事务 ID（辅助匹配查询与响应）"), dns, "Transaction ID");
        append(control, QStringLiteral("查询名称"), dns, "Question name");
        const auto type = number(dns, "Question type");
        if (type) control << QStringLiteral("查询类型：") + dnsType(*type);
        append(control, QStringLiteral("查询类别（1 为 IN）"), dns, "Question class");
        append(control, QStringLiteral("问题数"), dns, "Questions");
        append(control, QStringLiteral("回答记录数"), dns, "Answers");
        append(control, QStringLiteral("权威记录数"), dns, "Authority records");
        append(control, QStringLiteral("附加记录数"), dns, "Additional records");
        quality << QStringLiteral("当前只解析 DNS 首部和首个问题；回答记录数不表示已解析出具体回答内容。");
    }
    bool fragmented = false;
    if (ip) {
        append(network, v6 ? QStringLiteral("Hop Limit（剩余跳数上限）") : QStringLiteral("TTL（剩余生存时间／跳数）"), ip, v6 ? "Hop limit" : "TTL");
        append(network, QStringLiteral("DSCP（服务类别标记）"), ip, "DSCP");
        append(network, QStringLiteral("ECN（拥塞通知标记）"), ip, "ECN");
        if (!v6) {
            const auto offset = number(ip, "Fragment offset (bytes)");
            const auto *flags = child(ip, "Flags");
            fragmented = offset.value_or(0) != 0 || number(flags, "MF").value_or(0) != 0;
            append(network, QStringLiteral("标识（Identification）"), ip, "Identification");
            append(network, QStringLiteral("禁止分片 DF"), flags, "DF");
            append(network, QStringLiteral("后续分片 MF"), flags, "MF");
            append(network, QStringLiteral("分片偏移"), ip, "Fragment offset (bytes)", QStringLiteral(" 字节"));
            append(network, QStringLiteral("IPv4 首部校验和字段"), ip, "Header checksum");
            append(structure, QStringLiteral("IPv4 首部长度"), ip, "Header length", QStringLiteral(" 字节"));
            append(structure, QStringLiteral("IPv4 总长度"), ip, "Total length", QStringLiteral(" 字节"));
        } else {
            append(network, QStringLiteral("流标签"), ip, "Flow label");
            append(network, QStringLiteral("基本首部 Next Header"), ip, "Next header");
            structure << QStringLiteral("IPv6 基本首部长度：40 字节");
            append(structure, QStringLiteral("IPv6 声明载荷长度（包括扩展首部）"), ip, "Payload length", QStringLiteral(" 字节"));
            for (const auto &f : packet.fields) if (f.name == "IPv6 extension") {
                append(network, QStringLiteral("扩展首部的 Next Header"), &f, "Next header");
                network << QStringLiteral("IPv6 扩展首部编号：") + QString::fromStdString(f.value);
                append(network, QStringLiteral("扩展首部长度"), &f, "Header length", QStringLiteral(" 字节"));
                if (f.value == "44") {
                    fragmented = number(&f, "Fragment offset").value_or(0) != 0 || number(&f, "More fragments").value_or(0) != 0;
                    append(network, QStringLiteral("分片偏移（8 字节单位）"), &f, "Fragment offset");
                    append(network, QStringLiteral("后续分片"), &f, "More fragments");
                }
            }
        }
        if (fragmented) quality << QStringLiteral("这是 IP 分片；当前不进行重组，不将单片长度解释为完整上层报文长度。");
        // Only derive TCP payload size when the complete, unfragmented header chain is available.
        if (tcp && !fragmented && r.status == ParseStatus::Complete) {
            auto total = number(ip, v6 ? "Payload length" : "Total length");
            auto header = v6 ? std::optional<qulonglong>(0) : number(ip, "Header length");
            const auto tcpHeader = number(tcp, "Header length");
            if (header && v6) for (const auto &f : packet.fields) if (f.name == "IPv6 extension") {
                const auto size = number(&f, "Header length");
                if (size) *header += *size; else header.reset();
                if (!header) break;
            }
            if (total && header && tcpHeader && *total >= *header + *tcpHeader)
                structure << QStringLiteral("TCP 载荷长度：%1 字节%2").arg(*total - *header - *tcpHeader)
                    .arg(*total == *header + *tcpHeader ? QStringLiteral("（本包未携带应用数据）") : QString());
        }
    }
    if (!r.sourceMac.empty()) network << QStringLiteral("以太网源 MAC：") + QString::fromStdString(r.sourceMac);
    if (!r.destinationMac.empty()) network << QStringLiteral("以太网目的 MAC：") + QString::fromStdString(r.destinationMac) +
        (r.destinationMac == "ff:ff:ff:ff:ff:ff" ? QStringLiteral("（广播）") : QString());
    for (const auto &f : packet.fields) if (f.name == "VLAN") {
        append(network, QStringLiteral("VLAN ID"), &f, "ID");
        append(network, QStringLiteral("VLAN 优先级"), &f, "Priority");
    }
    quality.prepend(QStringLiteral("原始长度：%1 字节；捕获长度：%2 字节。").arg(r.originalLength).arg(r.capturedLength));
    if (r.capturedLength < r.originalLength) quality << QStringLiteral("发生抓包截断，缺失字节不可用于解析或推断。");
    else if (r.capturedLength == r.originalLength) quality << QStringLiteral("捕获长度与原始长度一致，未发生抓包截断。");
    switch (r.status) {
    case ParseStatus::Complete: quality << QStringLiteral("解析状态：完整（在当前解析器支持范围内）。"); break;
    case ParseStatus::Truncated: quality << QStringLiteral("解析状态：数据不足，声明长度或首部所需数据未完整捕获。"); break;
    case ParseStatus::Malformed: quality << QStringLiteral("解析状态：报文格式异常；以下解读仅基于已解析字段。"); break;
    case ParseStatus::Unsupported: quality << QStringLiteral("解析状态：存在不支持的协议或链路类型。"); break;
    }
    if (!r.diagnostic.empty()) quality << QStringLiteral("解析提示：") + QString::fromStdString(r.diagnostic);
    quality << QStringLiteral("校验和仅展示报文字段值，未验证正确性；解析完整不代表流量正常。");
    QStringList sections{title};
    const auto section = [&](const QString &heading, const QStringList &lines) {
        if (!lines.isEmpty()) sections << heading + '\n' + lines.join('\n');
    };
    section(QStringLiteral("报文用途"), purpose);
    section(QStringLiteral("关键字段及含义"), control);
    section(QStringLiteral("报文结构"), structure);
    section(QStringLiteral("网络与链路信息"), network);
    section(QStringLiteral("解析情况"), quality);
    return sections.join("\n\n");
}
}
