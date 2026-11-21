// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "ui/packet_model.h"
#include <QColor>
#include <QDateTime>

namespace flowguard
{
QString protocolName(const PacketRecord &r)
{
    if (r.isDns)
        return "DNS";
    if (r.network == NetworkProtocol::Arp)
        return "ARP";
    switch (r.transport)
    {
    case TransportProtocol::Tcp:
        return "TCP";
    case TransportProtocol::Udp:
        return "UDP";
    case TransportProtocol::Icmp:
        return "ICMP";
    case TransportProtocol::Icmpv6:
        return "ICMPv6";
    default:
        break;
    }
    if (r.network == NetworkProtocol::IPv4)
        return "IPv4";
    if (r.network == NetworkProtocol::IPv6)
        return "IPv6";
    return "Other";
}
int PacketModel::rowCount(const QModelIndex &p) const
{
    return p.isValid() ? 0 : int(visible_.size());
}
int PacketModel::columnCount(const QModelIndex &p) const
{
    return p.isValid() ? 0 : 7;
}
const ParsedPacket *PacketModel::packet(int row) const
{
    return row >= 0 && row < int(visible_.size()) ? &history_[visible_[std::size_t(row)]] : nullptr;
}
QVariant PacketModel::data(const QModelIndex &i, int role) const
{
    const auto *p = packet(i.row());
    if (!i.isValid() || !p)
        return {};
    const auto &r = p->record;
    if (role == Qt::BackgroundRole && r.status != ParseStatus::Complete)
        return QColor("#fff3df");
    if (role == Qt::ForegroundRole && i.column() == 4)
        return QColor(r.isDns ? "#7754c9" : "#087f83");
    if (role == Qt::ToolTipRole)
        return QString::fromStdString(r.summary + "\n" + r.diagnostic);
    if (role != Qt::DisplayRole)
        return {};
    switch (i.column())
    {
    case 0:
        return QVariant::fromValue<qulonglong>(r.sequence);
    case 1:
        return QDateTime::fromMSecsSinceEpoch(
                   std::chrono::duration_cast<std::chrono::milliseconds>(r.timestamp.time_since_epoch()).count())
            .toString("HH:mm:ss.zzz");
    case 2:
        return QString::fromStdString(r.sourceIp.empty() ? r.sourceMac : r.sourceIp);
    case 3:
        return QString::fromStdString(r.destinationIp.empty() ? r.destinationMac : r.destinationIp);
    case 4:
        return protocolName(r);
    case 5:
        return r.originalLength;
    case 6:
        return QString::fromStdString(r.summary);
    default:
        return {};
    }
}
QVariant PacketModel::headerData(int section, Qt::Orientation o, int role) const
{
    static const QStringList names{QStringLiteral("序号"),     QStringLiteral("时间"), QStringLiteral("源地址"),
                                   QStringLiteral("目的地址"), QStringLiteral("协议"), QStringLiteral("长度(B)"),
                                   QStringLiteral("摘要")};
    return o == Qt::Horizontal && role == Qt::DisplayRole && section >= 0 && section < names.size()
               ? QVariant(names[section])
               : QVariant();
}
void PacketModel::rebuild()
{
    visible_.clear();
    for (std::size_t i = 0; i < history_.size(); ++i)
        if (matchesDisplayFilter(history_[i].record, filter_))
            visible_.push_back(i);
}
void PacketModel::append(std::vector<ParsedPacket> packets)
{
    if (packets.empty())
        return;
    beginResetModel();
    for (auto &p : packets)
    {
        history_.push_back(std::move(p));
        if (history_.size() > 2000)
        {
            history_.pop_front();
            ++evicted_;
        }
    }
    rebuild();
    endResetModel();
}
void PacketModel::clear()
{
    beginResetModel();
    history_.clear();
    evicted_ = 0;
    visible_.clear();
    endResetModel();
}
void PacketModel::filter(DisplayFilter f)
{
    beginResetModel();
    filter_ = std::move(f);
    rebuild();
    endResetModel();
}
} // namespace flowguard
