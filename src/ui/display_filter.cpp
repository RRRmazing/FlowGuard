// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "core/module_contracts.h"
#include <QHostAddress>
#include <QString>

namespace flowguard
{
bool matchesDisplayFilter(const PacketRecord &r, const DisplayFilter &f)
{
    bool protocol = false;
    switch (f.protocol)
    {
    case ProtocolFilter::All:
        protocol = true;
        break;
    case ProtocolFilter::IPv4:
        protocol = r.network == NetworkProtocol::IPv4;
        break;
    case ProtocolFilter::IPv6:
        protocol = r.network == NetworkProtocol::IPv6;
        break;
    case ProtocolFilter::Arp:
        protocol = r.network == NetworkProtocol::Arp;
        break;
    case ProtocolFilter::Tcp:
        protocol = r.transport == TransportProtocol::Tcp;
        break;
    case ProtocolFilter::Udp:
        protocol = r.transport == TransportProtocol::Udp;
        break;
    case ProtocolFilter::Dns:
        protocol = r.isDns;
        break;
    case ProtocolFilter::Other:
        protocol = r.network == NetworkProtocol::Other;
        break;
    }
    if (!protocol)
        return false;
    if (f.ipAddress)
    {
        const QHostAddress ip(QString::fromStdString(*f.ipAddress));
        if (ip.isNull() || (ip != QHostAddress(QString::fromStdString(r.sourceIp)) &&
                            ip != QHostAddress(QString::fromStdString(r.destinationIp))))
            return false;
    }
    return !f.port || r.sourcePort == f.port || r.destinationPort == f.port;
}
} // namespace flowguard
