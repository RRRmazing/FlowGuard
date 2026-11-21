// Primary author: Xie Fuxiang. AI-assisted tests, pending user review.
#include "monitoring/run_recorder.h"
#include "ui/packet_model.h"
#include <QApplication>
#include <QFile>
#include <QJsonDocument>
#include <QTemporaryDir>
#include <QThread>
#include <iostream>

static int failures = 0;
static void check(bool good, const char *message)
{
    if (!good)
    {
        std::cerr << message << '\n';
        ++failures;
    }
}
int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    using namespace flowguard;
    PacketRecord r;
    r.network = NetworkProtocol::IPv6;
    r.transport = TransportProtocol::Udp;
    r.sourceIp = "2001:db8::1";
    r.destinationIp = "2001:db8::2";
    r.sourcePort = 0;
    r.destinationPort = 53;
    DisplayFilter f;
    f.ipAddress = "2001:0db8:0:0:0:0:0:1";
    f.port = 53;
    f.protocol = ProtocolFilter::Udp;
    check(matchesDisplayFilter(r, f), "normalized IPv6 and destination port");
    f.port = 0;
    check(matchesDisplayFilter(r, f), "zero source port valid");
    f.protocol = ProtocolFilter::Dns;
    check(!matchesDisplayFilter(r, f), "port53 does not imply DNS");
    r.isDns = true;
    check(matchesDisplayFilter(r, f), "verified DNS");
    f.ipAddress = "2001:db8::";
    check(!matchesDisplayFilter(r, f), "no substring matching");
    f.ipAddress = "invalid";
    check(!matchesDisplayFilter(r, f), "invalid IP rejected");
    PacketModel model;
    std::vector<ParsedPacket> packets;
    for (int i = 1; i <= 2500; ++i)
    {
        ParsedPacket p;
        p.record = r;
        p.record.sequence = i;
        packets.push_back(p);
    }
    model.append(std::move(packets));
    check(model.retained() == 2000 && model.rowCount() == 2000, "bounded model");
    check(model.evicted()==500,"list evictions separate from backend display drops");
    check(model.packet(0)->record.sequence == 501, "oldest removed");
    DisplayFilter filter;
    filter.protocol = ProtocolFilter::Tcp;
    model.filter(filter);
    check(model.rowCount() == 0 && model.retained() == 2000, "filter preserves history");
    model.filter({});
    check(model.rowCount() == 2000, "reset restores recent history");
    model.clear();
    check(!model.packet(0) && !model.rowCount(), "new session clears details");
    const auto first = sampleResources();
    check(!first.cpuPercent, "first CPU unknown");
    QThread::msleep(30);
    const auto second = sampleResources();
    check(second.cpuPercent && *second.cpuPercent >= 0 && *second.cpuPercent <= 100, "CPU bounded");
    check(second.workingSetBytes && *second.workingSetBytes > 0, "real working set");
    QTemporaryDir temp;
    RunRecorder log;
    check(log.open(temp.path()), "log opened");
    ProcessingSnapshot s;
    s.sessionId = 1;
    s.statistics.totalPackets = 18;
    s.displayDroppedPackets = 7;
    log.event("test_event");
    log.sample(s, first, 12);
    log.finish(s);
    QFile csv(log.directory() + "/resources.csv");
    check(csv.open(QIODevice::ReadOnly), "CSV exists");
    const auto data = csv.readAll();
    check(data.contains("driver_dropped") && data.count('\n') == 2, "CSV header and sample");
    check(data.contains(",18,"), "packet count recorded");
    QFile result(log.directory() + "/result.json");
    check(result.open(QIODevice::ReadOnly), "result exists");
    const auto json = QJsonDocument::fromJson(result.readAll()).object();
    check(json["normal_exit"].toBool() && json["total_packets"].toString() == "18", "normal exit metadata");
    QFile blocker(temp.path() + "/block");
    check(blocker.open(QIODevice::WriteOnly), "make blocked destination");
    blocker.close();
    RunRecorder bad;
    check(!bad.open(blocker.fileName()) && !bad.error().isEmpty(), "log creation failure visible");
    std::cout << "STAGE3_SUPPORT " << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
