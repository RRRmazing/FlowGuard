// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "ui/chart_panel.h"
#include <QCursor>
#include <QGridLayout>
#include <QToolTip>
#include <QtCharts/QBarCategoryAxis>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QLineSeries>
#include <QtCharts/QPieSeries>
#include <QtCharts/QValueAxis>
#include <algorithm>

namespace flowguard
{
static void theme(QChart *c)
{
    c->setAnimationOptions(QChart::NoAnimation);
    c->setBackgroundRoundness(6);
    c->setBackgroundBrush(QColor("#ffffff"));
    c->setMargins(QMargins(8, 8, 8, 8));
    c->setTitleFont(QFont("Microsoft YaHei UI", 10, QFont::DemiBold));
}
QChart *lineChart(const QString &title, const QList<QPointF> &points, const QString &x, const QString &y,
                  const QColor &color, bool percent)
{
    auto *c = new QChart;
    c->setTitle(title);
    theme(c);
    auto *series = new QLineSeries;
    series->replace(points);
    series->setColor(color);
    c->addSeries(series);
    c->createDefaultAxes();
    c->legend()->hide();
    if (!c->axes(Qt::Horizontal).isEmpty())
        c->axes(Qt::Horizontal).front()->setTitleText(x);
    if (!c->axes(Qt::Vertical).isEmpty())
    {
        auto *axis = qobject_cast<QValueAxis *>(c->axes(Qt::Vertical).front());
        axis->setTitleText(y);
        double maximum = 0;
        for (const auto &p : points)
            maximum = std::max(maximum, p.y());
        axis->setRange(0, percent ? 100 : std::max(1., maximum * 1.15));
    }
    QObject::connect(series, &QLineSeries::hovered, series, [x, y](const QPointF &p, bool on) {
        if (on)
            QToolTip::showText(QCursor::pos(), QString("%1: %2\n%3: %4").arg(x).arg(p.x()).arg(y).arg(p.y()));
        else
            QToolTip::hideText();
    });
    return c;
}
static QChart *bars(const QString &title, const QStringList &labels, const QList<qreal> &values)
{
    auto *c = new QChart;
    c->setTitle(title);
    theme(c);
    auto *set = new QBarSet(QStringLiteral("包数"));
    for (auto v : values)
        *set << v;
    set->setColor(QColor("#10a69c"));
    auto *series = new QBarSeries;
    series->append(set);
    series->setLabelsVisible(true);
    c->addSeries(series);
    auto *x = new QBarCategoryAxis;
    x->append(labels);
    c->addAxis(x, Qt::AlignBottom);
    series->attachAxis(x);
    auto *y = new QValueAxis;
    double max = 1;
    for (auto v : values)
        max = std::max(max, double(v));
    y->setRange(0, max * 1.2);
    y->setTitleText(QStringLiteral("包数"));
    c->addAxis(y, Qt::AlignLeft);
    series->attachAxis(y);
    c->legend()->hide();
    return c;
}
ChartPanel::ChartPanel(QWidget *parent) : QWidget(parent)
{
    auto *l = new QGridLayout(this);
    for (int i = 0; i < 8; ++i)
    {
        views_[i] = new QChartView;
        views_[i]->setMinimumHeight(245);
        views_[i]->setRenderHint(QPainter::Antialiasing);
        l->addWidget(views_[i], i / 2, i % 2);
    }
}
void ChartPanel::refresh(const ProcessingSnapshot &s)
{
    auto set = [this](int i, QChart *chart) {
        auto *old = views_[i]->chart();
        views_[i]->setChart(chart);
        delete old;
    };
    QList<QPointF> packets, bytes, dns, lengths;
    double start =
        s.history.empty() ? 0 : std::chrono::duration<double>(s.history.front().timestamp.time_since_epoch()).count();
    for (const auto &p : s.history)
    {
        const double x = std::chrono::duration<double>(p.timestamp.time_since_epoch()).count() - start;
        packets.append({x, p.rate.packetsPerSecond});
        bytes.append({x, p.rate.bytesPerSecond / 1024});
        dns.append({x, p.rate.dnsFraction * 100});
    }
    for (const auto &p : s.statistics.lengthFrequency)
        lengths.append({double(p.first), double(p.second)});
    const QString time = QStringLiteral("距窗口起点秒（捕获时间）");
    set(0, lineChart(QStringLiteral("包速率"), packets, time, "pkt/s", QColor("#0b9c94")));
    set(1, lineChart(QStringLiteral("字节速率"), bytes, time, "KiB/s", QColor("#4285ed")));
    set(2, lineChart(QStringLiteral("长度频次（65536 表示 >65535）"), lengths, QStringLiteral("原始长度 B"),
                     QStringLiteral("包数"), QColor("#0b9c94")));
    const auto &g = s.statistics.lengthGroups;
    set(3, bars(QStringLiteral("长度三区间"), {QStringLiteral("≤46 B"), "47–1500 B", ">1500 B"},
                {qreal(g[0]), qreal(g[1]), qreal(g[2])}));
    auto count = [](const auto &m, auto key) {
        auto i = m.find(key);
        return i == m.end() ? 0. : double(i->second);
    };
    double ip4 = count(s.statistics.networkCounts, NetworkProtocol::IPv4),
           ip6 = count(s.statistics.networkCounts, NetworkProtocol::IPv6),
           arp = count(s.statistics.networkCounts, NetworkProtocol::Arp),
           other = arp + count(s.statistics.networkCounts, NetworkProtocol::Other);
    set(4, bars(QStringLiteral("网络分类"), {"IPv4", "IPv6", QStringLiteral("其他")}, {ip4, ip6, other}));
    auto *pie = new QChart;
    theme(pie);
    pie->setTitle(s.statistics.totalPackets ? QStringLiteral("网络占比") : QStringLiteral("网络占比 · 暂无数据"));
    auto *series = new QPieSeries;
    series->setHoleSize(.55);
    if (s.statistics.totalPackets)
    {
        for (const auto &entry :
             std::array<std::pair<QString, double>, 3>{{{"IPv4", ip4}, {"IPv6", ip6}, {QStringLiteral("其他"), other}}})
        {
            auto *slice = series->append(entry.first, entry.second);
            slice->setLabel(QString("%1 %2%")
                                .arg(entry.first)
                                .arg(entry.second / double(s.statistics.totalPackets) * 100, 0, 'f', 1));
        }
        series->setLabelsVisible();
    }
    pie->addSeries(series);
    set(5, pie);
    set(6, bars(QStringLiteral("TCP / UDP / ARP（不涵盖全部包）"), {"TCP", "UDP", "ARP"},
                {count(s.statistics.transportCounts, TransportProtocol::Tcp),
                 count(s.statistics.transportCounts, TransportProtocol::Udp), arp}));
    set(7, lineChart(QStringLiteral("DNS 区间占比"), dns, time, "%", QColor("#8657ce"), true));
}
} // namespace flowguard
