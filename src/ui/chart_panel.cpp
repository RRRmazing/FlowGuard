// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "ui/chart_panel.h"
#include <QCursor>
#include <QDateTime>
#include <QGridLayout>
#include <QToolTip>
#include <QtCharts/QBarCategoryAxis>
#include <QtCharts/QBarSeries>
#include <QtCharts/QBarSet>
#include <QtCharts/QLineSeries>
#include <QtCharts/QPieSeries>
#include <QtCharts/QValueAxis>
#include <algorithm>
#include <cmath>

namespace flowguard
{
static void integerAxis(QValueAxis *axis, double minimum, double maximum)
{
    const double step = std::max(1., std::ceil((maximum - minimum) / 4.));
    const double low = std::floor(minimum / step) * step;
    const double high = std::max(low + step, std::ceil(maximum / step) * step);
    axis->setRange(low, high);
    axis->setTickCount(int(std::round((high - low) / step)) + 1);
    axis->setLabelFormat("%.0f");
}
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
    c->setTitle(points.isEmpty() ? title + QStringLiteral(" · 暂无数据") : title);
    theme(c);
    auto *series = new QLineSeries;
    series->replace(points);
    series->setPointsVisible(!points.isEmpty() && points.size() <= 100);
    series->setColor(color);
    c->addSeries(series);
    c->createDefaultAxes();
    c->legend()->hide();
    if (!c->axes(Qt::Horizontal).isEmpty())
    {
        c->axes(Qt::Horizontal).front()->setTitleText(x);
        if (points.size() == 1)
            qobject_cast<QValueAxis *>(c->axes(Qt::Horizontal).front())
                ->setRange(std::max(0., points.front().x() - 1), points.front().x() + 1);
    }
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
    integerAxis(y, 0, max * 1.2);
    y->setTitleText(QStringLiteral("包数"));
    c->addAxis(y, Qt::AlignLeft);
    series->attachAxis(y);
    c->legend()->hide();
    QObject::connect(set, &QBarSet::hovered, set, [labels, values](bool on, int index) {
        if (on && index >= 0 && index < labels.size())
            QToolTip::showText(QCursor::pos(), QString("%1：%2 包").arg(labels[index]).arg(values[index], 0, 'f', 0));
        else
            QToolTip::hideText();
    });
    if (std::all_of(values.begin(), values.end(), [](qreal value) { return value == 0; }))
        c->setTitle(title + QStringLiteral(" · 各分类均为 0"));
    return c;
}
ChartPanel::ChartPanel(QWidget *parent) : QWidget(parent)
{
    auto *l = new QGridLayout(this);
    scope_ = new QLabel;
    scope_->setObjectName("statisticsScope");
    scope_->setTextFormat(Qt::PlainText);
    scope_->setWordWrap(true);
    scope_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    l->addWidget(scope_, 0, 0, 1, 2);
    const std::array<int, 8> order{2, 3, 4, 5, 6, 7, 0, 1};
    for (int i = 0; i < 8; ++i)
    {
        views_[i] = new QChartView;
        views_[i]->setMinimumHeight(245);
        views_[i]->setRenderHint(QPainter::Antialiasing);
        views_[i]->setObjectName(QString("statisticsChart%1").arg(i));
        const int position = int(std::find(order.begin(), order.end(), i) - order.begin());
        l->addWidget(views_[i], position / 2 + 1, position % 2);
    }
}
void ChartPanel::refresh(const ProcessingSnapshot &s, const QString &source)
{
    QString window = QStringLiteral("暂无时间样本");
    if (!s.history.empty())
    {
        auto date = [](const auto &timestamp) {
            return QDateTime::fromMSecsSinceEpoch(
                       std::chrono::duration_cast<std::chrono::milliseconds>(timestamp.time_since_epoch()).count())
                .toString("yyyy-MM-dd HH:mm:ss");
        };
        window = date(s.history.front().timestamp) + QStringLiteral(" 至 ") + date(s.history.back().timestamp);
    }
    scope_->setText(
        QStringLiteral("统计分析\n%1\n累计统计：本次会话 %2 包；工作台显示筛选不影响统计，采集端 BPF 会影响输入。\n"
                       "近期曲线：%3（本地时间）；最多保留 3600 个时间点，并非全天曲线。")
            .arg(source.isEmpty() ? QStringLiteral("尚未选择数据源") : source)
            .arg(s.statistics.totalPackets)
            .arg(window));
    scope_->setToolTip(
        QStringLiteral("长度和协议分类图使用本次会话累计数据；速率和 DNS 曲线使用近期时间窗口。"
                       "离线曲线按 PCAP 捕获时间每秒分桶，不是文件导入速度。其他网络类型包含 ARP 和未能分类的报文。"));
    if (s.lateHistoryPackets)
        scope_->setText(
            scope_->text() +
            QStringLiteral("\n有 %1 包因时间戳过旧未进入近期曲线，仍计入累计统计。").arg(s.lateHistoryPackets));
    auto set = [this, &s](int i, QChart *chart) {
        if (!s.statistics.totalPackets)
            chart->setTitle(chart->title().replace(QStringLiteral("各分类均为 0"), QStringLiteral("暂无数据")));
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
    std::optional<std::uint32_t> previousLength;
    for (const auto &p : s.statistics.lengthFrequency)
    {
        if (previousLength && p.first > *previousLength + 1)
        {
            lengths.append({double(*previousLength + 1), 0});
            if (p.first > *previousLength + 2)
                lengths.append({double(p.first - 1), 0});
        }
        lengths.append({double(p.first), double(p.second)});
        previousLength = p.first;
    }
    const QString time = QStringLiteral("距窗口起点秒（捕获时间）");
    set(0, lineChart(QStringLiteral("包速率"), packets, time, "pkt/s", QColor("#0b9c94")));
    set(1, lineChart(QStringLiteral("字节速率"), bytes, time, "KiB/s", QColor("#4285ed")));
    set(2, lineChart(QStringLiteral("长度频次（65536 表示 >65535）"), lengths, QStringLiteral("原始长度 B"),
                     QStringLiteral("包数"), QColor("#0b9c94")));
    if (!lengths.isEmpty())
    {
        integerAxis(qobject_cast<QValueAxis *>(views_[2]->chart()->axes(Qt::Horizontal).front()),
                    std::max(0., lengths.front().x() - 1), lengths.back().x() + 1);
        double maximum = 1;
        for (const auto &p : lengths)
            maximum = std::max(maximum, p.y());
        integerAxis(qobject_cast<QValueAxis *>(views_[2]->chart()->axes(Qt::Vertical).front()), 0, maximum * 1.15);
    }
    views_[2]->setToolTip(
        QStringLiteral("横轴为整数长度，纵轴为包数；未出现的中间长度频次为 0。"
                       "超过 65535 B 的长度合并为一个桶，标在 65536；不是精确长度 65536 的单独频次。"));
    const auto &g = s.statistics.lengthGroups;
    set(3, bars(QStringLiteral("长度三区间 · 会话累计"), {QStringLiteral("≤46 B"), "47–1500 B", ">1500 B"},
                {qreal(g[0]), qreal(g[1]), qreal(g[2])}));
    auto count = [](const auto &m, auto key) {
        auto i = m.find(key);
        return i == m.end() ? 0. : double(i->second);
    };
    double ip4 = count(s.statistics.networkCounts, NetworkProtocol::IPv4),
           ip6 = count(s.statistics.networkCounts, NetworkProtocol::IPv6),
           arp = count(s.statistics.networkCounts, NetworkProtocol::Arp),
           other = arp + count(s.statistics.networkCounts, NetworkProtocol::Other);
    set(4, bars(QStringLiteral("网络分类 · 会话累计"), {"IPv4", "IPv6", QStringLiteral("其他")}, {ip4, ip6, other}));
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
            slice->setLabel(QString("%1：%2 包（%3%）")
                                .arg(entry.first)
                                .arg(entry.second, 0, 'f', 0)
                                .arg(entry.second / double(s.statistics.totalPackets) * 100, 0, 'f', 1));
        }
        series->setLabelsVisible();
    }
    pie->addSeries(series);
    pie->legend()->hide();
    set(5, pie);
    set(6, bars(QStringLiteral("TCP / UDP / ARP（不涵盖全部包）"), {"TCP", "UDP", "ARP"},
                {count(s.statistics.transportCounts, TransportProtocol::Tcp),
                 count(s.statistics.transportCounts, TransportProtocol::Udp), arp}));
    set(7, lineChart(QStringLiteral("DNS 报文区间占比"), dns, time, "%", QColor("#8657ce"), true));
    views_[7]->setToolTip(QStringLiteral("每个区间识别出的 DNS 报文数 ÷ 同一区间全部报文数 × 100%。"
                                         "无包区间按 0 显示；不代表 DNS 占 UDP 的比例，也不包含无法识别的加密 DNS。"));
}
} // namespace flowguard
