// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
// Protocol summary table: He Junjie, AI-assisted local acceptance addition.
#include "ui/chart_panel.h"
#include <QDateTime>
#include <QGridLayout>
#include <QHeaderView>
#include <QMouseEvent>
#include <QPainter>
#include <QTimer>
#include <QPointer>
#include <QApplication>
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
// Shared inspection card for all chart types; it survives periodic chart replacement.
class InteractiveChartView final : public QChartView
{
  public:
    explicit InteractiveChartView(QWidget *parent = nullptr) : QChartView(parent), readout_(new QLabel(viewport()))
    {
        setMouseTracking(true);
        viewport()->setMouseTracking(true);
        readout_->setObjectName("chartHoverReadout");
        readout_->setTextFormat(Qt::PlainText);
        readout_->setWordWrap(true);
        readout_->setAttribute(Qt::WA_TransparentForMouseEvents);
        setColor(QColor("#8657ce"));
        readout_->hide();
    }
    void adopt(QChart *next, const std::vector<TimeSample> &history)
    {
        clearPieHighlight();
        auto *old=chart(); setChart(next); delete old;
        samples_.clear(); categories_.clear(); bars_.clear();
        readout_->setObjectName(chart()->property("inspectDns").toBool() ? "dnsHoverReadout" : "chartHoverReadout");
        if (!chart()->series().isEmpty()) {
            if (auto *line=qobject_cast<QLineSeries *>(chart()->series().front())) {
                kind_=Line; samples_=line->points(); setColor(line->color());
            } else if (auto *bar=qobject_cast<QBarSeries *>(chart()->series().front())) {
                kind_=Bar; categories_=chart()->property("inspectCategories").toStringList();
                if (!bar->barSets().isEmpty()) {
                    auto *set=bar->barSets().front(); setColor(set->color());
                    for(int i=0;i<set->count();++i) bars_.append(set->at(i));
                }
            } else if (auto *pie=qobject_cast<QPieSeries *>(chart()->series().front())) {
                kind_=Pie;
                QObject::connect(pie,&QPieSeries::hovered,this,[this](QPieSlice *slice,bool on) {
                    if(on) {inspecting_=true;selectPie(slice);}
                    else if(activeSlice_==slice) {clearPieHighlight();readout_->hide();}
                });
            }
        }
        times_.clear(); intervals_.clear();
        for (const auto &sample : history) {
            times_.append(QDateTime::fromMSecsSinceEpoch(
                std::chrono::duration_cast<std::chrono::milliseconds>(sample.timestamp.time_since_epoch()).count()));
            intervals_.append(sample.intervalSeconds);
        }
        if (inspecting_) QTimer::singleShot(0,this,[this] {
            if (!inspecting_) return;
            inspect(pointer_);
            if(kind_==Pie) {
                QMouseEvent move(QEvent::MouseMove,QPointF(pointer_),QPointF(viewport()->mapToGlobal(pointer_)),
                                 Qt::NoButton,Qt::NoButton,Qt::NoModifier);
                QApplication::sendEvent(viewport(),&move);
            }
        });
        else { selected_=-1; readout_->hide(); }
    }
  protected:
    void mouseMoveEvent(QMouseEvent *event) override
    {
        pointer_=event->position().toPoint();
        inspect(pointer_);
        QChartView::mouseMoveEvent(event);
    }
    void leaveEvent(QEvent *event) override
    {
        inspecting_=false; selected_=-1; clearPieHighlight(); readout_->hide(); viewport()->update();
        QChartView::leaveEvent(event);
    }
    bool viewportEvent(QEvent *event) override
    {
        if (event->type()==QEvent::ToolTip && inspecting_) return true;
        return QChartView::viewportEvent(event);
    }
    void paintEvent(QPaintEvent *event) override
    {
        QChartView::paintEvent(event);
        if (selected_<0 || chart()->series().isEmpty() || kind_==Pie) return;
        const auto plot=chart()->plotArea();
        if(kind_==Bar) {
            if(selected_>=bars_.size() || bars_.isEmpty()) return;
            const double width=plot.width()/bars_.size();
            const auto a=mapFromScene(chart()->mapToScene(QPointF(plot.left()+selected_*width,plot.top())));
            const auto b=mapFromScene(chart()->mapToScene(QPointF(plot.left()+(selected_+1)*width,plot.bottom())));
            QPainter painter(viewport());
            QColor fill=color_;fill.setAlpha(28);
            painter.setPen(QPen(color_,1,Qt::DashLine));painter.setBrush(fill);
            painter.drawRect(QRect(a,b));return;
        }
        if(selected_>=samples_.size()) return;
        const auto at=chart()->mapToPosition(samples_[selected_],chart()->series().front());
        const auto point=mapFromScene(chart()->mapToScene(at));
        const auto top=mapFromScene(chart()->mapToScene({at.x(),plot.top()}));
        const auto bottom=mapFromScene(chart()->mapToScene({at.x(),plot.bottom()}));
        QPainter painter(viewport());
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(QPen(color_,1,Qt::DashLine));
        painter.drawLine(top,bottom);
        painter.setPen(QPen(Qt::white,2)); painter.setBrush(color_);
        painter.drawEllipse(point,5,5);
    }
  private:
    enum Kind {Line,Bar,Pie} kind_=Line;
    static QString number(double value,bool integer=false)
    {
        if(integer) return QString::number(value,'f',0);
        return value!=0 && std::abs(value)<.0001 ? QString::number(value,'g',6) : QString::number(value,'f',4);
    }
    void setColor(const QColor &color)
    {
        color_=color;
        readout_->setStyleSheet(QString("QLabel{background:#ffffff;color:#172639;border:2px solid %1;"
            "border-radius:5px;padding:8px;font-size:11pt;font-weight:600;}").arg(color.name()));
    }
    void showCard(const QString &text)
    {
        readout_->setText(text);
        readout_->setMaximumWidth(std::max(1,viewport()->width()-16)); readout_->adjustSize();
        const int left=pointer_.x()<viewport()->width()/2 ? viewport()->width()-readout_->width()-8 : 8;
        readout_->move(std::max(8,left),8);readout_->show();readout_->raise();viewport()->update();
    }
    void clearPieHighlight()
    {
        if(activeSlice_) activeSlice_->setPen(piePen_);
        activeSlice_=nullptr;
    }
    void selectPie(QPieSlice *slice)
    {
        if(activeSlice_!=slice) {
            clearPieHighlight();activeSlice_=slice;piePen_=slice->pen();
        }
        setColor(slice->color());slice->setPen(QPen(color_.darker(150),3));
        const auto category=slice->property("inspectCategory").toString();
        readout_->setProperty("sampleValue",slice->value());
        showCard(QStringLiteral("类别：%1\n报文数：%2 包\n占比：%3%")
            .arg(category.isEmpty()?slice->label():category,number(slice->value(),true),number(slice->percentage()*100)));
    }
    void inspect(const QPoint &pointer)
    {
        const auto local=chart()->mapFromScene(mapToScene(pointer));
        // Include the axis edge: tiny/zero values sit exactly at the baseline,
        // and a few pixels of pointer error must not make their readout vanish.
        inspecting_=chart()->plotArea().adjusted(-10,-12,10,28).contains(local);
        if (!inspecting_ || chart()->series().isEmpty()) {
            selected_=-1; readout_->hide(); viewport()->update(); return;
        }
        if(kind_==Pie) {if(activeSlice_) selectPie(activeSlice_);else readout_->hide();return;}
        if(kind_==Bar) {
            if(bars_.isEmpty()) {readout_->hide();return;}
            const auto fraction=(local.x()-chart()->plotArea().left())/std::max(1.,chart()->plotArea().width());
            selected_=std::clamp(qsizetype(std::floor(fraction*bars_.size())),qsizetype(0),bars_.size()-1);
            double total=0;for(const auto value:bars_) total+=value;
            readout_->setProperty("sampleValue",bars_[selected_]);
            readout_->setProperty("category",categories_.value(selected_));
            showCard(QStringLiteral("类别：%1\n报文数：%2 包\n占本图所列类别合计：%3%")
                .arg(categories_.value(selected_),number(bars_[selected_],true),number(total>0?bars_[selected_]/total*100:0)));
            return;
        }
        if(samples_.isEmpty()) {selected_=-1;readout_->hide();viewport()->update();return;}
        const auto x=chart()->mapToValue(local,chart()->series().front()).x();
        const auto byX=[](const QPointF &point,double value) {return point.x()<value;};
        auto nearest=std::lower_bound(samples_.cbegin(),samples_.cend(),x,byX);
        selected_=nearest==samples_.cend() ? samples_.size()-1 : qsizetype(nearest-samples_.cbegin());
        if(selected_>0 && std::abs(samples_[selected_-1].x()-x)<=std::abs(samples_[selected_].x()-x)) --selected_;
        // Several time samples may share one screen pixel. Near the curve,
        // use 2-D proximity so a narrow visible peak wins over its zero neighbours.
        if (chart()->plotArea().contains(local)) {
            double closest=18.*18.;
            const auto low=chart()->mapToValue(local-QPointF(18,0),chart()->series().front()).x();
            const auto high=chart()->mapToValue(local+QPointF(18,0),chart()->series().front()).x();
            auto candidate=std::lower_bound(samples_.cbegin(),samples_.cend(),low,byX);
            for(;candidate!=samples_.cend() && candidate->x()<=high;++candidate) {
                const auto at=chart()->mapToPosition(*candidate,chart()->series().front());
                const auto dx=at.x()-local.x(),dy=at.y()-local.y();
                const auto distance=dx*dx+dy*dy;
                if(distance<closest) {closest=distance;selected_=qsizetype(candidate-samples_.cbegin());}
            }
        }
        const auto value=samples_[selected_].y();
        QString text;
        if(chart()->property("inspectDns").toBool())
            text=QStringLiteral("DNS 占比：%1%\n捕获时间：%2\n窗口内：%3 秒  |  统计区间：%4 秒")
                .arg(number(value),times_.value(selected_).toString("yyyy-MM-dd HH:mm:ss.zzz"),
                     QString::number(samples_[selected_].x(),'f',3),QString::number(intervals_.value(selected_),'f',3));
        else {
            const bool integers=chart()->property("inspectInteger").toBool();
            const auto sampleX=samples_[selected_].x();
            const auto xUnit=chart()->property("inspectXUnit").toString();
            const auto xText=integers && sampleX==65536 ? QStringLiteral(">65535 B（合并统计）") :
                number(sampleX,integers)+(xUnit.isEmpty()?QString():" "+xUnit);
            text=QStringLiteral("%1：%2 %3\n%4：%5")
                .arg(chart()->property("inspectValueLabel").toString(),number(value,integers),
                     chart()->property("inspectUnit").toString(),chart()->property("inspectXLabel").toString(),xText);
            if(selected_<times_.size()) text+=QStringLiteral("\n捕获时间：%1\n统计区间：%2 秒")
                .arg(times_[selected_].toString("yyyy-MM-dd HH:mm:ss.zzz"),QString::number(intervals_[selected_],'f',3));
        }
        readout_->setProperty("dnsPercentage",value);
        readout_->setProperty("sampleSeconds",samples_[selected_].x());
        readout_->setProperty("sampleValue",value);
        showCard(text);
    }
    QLabel *readout_;
    QList<QPointF> samples_;
    QList<QDateTime> times_;
    QList<double> intervals_;
    QStringList categories_;
    QList<qreal> bars_;
    QColor color_;
    QPointer<QPieSlice> activeSlice_;
    QPen piePen_;
    QPoint pointer_;
    qsizetype selected_=-1;
    bool inspecting_=false;
};
QChartView *createInteractiveChartView(QWidget *parent) {return new InteractiveChartView(parent);}
void replaceInteractiveChart(QChartView *view,QChart *chart,const std::vector<TimeSample> &history)
{
    static_cast<InteractiveChartView *>(view)->adopt(chart,history);
}
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
    c->setProperty("inspectValueLabel",title);
    c->setProperty("inspectXLabel",x);
    c->setProperty("inspectUnit",y);
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
        const double upper=maximum>0 ? std::max(.000001,maximum*1.25) : 1.;
        axis->setRange(0,percent ? std::min(100.,upper) : upper);
        axis->setLabelFormat("%.4g");
        if(percent) axis->setTitleText(QStringLiteral("%（自动缩放）"));
    }
    return c;
}
static QChart *bars(const QString &title, const QStringList &labels, const QList<qreal> &values)
{
    auto *c = new QChart;
    c->setProperty("inspectCategories",labels);
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
    // Required course deliverable: numeric protocol summary, separate from the
    // recent-packet table and from chart rendering. Counts retain uint64 precision.
    protocolTable_ = new QTableWidget(9, 5, this);
    protocolTable_->setObjectName("protocolSummaryTable");
    protocolTable_->setAccessibleName(QStringLiteral("协议汇总统计表"));
    protocolTable_->setHorizontalHeaderLabels({QStringLiteral("分类"), QStringLiteral("协议"),
        QStringLiteral("报文数"), QStringLiteral("占会话总包数"), QStringLiteral("统计说明")});
    protocolTable_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    protocolTable_->setSelectionBehavior(QAbstractItemView::SelectRows);
    protocolTable_->setAlternatingRowColors(true);
    protocolTable_->setSortingEnabled(false);
    protocolTable_->verticalHeader()->hide();
    protocolTable_->verticalHeader()->setDefaultSectionSize(28);
    protocolTable_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    protocolTable_->horizontalHeader()->setSectionResizeMode(4, QHeaderView::Stretch);
    const QStringList names{"IPv4", "IPv6", "ARP", "Other", "TCP", "UDP", "ICMP", "ICMPv6", "DNS"};
    for (int row = 0; row < names.size(); ++row) {
        for (int col = 0; col < 5; ++col) {
            auto *item = new QTableWidgetItem;
            item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
            protocolTable_->setItem(row, col, item);
        }
        protocolTable_->item(row, 0)->setText(row < 4 ? QStringLiteral("网络分类") : row < 8 ? QStringLiteral("传输/控制") : QStringLiteral("应用识别"));
        protocolTable_->item(row, 1)->setText(names[row]);
        protocolTable_->item(row, 4)->setText(row == 3 ? QStringLiteral("未归入 IPv4/IPv6/ARP") :
            row == 8 ? QStringLiteral("已识别的 DNS，包含在相应 TCP/UDP 中") : QStringLiteral("本次会话累计，包含可识别的异常包"));
        protocolTable_->item(row, 2)->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        protocolTable_->item(row, 3)->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    }
    protocolTable_->setToolTip(QStringLiteral("分母均为本次会话总报文数，显示筛选不改变统计。"
        "网络层、传输层及 DNS 识别会交叠，各行不能相加当作总包数；网络分类图中的其他还包含 ARP。"));
    protocolTable_->setMinimumHeight(9 * 28 + 42);
    protocolTable_->setMaximumHeight(9 * 28 + 42);
    l->addWidget(protocolTable_, 1, 0, 1, 2);
    const std::array<int, 8> order{2, 3, 4, 5, 6, 7, 0, 1};
    for (int i = 0; i < 8; ++i)
    {
        views_[i] = createInteractiveChartView();
        views_[i]->setMinimumHeight(245);
        views_[i]->setRenderHint(QPainter::Antialiasing);
        views_[i]->setObjectName(QString("statisticsChart%1").arg(i));
        const int position = int(std::find(order.begin(), order.end(), i) - order.begin());
        l->addWidget(views_[i], position / 2 + 2, position % 2);
    }
}
void ChartPanel::refresh(const ProcessingSnapshot &s, const QString &source)
{
    const auto value = [](const auto &counts, auto key) -> std::uint64_t {
        const auto it = counts.find(key); return it == counts.end() ? 0 : it->second;
    };
    const auto &stats = s.statistics;
    const std::array<std::uint64_t, 9> counts{
        value(stats.networkCounts, NetworkProtocol::IPv4), value(stats.networkCounts, NetworkProtocol::IPv6),
        value(stats.networkCounts, NetworkProtocol::Arp), value(stats.networkCounts, NetworkProtocol::Other),
        value(stats.transportCounts, TransportProtocol::Tcp), value(stats.transportCounts, TransportProtocol::Udp),
        value(stats.transportCounts, TransportProtocol::Icmp), value(stats.transportCounts, TransportProtocol::Icmpv6),
        stats.dnsPackets};
    for (int row = 0; row < int(counts.size()); ++row) {
        protocolTable_->item(row, 2)->setText(QString::number(qulonglong(counts[row])));
        protocolTable_->item(row, 2)->setData(Qt::UserRole, QVariant::fromValue(qulonglong(counts[row])));
        const double percent = stats.totalPackets ? double(counts[row]) / double(stats.totalPackets) * 100 : 0;
        protocolTable_->item(row, 3)->setText(QString::number(percent, 'f', 2) + '%');
    }
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
        if(i==7) chart->setProperty("inspectDns",true);
        if(i==2) {
            chart->setProperty("inspectInteger",true);
            chart->setProperty("inspectValueLabel",QStringLiteral("长度频次"));
            chart->setProperty("inspectUnit",QStringLiteral("包"));
            chart->setProperty("inspectXLabel",QStringLiteral("原始长度"));
            chart->setProperty("inspectXUnit","B");
        }
        if(i==0 || i==1 || i==7) replaceInteractiveChart(views_[i],chart,s.history);
        else replaceInteractiveChart(views_[i],chart);
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
    set(2, lineChart(QStringLiteral("长度频次（>65535 B 合并统计）"), lengths, QStringLiteral("原始长度 B"),
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
            slice->setProperty("inspectCategory",entry.first);
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
    set(7, lineChart(QStringLiteral("DNS 报文区间占比（自动缩放）"), dns, time, "%", QColor("#8657ce"), true));
    // DNS fractions can be far below 1%; a fixed 0-100 axis hides their peaks.
    double dnsMaximum=0;
    for (const auto &point : dns) dnsMaximum=std::max(dnsMaximum,point.y());
    auto *dnsAxis=qobject_cast<QValueAxis *>(views_[7]->chart()->axes(Qt::Vertical).front());
    dnsAxis->setRange(0,dnsMaximum>0 ? std::min(100.,std::max(0.000001,dnsMaximum*1.25)) : 1.);
    dnsAxis->setLabelFormat("%.4g");
    dnsAxis->setTitleText(QStringLiteral("DNS 占比（%，自动缩放）"));
    views_[7]->setToolTip(QStringLiteral("纵轴按当前窗口真实占比自动缩放，数值仍为百分比。鼠标可在绘图区或X轴附近读取最近采样点。"
                                         "每个区间识别出的 DNS 报文数 ÷ 同一区间全部报文数 × 100%。"
                                         "无包区间按 0 显示；不代表 DNS 占 UDP 的比例，也不包含无法识别的加密 DNS。"));
}
} // namespace flowguard
