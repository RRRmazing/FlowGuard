#include "ui/alert_panel.h"
#include <QtWidgets>
#include <QSaveFile>
#include <algorithm>

namespace flowguard {
QString alertRuleName(AlertRule rule) {
    static const QStringList names{QStringLiteral("疑似 SYN 泛洪"),QStringLiteral("回声请求频率异常"),
        QStringLiteral("疑似 TCP 端口扫描"),QStringLiteral("UDP 高频流量"),QStringLiteral("ARP 地址映射变化/冲突")};
    return names[int(rule)];
}
static QString text(const std::string& s) { return QString::fromStdString(s); }
static QString stamp(std::chrono::system_clock::time_point t) {
    return QDateTime::fromMSecsSinceEpoch(std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count())
        .toString("yyyy-MM-dd HH:mm:ss.zzz");
}
static std::string identity(const AlertRecord& a) { return std::to_string(int(a.rule))+":"+a.key; }
static QString countUnit(AlertRule rule) {
    return rule==AlertRule::PortScan ? QStringLiteral("端口") : rule==AlertRule::Arp ? QStringLiteral("次") : QStringLiteral("包");
}
static QWidget* numberControl(QSpinBox* value,const QString& label) {
    auto* control=new QWidget;
    auto* row=new QHBoxLayout(control);row->setContentsMargins(0,0,0,0);row->setSpacing(0);
    value->setButtonSymbols(QAbstractSpinBox::NoButtons);
    row->addWidget(value,1);
    auto* up=new QToolButton;auto* down=new QToolButton;
    up->setObjectName(value->objectName()+"Increase");down->setObjectName(value->objectName()+"Decrease");
    up->setText(QStringLiteral("▲"));down->setText(QStringLiteral("▼"));
    up->setToolTip(QStringLiteral("增加")+label);down->setToolTip(QStringLiteral("减少")+label);
    up->setAccessibleName(up->toolTip());down->setAccessibleName(down->toolTip());
    for(auto* button : {up,down}) {
        button->setFixedWidth(28);button->setMinimumHeight(32);
        button->setSizePolicy(QSizePolicy::Fixed,QSizePolicy::Expanding);
        button->setCursor(Qt::ArrowCursor);button->setAutoRepeat(true);
        button->setStyleSheet("QToolButton{background:white;border:1px solid #cad6e3;color:#172639;} "
            "QToolButton:hover{background:#e0f2f1;} QToolButton:disabled{background:#edf0f4;color:#9da7b3;}");
        row->addWidget(button);
    }
    QObject::connect(up,&QToolButton::clicked,value,&QSpinBox::stepUp);
    QObject::connect(down,&QToolButton::clicked,value,&QSpinBox::stepDown);
    const auto update=[value,up,down] {
        up->setEnabled(value->value()<value->maximum());down->setEnabled(value->value()>value->minimum());
    };
    QObject::connect(value,&QSpinBox::valueChanged,control,[update](int){update();});update();
    return control;
}
AlertPanel::AlertPanel(QWidget* parent) : QWidget(parent) {
    setObjectName("alertPanel");
    auto* layout = new QVBoxLayout(this);
    auto* header = new QHBoxLayout;
    auto* title = new QLabel(QStringLiteral("预警监测")); title->setObjectName("metric"); header->addWidget(title);
    header->addStretch();
    auto* settings = new QPushButton(QStringLiteral("规则设置")); settings->setObjectName("alertSettings");
    settings->setCheckable(true); header->addWidget(settings); layout->addLayout(header);
    auto* row = new QHBoxLayout;
    status_ = new QLabel; status_->setObjectName("alertStatus"); status_->setWordWrap(true); row->addWidget(status_,1);
    pause_ = new QPushButton(QStringLiteral("暂停预警")); pause_->setObjectName("pauseAlerts"); row->addWidget(pause_);
    layout->addLayout(row);
    scope_ = new QLabel; scope_->setTextFormat(Qt::PlainText); scope_->setWordWrap(true); layout->addWidget(scope_);
    auto* rules = new QWidget; rules->setObjectName("alertRuleSettings");
    auto* grid = new QGridLayout(rules);
    const QStringList columns{QStringLiteral("启用规则"),QStringLiteral("统计对象"),QStringLiteral("窗口 / 秒"),QStringLiteral("触发数量 ≥")};
    for (int i=0;i<columns.size();++i) grid->addWidget(new QLabel(columns[i]),0,i);
    const QStringList groups{QStringLiteral("目标 IP＋端口"),QStringLiteral("目标 IP（IPv4 / IPv6）"),
        QStringLiteral("来源＋目标的不同端口"),QStringLiteral("目标 IP＋端口"),QStringLiteral("同一 IP 的 MAC 变化次数")};
    const auto defaults = defaultAlertRules();
    for (std::size_t i=0;i<alertRuleCount;++i) {
        enabled_[i] = new QCheckBox(alertRuleName(AlertRule(i))); enabled_[i]->setChecked(defaults[i].enabled);
        enabled_[i]->setObjectName(QString("alertEnabled%1").arg(i));
        window_[i] = new QSpinBox; window_[i]->setRange(1,60); window_[i]->setValue(int(defaults[i].windowSeconds));
        window_[i]->setObjectName(QString("alertWindow%1").arg(i));
        threshold_[i] = new QSpinBox; threshold_[i]->setRange(1,i==2?65536:100000); threshold_[i]->setValue(int(defaults[i].threshold));
        threshold_[i]->setObjectName(QString("alertThreshold%1").arg(i));
        grid->addWidget(enabled_[i],int(i)+1,0); grid->addWidget(new QLabel(groups[int(i)]),int(i)+1,1);
        grid->addWidget(numberControl(window_[i],alertRuleName(AlertRule(i))+QStringLiteral("窗口秒数")),int(i)+1,2);
        grid->addWidget(numberControl(threshold_[i],alertRuleName(AlertRule(i))+QStringLiteral("触发数量")),int(i)+1,3);
    }
    auto* apply = new QPushButton(QStringLiteral("应用规则")); apply->setObjectName("applyAlertRules");
    grid->addWidget(apply,6,3);
    auto* ruleHint = new QLabel(QStringLiteral("窗口采用 (当前时间－窗口, 当前时间]。修改后重新评判；文件模式自动扫描已分析部分。默认阈值仅供起步，需按环境校准。"));
    ruleHint->setWordWrap(true); grid->addWidget(ruleHint,6,0,1,3);
    layout->addWidget(rules); rules->hide();
    connect(settings,&QPushButton::toggled,rules,&QWidget::setVisible);
    connect(apply,&QPushButton::clicked,this,[this] {
        AlertRules rules;
        for (std::size_t i=0;i<alertRuleCount;++i) rules[i] = {enabled_[i]->isChecked(),unsigned(window_[i]->value()),std::uint64_t(threshold_[i]->value())};
        if (applyRules) applyRules(rules);
    });
    counts_ = new QLabel; counts_->setObjectName("alertCounts"); layout->addWidget(counts_);
    auto* listHeader = new QHBoxLayout; listHeader->addStretch();
    export_ = new QPushButton(QStringLiteral("导出告警 CSV")); listHeader->addWidget(export_); layout->addLayout(listHeader);
    table_ = new QTableWidget(0,6); table_->setObjectName("alertTable");
    table_->setHorizontalHeaderLabels({QStringLiteral("最近触发"),QStringLiteral("预警类型"),QStringLiteral("检测对象"),
        QStringLiteral("峰值 / 阈值"),QStringLiteral("检测状态"),QStringLiteral("确认状态")});
    table_->setSelectionBehavior(QAbstractItemView::SelectRows); table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers); table_->verticalHeader()->hide();
    table_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setStretchLastSection(true); table_->setMinimumHeight(180); layout->addWidget(table_,1);
    auto* detailBox = new QGroupBox(QStringLiteral("告警详情与触发依据")); auto* detailLayout = new QVBoxLayout(detailBox);
    detail_ = new QLabel; detail_->setObjectName("alertDetail"); detail_->setTextFormat(Qt::PlainText);
    detail_->setTextInteractionFlags(Qt::TextSelectableByMouse); detail_->setWordWrap(true); detailLayout->addWidget(detail_);
    auto* actions = new QHBoxLayout;
    confirm_ = new QPushButton(QStringLiteral("标记已确认")); related_ = new QPushButton(QStringLiteral("查看相关报文"));
    related_->setObjectName("alertRelatedPackets"); actions->addWidget(confirm_); actions->addWidget(related_); actions->addStretch(); detailLayout->addLayout(actions);
    layout->addWidget(detailBox);
    connect(table_,&QTableWidget::itemSelectionChanged,this,[this]{
        const int row=table_->currentRow();
        selectedKey_ = row>=0 && row<int(snapshot_.records.size()) ? identity(snapshot_.records[std::size_t(row)]) : "";
        showDetail();
    });
    connect(confirm_,&QPushButton::clicked,this,[this]{ if (const auto* a=selected()) { confirmed_.insert(identity(*a)); updateCounts(); showDetail();
        if (table_->currentRow()>=0) table_->item(table_->currentRow(),5)->setText(QStringLiteral("已确认")); }});
    connect(related_,&QPushButton::clicked,this,[this]{ if (const auto* a=selected()) if(relatedPackets) relatedPackets(*a); });
    connect(pause_,&QPushButton::clicked,this,[this]{if(pauseDetection) pauseDetection(!snapshot_.paused);});
    connect(export_,&QPushButton::clicked,this,[this]{exportCsv();});
    auto* hint = new QLabel(QStringLiteral("预警仅表示规则命中；只监测当前网卡或文件中可见的报文。过滤、丢包、截断会影响结论。SYN 规则统计请求速率，不代表已证实握手失败；ARP 变化不等于欺骗。"));
    hint->setWordWrap(true); layout->addWidget(hint);
    refresh({},QString(),false,false);
}
std::size_t AlertPanel::unconfirmedCount() const {
    return std::count_if(snapshot_.records.begin(),snapshot_.records.end(),[this](const auto& a){return !confirmed_.count(identity(a));});
}
void AlertPanel::updateCounts() {
    const auto active = std::count_if(snapshot_.records.begin(),snapshot_.records.end(),[](const auto& a){return a.active;});
    counts_->setText(QStringLiteral("持续异常 %1  |  待确认 %2  |  当前规则下的会话告警 %3").arg(active).arg(unconfirmedCount()).arg(snapshot_.records.size()));
}
const AlertRecord* AlertPanel::selected() const {
    for (const auto& a : snapshot_.records) if(identity(a)==selectedKey_) return &a;
    return nullptr;
}
void AlertPanel::showDetail() {
    const auto* a=selected(); confirm_->setEnabled(a && !confirmed_.count(identity(*a))); related_->setEnabled(a!=nullptr);
    if(!a) {detail_->setText(QStringLiteral("选择一条告警查看触发依据。暂无告警只表示当前规则未发现异常。"));return;}
    const QString unit=countUnit(a->rule);
    QString evidence;
    if(!a->evidence.empty()) {
        const auto macs=text(a->evidence).split(" -> ");
        evidence=macs.size()==2 ? QStringLiteral("\n原 MAC 地址：%1\n新 MAC 地址：%2").arg(macs[0],macs[1]) : QStringLiteral("\nMAC 地址变化：")+text(a->evidence);
    }
    detail_->setText(QStringLiteral("%1\n检测对象：%2\n窗口 %3 秒，触发数量 ≥ %4；窗口峰值 %5，当前窗口数量 %6。\n首次触发：%7\n最近触发：%8\n关联报文序号：%9%10%11")
        .arg(alertRuleName(a->rule),text(a->key)).arg(a->config.windowSeconds)
        .arg(QString::number(a->config.threshold)+unit,QString::number(a->peak)+unit,QString::number(a->current)+unit)
        .arg(stamp(a->first),stamp(a->last)).arg(a->packetSequence).arg(evidence)
        .arg(snapshot_.rebuilding[std::size_t(a->rule)]?QStringLiteral("\n正在重新检测：当前显示旧结果，完成后替换。 "):QString()));
}
void AlertPanel::refresh(const AlertSnapshot& s,const QString& source,bool running,bool playbackPaused) {
    if(snapshot_.sessionId!=s.sessionId){confirmed_.clear(); selectedKey_.clear();}
    snapshot_=s;
    const bool rebuilding = std::any_of(s.rebuilding.begin(),s.rebuilding.end(),[](bool b){return b;});
    QString state = !s.sessionId ? QStringLiteral("等待采集或打开 PCAP") : s.finished ? (s.file?QStringLiteral("文件分析已结束"):QStringLiteral("采集已结束"))
        : playbackPaused ? QStringLiteral("文件回放已暂停") : running ? QStringLiteral("正在监测") : QStringLiteral("等待报文");
    if(s.paused) state+=QStringLiteral(" · 预警已暂停，采集/读取继续");
    if(rebuilding) state+=QStringLiteral(" · 正在按新规则重新检测…");
    if(!s.error.empty()) state+=QStringLiteral("\n重新检测失败，原结果保留：")+text(s.error);
    if(s.latePackets) state+=QStringLiteral("\n时间戳回退：有 %1 次规则评估跳过乱序报文，结果可能不完整。 ").arg(s.latePackets);
    if(s.limited) state+=QStringLiteral("\n检测容量限制已触发 %1 次，结果可能不完整。 ").arg(s.limited);
    if(s.ignoredPackets) state+=QStringLiteral("\n已跳过 %1 条截断、错误或不支持的报文；未将其视为正常流量。 ").arg(s.ignoredPackets);
    status_->setText(state); scope_->setText(QStringLiteral("监测范围：")+(source.isEmpty()?QStringLiteral("尚未选择输入"):source));
    pause_->setText(s.paused?QStringLiteral("恢复预警"):QStringLiteral("暂停预警")); pause_->setEnabled(s.paused || running || playbackPaused);
    export_->setEnabled(!s.records.empty() && !rebuilding && s.error.empty());
    std::set<std::string> present;for(const auto& a:s.records)present.insert(identity(a));
    for(auto i=confirmed_.begin();i!=confirmed_.end();)if(!present.count(*i))i=confirmed_.erase(i);else ++i;
    QSignalBlocker blocker(table_); table_->setRowCount(int(s.records.size()));
    int selectedRow=-1;
    for(std::size_t i=0;i<s.records.size();++i){const auto& a=s.records[i];
        QString detection = a.active ? (s.finished?QStringLiteral("输入结束时仍异常"):QStringLiteral("持续异常")):QStringLiteral("已恢复");
        if(s.rebuilding[std::size_t(a.rule)]) detection=QStringLiteral("待更新（旧结果）");
        else if(!s.error.empty()) detection+=QStringLiteral("（结果待核实）");
        const auto unit=countUnit(a.rule);
        const QStringList cells{stamp(a.last),alertRuleName(a.rule),text(a.key),QStringLiteral("%1%2 / %3%2").arg(a.peak).arg(unit).arg(a.config.threshold),detection,
            confirmed_.count(identity(a))?QStringLiteral("已确认"):QStringLiteral("待确认")};
        for(int c=0;c<cells.size();++c){auto* item=table_->item(int(i),c);if(!item){item=new QTableWidgetItem;table_->setItem(int(i),c,item);}item->setText(cells[c]);}
        if(identity(a)==selectedKey_)selectedRow=int(i);
    }
    if(selectedRow<0 && !s.records.empty()) {selectedRow=0;selectedKey_=identity(s.records.front());}
    if(selectedRow>=0)table_->selectRow(selectedRow);else selectedKey_.clear();
    updateCounts();showDetail();
}
void AlertPanel::exportCsv() {
    const auto path=QFileDialog::getSaveFileName(this,QStringLiteral("导出当前规则的告警记录"),{},"CSV (*.csv)");if(path.isEmpty())return;
    QSaveFile file(path);if(!file.open(QIODevice::WriteOnly)){QMessageBox::warning(this,QStringLiteral("导出失败"),file.errorString());return;}
    QByteArray csv("\xEF\xBB\xBF");
    csv+="session,rule,object,first,last,window_seconds,threshold,peak,current,active,confirmed,evidence\r\n";
    auto quote=[](QString s){s.replace('"',"\"\"");return '"'+s+'"';};
    for(const auto& a:snapshot_.records){QStringList row{QString::number(snapshot_.sessionId),alertRuleName(a.rule),text(a.key),stamp(a.first),stamp(a.last),
        QString::number(a.config.windowSeconds),QString::number(a.config.threshold),QString::number(a.peak),QString::number(a.current),
        a.active?"true":"false",confirmed_.count(identity(a))?"true":"false",text(a.evidence)};
        for(auto& cell:row)cell=quote(cell);csv+=row.join(',').toUtf8()+"\r\n";
    }
    if(file.write(csv)!=csv.size() || !file.commit())QMessageBox::warning(this,QStringLiteral("导出失败"),file.errorString());
}
} // namespace flowguard
