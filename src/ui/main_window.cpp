// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "ui/main_window.h"
#include "monitoring/run_recorder.h"
#include "ui/chart_panel.h"
#include "ui/device_selector.h"
#include "ui/packet_model.h"
#include <QDesktopServices>
#include <QElapsedTimer>
#include <QHostAddress>
#include <QStandardPaths>
#include <QThread>
#include <QTimer>
#include <QtWidgets>
#include <atomic>
#include <functional>

namespace flowguard
{
static QString txt(const std::string &s)
{
    return QString::fromStdString(s);
}
static QString num(std::uint64_t n)
{
    return QString::number(qulonglong(n));
}
static QString duration(qint64 s)
{
    return QStringLiteral("%1天 %2:%3:%4")
        .arg(s / 86400)
        .arg(s / 3600 % 24, 2, 10, QChar('0'))
        .arg(s / 60 % 60, 2, 10, QChar('0'))
        .arg(s % 60, 2, 10, QChar('0'));
}
static QString mib(std::uint64_t n)
{
    return QString::number(double(n) / 1024 / 1024, 'f', 2) + " MiB";
}
static QString stateName(ProcessingState s)
{
    switch (s)
    {
    case ProcessingState::Idle:
        return QStringLiteral("就绪");
    case ProcessingState::Running:
        return QStringLiteral("运行中");
    case ProcessingState::Paused:
        return QStringLiteral("已暂停");
    case ProcessingState::Stopped:
        return QStringLiteral("已停止");
    case ProcessingState::Completed:
        return QStringLiteral("分析完成");
    case ProcessingState::Failed:
        return QStringLiteral("失败");
    }
    return {};
}
static QString parseName(ParseStatus s)
{
    switch (s)
    {
    case ParseStatus::Complete:
        return QStringLiteral("解析完整");
    case ParseStatus::Truncated:
        return QStringLiteral("截断");
    case ParseStatus::Malformed:
        return QStringLiteral("格式错误");
    case ParseStatus::Unsupported:
        return QStringLiteral("不支持");
    }
    return {};
}
static void fields(QTreeWidgetItem *parent, const std::vector<ProtocolField> &list)
{
    for (const auto &f : list)
    {
        auto *node = new QTreeWidgetItem(parent, {txt(f.name), txt(f.value)});
        fields(node, f.children);
    }
}
struct MainWindow::Impl
{
    MainWindow *w;
    ProcessingSession backend;
    QThread thread;
    QObject *worker = new QObject;
    RunRecorder recorder; // Worker thread only. UI receives copied results.
    QTimer *recorderTimer = nullptr;
    std::atomic<double> guiDelay{0};
    std::atomic<std::uint64_t> guiSession{0}, listEvicted{0};
    QElapsedTimer uptime, guiTick, sessionClock;
    QDateTime sessionStarted;
    qint64 sessionElapsed = 0;
    ProcessingSnapshot snapshot;
    ResourceSample resource;
    std::deque<std::pair<double, ResourceSample>> resourceHistory;
    bool busy = false, closing = false, allowClose = false;
    QString recordPath, recordError, controlError, lastState, lastSavingError, lastSourceError;
    QTimer *poll, *second;
    DeviceSelector *devices = nullptr;
    QComboBox *protocol = nullptr;
    QLineEdit *bpf = nullptr, *ip = nullptr, *port = nullptr;
    QCheckBox *promiscuous = nullptr, *follow = nullptr;
    QSpinBox *snaplen = nullptr;
    QWidget *snapshotControl = nullptr;
    QToolButton *snapshotUp = nullptr, *snapshotDown = nullptr;
    QPushButton *start = nullptr, *stop = nullptr, *open = nullptr, *pause = nullptr, *save = nullptr,
                *refresh = nullptr;
    QLabel *state = nullptr, *sessionTime = nullptr, *error = nullptr, *count = nullptr, *resourcesText = nullptr,
           *recordLabel = nullptr;
    QAction *pauseAction = nullptr;
    std::array<QLabel *, 3> timeBar{};
    std::array<QLabel *, 4> resourceMetrics{};
    QString sourceDescription;
    QString recordLocationDescription = QStringLiteral("正在准备运行记录");
    std::array<QLabel *, 4> metrics{};
    PacketModel *model = nullptr;
    QTableView *table = nullptr;
    QTreeWidget *tree = nullptr;
    QLabel *summary = nullptr;
    ChartPanel *charts = nullptr;
    QChartView *cpuView = nullptr, *memoryView = nullptr;
    QStackedWidget *pages = nullptr;
    explicit Impl(MainWindow *window) : w(window), poll(new QTimer(window)), second(new QTimer(window))
    {
        uptime.start();
        guiTick.start();
        worker->moveToThread(&thread);
        QObject::connect(&thread, &QThread::finished, worker, &QObject::deleteLater);
        thread.start();
    }
    bool active() const
    {
        return snapshot.state == ProcessingState::Running || snapshot.state == ProcessingState::Paused;
    }
    void command(const QString &name, std::function<OperationResult()> fn, QJsonObject detail = {})
    {
        if (busy || closing)
            return;
        busy = true;
        controlError.clear();
        updateControls();
        QMetaObject::invokeMethod(
            worker,
            [this, name, fn = std::move(fn), detail] {
                recorder.event("control_requested", {{"name", name}, {"settings", detail}});
                OperationResult result;
                try
                {
                    result = fn();
                }
                catch (const std::exception &e)
                {
                    result = {ErrorCode::InvalidState, e.what()};
                }
                const auto s = backend.snapshot();
                recorder.event("control_finished",
                               {{"name", name},
                                {"ok", result.ok()},
                                {"message", txt(result.message)},
                                {"session", QJsonObject{{"session_id", num(s.sessionId)},
                                                        {"source", int(s.source)},
                                                        {"state", int(s.state)},
                                                        {"total_packets", num(s.statistics.totalPackets)},
                                                        {"total_bytes", num(s.statistics.totalBytes)},
                                                        {"saved_packets", num(s.savedPackets)},
                                                        {"queue_dropped", num(s.capture.queueDroppedPackets)},
                                                        {"display_dropped", num(s.displayDroppedPackets)},
                                                        {"late_history_packets", num(s.lateHistoryPackets)}}}});
                QMetaObject::invokeMethod(
                    w,
                    [this, result] {
                        busy = false;
                        if (!result.ok())
                            controlError = txt(result.message);
                        tick();
                    },
                    Qt::QueuedConnection);
            },
            Qt::QueuedConnection);
    }
    void updateControls()
    {
        const bool idle = !active() && !busy && !closing;
        for (auto *widget : std::initializer_list<QWidget *>{devices, refresh, bpf, promiscuous, snapshotControl})
            widget->setEnabled(idle);
        snapshotUp->setEnabled(idle && snaplen->value() < snaplen->maximum());
        snapshotDown->setEnabled(idle && snaplen->value() > snaplen->minimum());
        start->setEnabled(idle && devices->count() > 0);
        open->setEnabled(idle);
        stop->setEnabled(active() && !busy && !closing);
        if (pauseAction)
            pauseAction->setVisible(snapshot.source == ProcessingSource::File && active());
        pause->setEnabled(!busy && !closing);
        pause->setText(snapshot.state == ProcessingState::Paused ? QStringLiteral("继续回放")
                                                                 : QStringLiteral("暂停回放"));
        save->setEnabled(active() && !busy && !closing);
        save->setText(snapshot.savingActive || snapshot.savingRequested ? QStringLiteral("结束保存")
                                                                        : QStringLiteral("保存后续报文"));
        state->setToolTip(sourceDescription);
        state->setText(closing ? QStringLiteral("正在退出…")
                       : busy  ? QStringLiteral("处理中…")
                               : stateName(snapshot.state));
        QStringList problems;
        if (!controlError.isEmpty())
            problems << controlError;
        if (!snapshot.error.ok())
            problems << QStringLiteral("来源：") + txt(snapshot.error.message);
        if (!snapshot.savingError.ok())
            problems << QStringLiteral("保存：") + txt(snapshot.savingError.message);
        if (!recordError.isEmpty())
            problems << QStringLiteral("日志：") + recordError;
        error->setText(problems.join('\n'));
        error->setVisible(!problems.empty());
    }
    void refreshDevices()
    {
        command("enumerate", [this] {
            const auto result = enumerateDevices();
            const auto choices = captureDeviceChoices(result.devices);
            QMetaObject::invokeMethod(
                w,
                [this, result, choices] {
                    devices->setChoices(choices);
                    devices->setToolTip(devices->currentData(Qt::ToolTipRole).toString());
                    if (devices->count() == 0)
                        controlError = QStringLiteral("未发现网卡，请检查 Npcap 后刷新。");
                },
                Qt::QueuedConnection);
            return result.result;
        });
    }
    void chooseFile()
    {
        if (active() || busy)
            return;
        const auto path =
            QFileDialog::getOpenFileName(w, QStringLiteral("打开经典 PCAP"), {}, "PCAP (*.pcap);;所有文件 (*)");
        if (path.isEmpty())
            return;
        QDialog dialog(w);
        dialog.setWindowTitle(QStringLiteral("文件导入与回放"));
        auto *layout = new QFormLayout(&dialog);
        auto *mode = new QComboBox;
        mode->addItems({QStringLiteral("快速导入分析"), QStringLiteral("按捕获时间回放")});
        auto *speed = new QDoubleSpinBox;
        speed->setRange(.1, 100);
        speed->setValue(1);
        speed->setSuffix(" ×");
        layout->addRow(QStringLiteral("文件"), new QLabel(path));
        layout->addRow(QStringLiteral("模式"), mode);
        layout->addRow(QStringLiteral("倍速"), speed);
        layout->addRow(new QLabel(QStringLiteral("经典 PCAP；启动后锁定倍速。PCAPNG 暂不支持。")));
        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
        layout->addRow(buttons);
        QObject::connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
        QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        if (dialog.exec() == QDialog::Accepted)
            w->openFile(path, mode->currentIndex() == 1, speed->value());
    }
    void applyFilter()
    {
        DisplayFilter f;
        f.protocol = static_cast<ProtocolFilter>(protocol->currentIndex());
        const auto address = ip->text().trimmed();
        if (!address.isEmpty())
        {
            QHostAddress parsed(address);
            if (parsed.isNull())
            {
                controlError = QStringLiteral("请输入完整有效 IP，旧筛选保持不变。");
                updateControls();
                return;
            }
            f.ipAddress = parsed.toString().toStdString();
        }
        const auto p = port->text().trimmed();
        if (!p.isEmpty())
        {
            bool ok = false;
            auto n = p.toUInt(&ok);
            if (!ok || n > 65535)
            {
                controlError = QStringLiteral("端口必须为 0–65535 整数，旧筛选保持不变。");
                updateControls();
                return;
            }
            f.port = std::uint16_t(n);
        }
        controlError.clear();
        model->filter(f);
        tree->clear();
        summary->clear();
        updateControls();
    }
    void showPacket(int row)
    {
        tree->clear();
        const auto *p = model->packet(row);
        if (!p)
        {
            summary->clear();
            return;
        }
        fields(tree->invisibleRootItem(), p->fields);
        tree->expandAll();
        const auto &r = p->record;
        auto *required = new QTreeWidgetItem(tree, {QStringLiteral("关键字段核对"), parseName(r.status)});
        auto item = [required](QString k, QString v) {
            new QTreeWidgetItem(required, {k, v.isEmpty() ? QStringLiteral("—") : v});
        };
        item(QStringLiteral("源 MAC"), txt(r.sourceMac));
        item(QStringLiteral("目的 MAC"), txt(r.destinationMac));
        item(QStringLiteral("以太网类型"),
             r.etherType ? QString("0x%1").arg(*r.etherType, 4, 16, QChar('0')) : QString());
        item(QStringLiteral("源 IP"), txt(r.sourceIp));
        item(QStringLiteral("目的 IP"), txt(r.destinationIp));
        item(QStringLiteral("IP 版本"), r.ipVersion ? QString::number(*r.ipVersion) : QString());
        item(r.ipVersion == 6 ? "Hop Limit" : "TTL", r.ttlOrHopLimit ? QString::number(*r.ttlOrHopLimit) : QString());
        item(r.ipVersion == 6 ? "Next Header" : "Protocol", r.ipProtocol ? QString::number(*r.ipProtocol) : QString());
        item(QStringLiteral("源端口"), r.sourcePort ? QString::number(*r.sourcePort) : QString());
        item(QStringLiteral("目的端口"), r.destinationPort ? QString::number(*r.destinationPort) : QString());
        if (r.tcpFlags)
            for (const auto &flag :
                 std::array<std::pair<const char *, int>, 4>{{{"SYN", 2}, {"ACK", 16}, {"FIN", 1}, {"RST", 4}}})
                item(flag.first, QString::number((*r.tcpFlags & flag.second) ? 1 : 0));
        required->setExpanded(true);
        QStringList sections{
            QStringLiteral("%1 · %2\n\n时间：%3\n源：%4\n目的：%5\n原始长度：%6 B\n捕获长度：%7 B")
                .arg(protocolName(r), parseName(r.status),
                     QDateTime::fromMSecsSinceEpoch(
                         std::chrono::duration_cast<std::chrono::milliseconds>(r.timestamp.time_since_epoch()).count())
                         .toString(Qt::ISODateWithMs),
                     txt(r.sourceIp), txt(r.destinationIp), num(r.originalLength), num(r.capturedLength))};
        // Addresses are already shown above; keep only summaries with additional information.
        if (!r.summary.empty() && r.summary != r.sourceIp + " -> " + r.destinationIp)
            sections << txt(r.summary);
        if (!r.diagnostic.empty())
            sections << txt(r.diagnostic);
        sections << QStringLiteral("仅展示解析字段；原始报文通过 PCAP 保存。");
        summary->setText(sections.join("\n\n"));
    }
    void tick()
    {
        const double interval = guiTick.restart();
        double previous = guiDelay.load();
        const auto delay = std::max(0., interval - 100.);
        while (previous < delay && !guiDelay.compare_exchange_weak(previous, delay))
        {
        }
        const auto old = snapshot;
        snapshot = backend.snapshot();
        if (old.sessionId != snapshot.sessionId)
        {
            model->clear();
            tree->clear();
            summary->clear();
            sessionClock.start();
            sessionStarted = QDateTime::currentDateTime();
            sessionElapsed = 0;
        }
        if (active() || old.state == ProcessingState::Running || old.state == ProcessingState::Paused)
            sessionElapsed = sessionClock.isValid() ? sessionClock.elapsed() : 0;
        std::uint64_t selected = 0;
        if (const auto *p = model->packet(table->currentIndex().row()))
            selected = p->record.sequence;
        auto batch = backend.takePackets();
        if (batch.sessionId == snapshot.sessionId && !batch.packets.empty())
        {
            model->append(std::move(batch.packets));
            bool restored = false;
            for (int row = 0; row < model->rowCount(); ++row)
                if (model->packet(row)->record.sequence == selected)
                {
                    table->selectRow(row);
                    restored = true;
                    break;
                }
            if (!restored)
            {
                tree->clear();
                summary->clear();
            }
            if (follow->isChecked())
                table->scrollToBottom();
        }
        listEvicted.store(model->evicted());
        guiSession.store(snapshot.sessionId);
        count->setText(QStringLiteral("会话累计 %1 包  |  列表保留最近 %2 条（最多 2000）  |  当前筛选显示 %3 条")
                           .arg(snapshot.statistics.totalPackets)
                           .arg(model->retained())
                           .arg(model->rowCount()));
        metrics[0]->setText(num(snapshot.statistics.totalPackets));
        metrics[1]->setText(mib(snapshot.statistics.totalBytes));
        metrics[2]->setText(QString::number(snapshot.rate.packetsPerSecond, 'f', 1) + " pkt/s");
        metrics[3]->setText(QString::number(snapshot.rate.bytesPerSecond / 1024, 'f', 1) + " KiB/s");
        updateTimeBar();
        updateControls();
    }
    void logStart()
    {
        QMetaObject::invokeMethod(
            worker,
            [this] {
                QString root = qEnvironmentVariable("FLOWGUARD_LOG_ROOT");
                const bool customRoot = !root.isEmpty();
                if (root.isEmpty())
                    root = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation) + "/runs";
                recorder.open(root);
                QMetaObject::invokeMethod(
                    w,
                    [this, path = recorder.directory(), err = recorder.error(), customRoot] {
                        recordPath = path;
                        recordLocationDescription = customRoot ? QStringLiteral("指定的日志目录")
                                                               : QStringLiteral("当前用户的应用数据目录（自动创建）");
                        recordError = err;
                    },
                    Qt::QueuedConnection);
                recorderTimer = new QTimer(worker);
                recorderTimer->setInterval(1000);
                QObject::connect(recorderTimer, &QTimer::timeout, worker, [this] {
                    const auto s = backend.snapshot();
                    const auto r = sampleResources();
                    recorder.sample(s, r, guiDelay.exchange(0),
                                    guiSession.load() == s.sessionId ? listEvicted.load() : 0);
                    const auto key =
                        num(s.sessionId) + ":" + QString::number(int(s.state)) + ":" + QString::number(s.savingActive);
                    if (key != lastState)
                    {
                        recorder.event("session_state", {{"session_id", num(s.sessionId)},
                                                         {"state", int(s.state)},
                                                         {"source", int(s.source)},
                                                         {"saving_active", s.savingActive}});
                        lastState = key;
                    }
                    if (txt(s.error.message) != lastSourceError)
                    {
                        lastSourceError = txt(s.error.message);
                        if (!lastSourceError.isEmpty())
                            recorder.event("source_error", {{"message", lastSourceError}});
                    }
                    if (txt(s.savingError.message) != lastSavingError)
                    {
                        lastSavingError = txt(s.savingError.message);
                        if (!lastSavingError.isEmpty())
                            recorder.event("saving_error", {{"message", lastSavingError}});
                    }
                    QMetaObject::invokeMethod(
                        w,
                        [this, r, err = recorder.error()] {
                            resource = r;
                            recordError = err;
                            resourceHistory.push_back({uptime.elapsed() / 1000., r});
                            if (resourceHistory.size() > 3600)
                                resourceHistory.pop_front();
                        },
                        Qt::QueuedConnection);
                });
                recorderTimer->start();
            },
            Qt::QueuedConnection);
    }
    void updateTimeBar()
    {
        const bool file = snapshot.source == ProcessingSource::File;
        timeBar[0]->setText(QStringLiteral("当前时间：") +
                            QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss"));
        timeBar[1]->setText(
            (file ? QStringLiteral("本次文件处理开始：") : QStringLiteral("本次采集开始：")) +
            (sessionStarted.isValid() ? sessionStarted.toString("yyyy-MM-dd HH:mm:ss") : QStringLiteral("—")));
        timeBar[2]->setText((file ? QStringLiteral("本次文件处理时长：") : QStringLiteral("本次采集时长：")) +
                            (sessionStarted.isValid() ? duration(sessionElapsed / 1000) : QStringLiteral("—")));
    }
    void updateSecond()
    {
        if (pages->currentIndex() == 1)
            charts->refresh(snapshot, sourceDescription);
        auto opt = [](const auto &n) { return n ? QString::number(*n) : QStringLiteral("不可用"); };
        updateTimeBar();
        resourceMetrics[0]->setText(resource.cpuPercent ? QString::number(*resource.cpuPercent, 'f', 2) + " %"
                                                        : QStringLiteral("不可用"));
        resourceMetrics[1]->setText(resource.workingSetBytes ? mib(*resource.workingSetBytes)
                                                             : QStringLiteral("不可用"));
        resourceMetrics[2]->setText(resource.processReadBytes ? mib(*resource.processReadBytes)
                                                              : QStringLiteral("不可用"));
        resourceMetrics[3]->setText(resource.processWriteBytes ? mib(*resource.processWriteBytes)
                                                               : QStringLiteral("不可用"));
        resourcesText->setText(
            QStringLiteral("<table cellspacing='0' cellpadding='0'>"
                           "<tr><td style='padding-right:28px'>驱动接收 %1 包</td>"
                           "<td style='padding-right:28px'>驱动丢弃 %2 包</td>"
                           "<td style='padding-right:28px'>接口丢弃 %3 包</td><td>已保存 %4 包</td></tr></table>"
                           "CPU 占整机能力；I/O 是进程累计读写量，不是物理磁盘吞吐。")
                .arg(opt(snapshot.capture.driverReceived), opt(snapshot.capture.driverDropped),
                     opt(snapshot.capture.interfaceDropped), num(snapshot.savedPackets)));
        const QString saving = snapshot.savingActive      ? QStringLiteral("保存中")
                               : snapshot.savingRequested ? QStringLiteral("等待首包/准备保存")
                                                          : QStringLiteral("未保存");
        recordLabel->setText(
            QStringLiteral("报文保存状态：%1\n屏幕最多 3600 点；完整日志持续写盘。过旧离线时间桶 %2 包")
                .arg(saving, num(snapshot.lateHistoryPackets)));
        recordLabel->setToolTip(recordPath);
        QList<QPointF> cpu, memory;
        for (const auto &p : resourceHistory)
        {
            if (p.second.cpuPercent)
                cpu.append({p.first, *p.second.cpuPercent});
            if (p.second.workingSetBytes)
                memory.append({p.first, double(*p.second.workingSetBytes) / 1024 / 1024});
        }
        if (pages->currentIndex() == 2)
        {
            auto replace = [](QChartView *v, QChart *c) {
                auto *old = v->chart();
                v->setChart(c);
                delete old;
            };
            replace(cpuView, lineChart(QStringLiteral("CPU 占用"), cpu, QStringLiteral("记录经过秒"), "%",
                                       QColor("#07968e"), true));
            replace(memoryView, lineChart(QStringLiteral("内存占用"), memory, QStringLiteral("记录经过秒"), "MiB",
                                          QColor("#4285ed")));
        }
        updateControls();
    }
};
MainWindow::MainWindow(const QString &version, QWidget *parent) : QMainWindow(parent), d(std::make_unique<Impl>(this))
{
    setWindowTitle(QStringLiteral("FlowGuard 流量哨兵"));
    setMinimumSize(1100, 720);
    resize(1440, 960);
    setWindowIcon(QIcon(":/flowguard.png"));
    setStyleSheet(
        "QMainWindow,QWidget{background:#f4f7fb;color:#172639;font-family:'Microsoft YaHei UI';font-size:10pt;} "
        "QToolBar{spacing:8px;padding:8px;border-bottom:1px solid #d5dfea;} QPushButton{background:white;border:1px "
        "solid #cad6e3;border-radius:5px;padding:7px 12px;} QPushButton:hover{background:#e0f2f1;} "
        "QPushButton:disabled{color:#9da7b3;background:#edf0f4;} "
        "QPushButton#primary:enabled{background:#087f83;color:white;} "
        "QPushButton#primary:disabled{background:#e1e6ec;color:#8a95a3;border:1px solid #cad6e3;} "
        "QLabel#metric{font-size:19pt;font-weight:600;color:#123348;} "
        "QLineEdit,QComboBox,QSpinBox,QDoubleSpinBox{background:white;border:1px solid "
        "#cad6e3;border-radius:4px;padding:5px;} "
        "QSpinBox:disabled,QDoubleSpinBox:disabled,QComboBox:disabled,QLineEdit:disabled{color:#929daa;background:#"
        "edf0f4;} QCheckBox:disabled{color:#929daa;} "
        "QTableView,QTreeWidget{background:white;alternate-background-color:#f0f5fa;border:1px solid "
        "#cad6e3;selection-background-color:#c6e3fa;selection-color:#102a43;} "
        "QHeaderView::section{background:#eaf0f7;padding:6px;border:0;border-bottom:1px solid #cad6e3;} "
        "QListWidget{border:0;background:#edf4f8;} QListWidget::item{padding:16px 10px;} "
        "QListWidget::item:selected{background:#d2eeeb;color:#087f83;}");
    auto *file = menuBar()->addMenu(QStringLiteral("文件"));
    auto *fileAction = file->addAction(QStringLiteral("打开 PCAP…"));
    fileAction->setShortcut(QKeySequence::Open);
    connect(fileAction, &QAction::triggered, this, [this] { d->chooseFile(); });
    file->addSeparator();
    connect(file->addAction(QStringLiteral("退出")), &QAction::triggered, this, &QWidget::close);
    auto *help = menuBar()->addMenu(QStringLiteral("帮助"));
    connect(help->addAction(QStringLiteral("关于")), &QAction::triggered, this, [this, version] {
        QMessageBox::information(
            this, QStringLiteral("关于 FlowGuard"),
            QStringLiteral("流量哨兵 · Qt %1\n%2\n显示筛选只影响列表，不影响统计及保存。").arg(qVersion(), version));
    });
    auto *toolbar = addToolBar(QStringLiteral("采集与文件"));
    toolbar->setMovable(false);
    d->devices = new DeviceSelector;
    toolbar->addWidget(d->devices);
    auto button = [toolbar](const QString &label) {
        auto *b = new QPushButton(label);
        toolbar->addWidget(b);
        return b;
    };
    d->refresh = button(QStringLiteral("刷新网卡"));
    d->refresh->setToolTip(
        QStringLiteral("重新读取网卡列表、IP 和连接状态，不清空报文及统计。插拔网线或启停 VPN 后可刷新；采集中锁定。"));
    d->start = button(QStringLiteral("开始采集"));
    d->start->setObjectName("primary");
    d->stop = button(QStringLiteral("停止"));
    d->open = button(QStringLiteral("打开 PCAP"));
    d->pause = button(QStringLiteral("暂停回放"));
    d->pauseAction = toolbar->actions().back();
    d->save = button(QStringLiteral("保存后续报文"));
    d->state = new QLabel;
    toolbar->addWidget(d->state);
    auto *central = new QWidget;
    setCentralWidget(central);
    auto *outer = new QVBoxLayout(central);
    auto *capture = new QHBoxLayout;
    capture->addWidget(new QLabel(QStringLiteral("捕获过滤 BPF")));
    d->bpf = new QLineEdit;
    d->bpf->setPlaceholderText(QStringLiteral("udp or tcp（留空不过滤）"));
    capture->addWidget(d->bpf, 1);
    d->promiscuous = new QCheckBox(QStringLiteral("混杂模式"));
    capture->addWidget(d->promiscuous);
    capture->addWidget(new QLabel(QStringLiteral("截取长度")));
    d->snaplen = new QSpinBox;
    d->snaplen->setObjectName("snapshotLength");
    d->snaplen->setToolTip(
        QStringLiteral("每个报文最多截取的字节数。仅开始采集前可修改，采集中锁定；默认 65535 字节。"));
    d->snaplen->setRange(1, 16 * 1024 * 1024);
    d->snaplen->setValue(65535);
    // Separate real button widgets avoid platform-style arrow/edit hit-region mismatches.
    d->snaplen->setButtonSymbols(QAbstractSpinBox::NoButtons);
    d->snaplen->setFixedWidth(100);
    d->snapshotControl = new QWidget;
    auto *lengthLayout = new QHBoxLayout(d->snapshotControl);
    lengthLayout->setContentsMargins(0, 0, 0, 0);
    lengthLayout->setSpacing(0);
    lengthLayout->addWidget(d->snaplen);
    d->snapshotUp = new QToolButton;
    d->snapshotDown = new QToolButton;
    d->snapshotUp->setObjectName("snapshotIncrease");
    d->snapshotDown->setObjectName("snapshotDecrease");
    d->snapshotUp->setText(QStringLiteral("▲"));
    d->snapshotDown->setText(QStringLiteral("▼"));
    d->snapshotUp->setToolTip(QStringLiteral("增加截取长度"));
    d->snapshotDown->setToolTip(QStringLiteral("减少截取长度"));
    for (auto *step : {d->snapshotUp, d->snapshotDown})
    {
        step->setFixedSize(28, 32);
        step->setCursor(Qt::ArrowCursor);
        step->setAutoRepeat(true);
        step->setStyleSheet(
            "QToolButton{background:white;border:1px solid #cad6e3;color:#172639;} "
            "QToolButton:hover{background:#e0f2f1;} QToolButton:disabled{background:#edf0f4;color:#9da7b3;}");
        lengthLayout->addWidget(step);
    }
    connect(d->snapshotUp, &QToolButton::clicked, d->snaplen, &QSpinBox::stepUp);
    connect(d->snapshotDown, &QToolButton::clicked, d->snaplen, &QSpinBox::stepDown);
    connect(d->snaplen, &QSpinBox::valueChanged, this, [this] { d->updateControls(); });
    capture->addWidget(d->snapshotControl);
    outer->addLayout(capture);
    connect(d->devices, &QComboBox::currentIndexChanged, this,
            [this] { d->devices->setToolTip(d->devices->currentData(Qt::ToolTipRole).toString()); });
    d->error = new QLabel;
    d->error->setWordWrap(true);
    d->error->setStyleSheet("color:#9b361f;background:#fff0db;padding:8px;");
    outer->addWidget(d->error);
    auto *body = new QHBoxLayout;
    outer->addLayout(body, 1);
    auto *nav = new QListWidget;
    nav->addItems({QStringLiteral("报文工作台"), QStringLiteral("统计分析"), QStringLiteral("资源监控")});
    nav->setFixedWidth(150);
    body->addWidget(nav);
    d->pages = new QStackedWidget;
    body->addWidget(d->pages, 1);
    auto *bench = new QWidget;
    auto *layout = new QVBoxLayout(bench);
    auto *metricRow = new QHBoxLayout;
    QStringList titles{QStringLiteral("累计报文"), QStringLiteral("累计原始流量"), QStringLiteral("当前包速率"),
                       QStringLiteral("当前字节速率")};
    for (int i = 0; i < 4; ++i)
    {
        auto *card = new QVBoxLayout;
        card->addWidget(new QLabel(titles[i]));
        d->metrics[i] = new QLabel("0");
        d->metrics[i]->setObjectName("metric");
        card->addWidget(d->metrics[i]);
        metricRow->addLayout(card, 1);
    }
    layout->addLayout(metricRow);
    auto *filter = new QHBoxLayout;
    filter->addWidget(new QLabel(QStringLiteral("显示筛选")));
    d->protocol = new QComboBox;
    d->protocol->setObjectName("protocolFilter");
    d->protocol->addItems({QStringLiteral("全部协议"), "IPv4", "IPv6", "ARP", "TCP", "UDP", "DNS", "Other"});
    filter->addWidget(d->protocol);
    d->ip = new QLineEdit;
    d->ip->setObjectName("ipFilter");
    d->ip->setPlaceholderText(QStringLiteral("源或目的 IP"));
    filter->addWidget(d->ip, 1);
    d->port = new QLineEdit;
    d->port->setObjectName("portFilter");
    d->port->setPlaceholderText(QStringLiteral("源或目的端口"));
    filter->addWidget(d->port);
    auto *apply = new QPushButton(QStringLiteral("应用"));
    auto *reset = new QPushButton(QStringLiteral("重置"));
    filter->addWidget(apply);
    filter->addWidget(reset);
    layout->addLayout(filter);
    auto *split = new QSplitter(Qt::Vertical);
    d->model = new PacketModel(this);
    d->table = new QTableView;
    d->table->setObjectName("packetTable");
    d->table->setModel(d->model);
    d->table->setAlternatingRowColors(true);
    d->table->setSelectionBehavior(QAbstractItemView::SelectRows);
    d->table->setSelectionMode(QAbstractItemView::SingleSelection);
    d->table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    d->table->verticalHeader()->hide();
    d->table->horizontalHeader()->setStretchLastSection(true);
    for (int i = 0; i < 7; ++i)
        d->table->setColumnWidth(i, i == 2 || i == 3 ? 175 : i == 1 ? 115 : 75);
    split->addWidget(d->table);
    auto *details = new QSplitter;
    d->tree = new QTreeWidget;
    d->tree->setObjectName("protocolFields");
    d->tree->setHeaderLabels({QStringLiteral("协议字段"), QStringLiteral("值")});
    d->tree->setColumnWidth(0, 220);
    details->addWidget(d->tree);
    d->summary = new QLabel;
    d->summary->setObjectName("packetSummary");
    d->summary->setWordWrap(true);
    d->summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    auto *summaryScroll = new QScrollArea;
    summaryScroll->setWidgetResizable(true);
    summaryScroll->setWidget(d->summary);
    d->summary->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    d->summary->setMargin(12);
    summaryScroll->setMinimumWidth(280);
    details->addWidget(summaryScroll);
    details->setStretchFactor(0, 3);
    details->setStretchFactor(1, 2);
    details->setSizes({600, 400});
    split->addWidget(details);
    split->setSizes({330, 350});
    layout->addWidget(split, 1);
    auto *below = new QHBoxLayout;
    d->count = new QLabel;
    d->count->setWordWrap(true);
    d->count->setToolTip(
        QStringLiteral("会话累计是后台处理的全部报文；列表只缓存最近 2000 "
                       "条，筛选显示数仅针对这些缓存记录。较旧记录离开列表不会改变统计，也不影响已开启的 PCAP 保存。"));
    below->addWidget(d->count, 1);
    d->follow = new QCheckBox(QStringLiteral("自动滚动"));
    d->follow->setChecked(true);
    below->addWidget(d->follow);
    layout->addLayout(below);
    d->pages->addWidget(bench);
    d->charts = new ChartPanel;
    auto *chartScroll = new QScrollArea;
    chartScroll->setWidgetResizable(true);
    chartScroll->setWidget(d->charts);
    d->pages->addWidget(chartScroll);
    auto *res = new QWidget;
    auto *resLayout = new QVBoxLayout(res);
    auto *heading = new QLabel(QStringLiteral("资源监控"));
    heading->setObjectName("metric");
    resLayout->addWidget(heading);
    auto *resMetrics = new QHBoxLayout;
    const QStringList resTitles{QStringLiteral("CPU 占用"), QStringLiteral("内存占用"), QStringLiteral("累计读取"),
                                QStringLiteral("累计写入")};
    const QStringList resHints{QStringLiteral("本程序占整机处理能力的比例，不是所有程序的 CPU 使用率。"),
                               QStringLiteral("本程序当前使用的物理内存，技术名称为工作集。"),
                               QStringLiteral("本程序自启动以来累计的进程读取量，不等于抓包流量。"),
                               QStringLiteral("本程序自启动以来累计的进程写入量，不等于 PCAP 文件大小。")};
    for (int i = 0; i < 4; ++i)
    {
        auto *card = new QVBoxLayout;
        auto *title = new QLabel(resTitles[i]);
        title->setToolTip(resHints[i]);
        card->addWidget(title);
        d->resourceMetrics[i] = new QLabel("—");
        d->resourceMetrics[i]->setObjectName("metric");
        d->resourceMetrics[i]->setToolTip(resHints[i]);
        card->addWidget(d->resourceMetrics[i]);
        resMetrics->addLayout(card, 1);
    }
    resLayout->addLayout(resMetrics);
    d->resourcesText = new QLabel;
    d->resourcesText->setTextInteractionFlags(Qt::TextSelectableByMouse);
    resLayout->addWidget(d->resourcesText);
    auto *plots = new QHBoxLayout;
    d->cpuView = new QChartView;
    d->memoryView = new QChartView;
    for (auto *view : {d->cpuView, d->memoryView})
    {
        view->setMinimumHeight(250);
        view->setRenderHint(QPainter::Antialiasing);
        plots->addWidget(view);
    }
    resLayout->addLayout(plots, 1);
    d->recordLabel = new QLabel;
    d->recordLabel->setWordWrap(true);
    resLayout->addWidget(d->recordLabel);
    auto *folder = new QPushButton(QStringLiteral("打开运行日志目录"));
    folder->setToolTip(
        QStringLiteral("打开当前电脑上本次运行的日志目录。每位用户使用自己的存储位置，不依赖开发者用户名。"));
    resLayout->addWidget(folder);
    auto *resScroll = new QScrollArea;
    resScroll->setWidgetResizable(true);
    resScroll->setWidget(res);
    d->pages->addWidget(resScroll);
    auto *bottom = statusBar();
    bottom->setSizeGripEnabled(false);
    bottom->setStyleSheet("QStatusBar{border-top:1px solid #cad6e3;background:#edf3f8;} QStatusBar::item{border:0;} "
                          "QLabel{padding:5px 8px;background:transparent;}");
    for (int i = 0; i < 3; ++i)
    {
        d->timeBar[i] = new QLabel;
        d->timeBar[i]->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        bottom->addWidget(d->timeBar[i], 1);
    }
    d->sessionTime = d->timeBar[2];
    d->sessionTime->setObjectName("sessionDuration");
    connect(nav, &QListWidget::currentRowChanged, this, [this](int index) {
        d->pages->setCurrentIndex(index);
        d->updateSecond();
    });
    nav->setCurrentRow(0);
    connect(d->refresh, &QPushButton::clicked, this, [this] { d->refreshDevices(); });
    connect(d->start, &QPushButton::clicked, this,
            [this] { startDevice(d->devices->currentData().toString(), d->bpf->text()); });
    connect(d->stop, &QPushButton::clicked, this, &MainWindow::requestStop);
    connect(d->open, &QPushButton::clicked, this, [this] { d->chooseFile(); });
    connect(d->pause, &QPushButton::clicked, this, [this] {
        const bool paused = d->snapshot.state == ProcessingState::Paused;
        d->command("pause_resume", [this, paused] { return paused ? d->backend.resume() : d->backend.pause(); });
    });
    connect(d->save, &QPushButton::clicked, this, [this] {
        if (d->snapshot.savingActive || d->snapshot.savingRequested)
        {
            d->command("disable_saving", [this] {
                d->backend.disableSaving();
                return OperationResult{};
            });
            return;
        }
        const auto path = QFileDialog::getSaveFileName(this, QStringLiteral("保存后续原始报文（不覆盖已有文件）"), {},
                                                       "PCAP (*.pcap)");
        if (!path.isEmpty())
            d->command("enable_saving",
                       [this, path] { return d->backend.enableSaving(std::filesystem::path(path.toStdWString())); },
                       {{"path", path}, {"max_bytes", "1073741824"}});
    });
    connect(apply, &QPushButton::clicked, this, [this] { d->applyFilter(); });
    connect(reset, &QPushButton::clicked, this, [this] {
        d->protocol->setCurrentIndex(0);
        d->ip->clear();
        d->port->clear();
        d->applyFilter();
    });
    connect(d->table->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex &i) { d->showPacket(i.row()); });
    connect(d->table->verticalScrollBar(), &QScrollBar::sliderPressed, this, [this] { d->follow->setChecked(false); });
    connect(folder, &QPushButton::clicked, this,
            [this] { QDesktopServices::openUrl(QUrl::fromLocalFile(d->recordPath)); });
    connect(d->poll, &QTimer::timeout, this, [this] { d->tick(); });
    d->poll->start(100);
    connect(d->second, &QTimer::timeout, this, [this] { d->updateSecond(); });
    d->second->start(1000);
    d->logStart();
    d->updateControls();
    d->refreshDevices();
}
MainWindow::~MainWindow()
{
    d->poll->stop();
    d->second->stop();
    if (d->thread.isRunning())
    {
        QMetaObject::invokeMethod(
            d->worker,
            [this] {
                if (d->recorderTimer)
                    d->recorderTimer->stop();
                d->backend.stop();
                d->recorder.finish(d->backend.snapshot());
            },
            Qt::BlockingQueuedConnection);
        d->thread.quit();
        d->thread.wait();
    }
}
void MainWindow::openFile(const QString &path, bool paced, double speed)
{
    if (d->active() || d->busy)
        return;
    if (d->snapshot.statistics.totalPackets && !qEnvironmentVariableIsSet("FLOWGUARD_ACCEPTANCE") &&
        QMessageBox::question(this, QStringLiteral("新会话"), QStringLiteral("新会话将替换当前列表与统计，继续？")) !=
            QMessageBox::Yes)
        return;
    ProcessingOptions options;
    options.pacedReplay = paced;
    options.replaySpeed = speed;
    d->sourceDescription = QStringLiteral("文件：") + path +
                           (paced ? QStringLiteral(" · 按捕获时间回放 %1×").arg(speed) : QStringLiteral(" · 快速导入"));
    d->command(
        "start_file",
        [this, path, options] { return d->backend.startFile(std::filesystem::path(path.toStdWString()), options); },
        {{"path", path}, {"paced", paced}, {"speed", speed}});
}
void MainWindow::startDevice(const QString &id, const QString &bpf, const QString &initialSavePath)
{
    if (d->active() || d->busy)
        return;
    if (d->snapshot.statistics.totalPackets && !qEnvironmentVariableIsSet("FLOWGUARD_ACCEPTANCE") &&
        QMessageBox::question(this, QStringLiteral("新会话"), QStringLiteral("新会话将替换当前列表与统计，继续？")) !=
            QMessageBox::Yes)
        return;
    CaptureOptions options;
    options.deviceId = id.toStdString();
    options.bpfExpression = bpf.toStdString();
    options.promiscuous = d->promiscuous->isChecked();
    options.snapshotLength = std::uint32_t(d->snaplen->value());
    const int selected = d->devices->findData(id);
    if (selected >= 0)
        d->devices->setCurrentIndex(selected);
    d->sourceDescription = QStringLiteral("实时采集：") + (selected >= 0 ? d->devices->itemText(selected) : id);
    ProcessingOptions processing;
    if (!initialSavePath.isEmpty())
        processing.savePath = std::filesystem::path(initialSavePath.toStdWString());
    d->command("start_live", [this, options, processing] { return d->backend.startLive(options, processing); },
               {{"device", id},
                {"bpf", bpf},
                {"promiscuous", options.promiscuous},
                {"snapshot_length", int(options.snapshotLength)}});
}
void MainWindow::requestStop()
{
    d->command("stop", [this] {
        d->backend.stop();
        return OperationResult{};
    });
}
bool MainWindow::fileCompleted() const
{
    return d->snapshot.source == ProcessingSource::File && d->snapshot.state == ProcessingState::Completed;
}
quint64 MainWindow::totalPackets() const
{
    return d->snapshot.statistics.totalPackets;
}
QString MainWindow::logDirectory() const
{
    return d->recordPath;
}
bool MainWindow::saveScreenshot(const QString &path)
{
    return grab().save(path);
}
void MainWindow::closeEvent(QCloseEvent *event)
{
    if (d->allowClose)
    {
        event->accept();
        return;
    }
    event->ignore();
    if (d->closing)
        return;
    if (d->active() && !qEnvironmentVariableIsSet("FLOWGUARD_ACCEPTANCE") &&
        QMessageBox::question(this, QStringLiteral("结束运行"), QStringLiteral("停止当前会话并关闭保存后退出？")) !=
            QMessageBox::Yes)
        return;
    d->closing = true;
    d->updateControls();
    d->poll->stop();
    d->second->stop();
    QMetaObject::invokeMethod(
        d->worker,
        [this] {
            if (d->recorderTimer)
                d->recorderTimer->stop();
            d->backend.stop();
            const auto final = d->backend.snapshot();
            d->recorder.sample(final, sampleResources(), d->guiDelay.load(),
                               d->guiSession.load() == final.sessionId ? d->listEvicted.load() : 0);
            d->recorder.finish(final);
            const auto err = d->recorder.error();
            QMetaObject::invokeMethod(
                this,
                [this, err, saveError = txt(final.savingError.message)] {
                    if (!qEnvironmentVariableIsSet("FLOWGUARD_ACCEPTANCE") && (!err.isEmpty() || !saveError.isEmpty()))
                        QMessageBox::warning(this, QStringLiteral("退出时发现错误"), err + '\n' + saveError);
                    d->allowClose = true;
                    close();
                },
                Qt::QueuedConnection);
        },
        Qt::QueuedConnection);
}
} // namespace flowguard
