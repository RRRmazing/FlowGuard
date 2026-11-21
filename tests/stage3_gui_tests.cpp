// Primary author: Xie Fuxiang. AI-assisted integration tests, pending user review.
#include "core/module_contracts.h"
#include "ui/chart_panel.h"
#include "ui/main_window.h"
#include <QTemporaryDir>
#include <QUdpSocket>
#include <QtCharts/QLineSeries>
#include <QtCharts/QPieSeries>
#include <QtCharts/QValueAxis>
#include <QtTest/QTest>
#include <QtWidgets>
#include <cmath>
#include <iostream>

static int failures = 0;
static void check(bool value, const char *name)
{
    if (!value)
    {
        std::cerr << "FAIL " << name << '\n';
        ++failures;
    }
}
static QPushButton *button(QWidget &w, const QString &label)
{
    for (auto *b : w.findChildren<QPushButton *>())
        if (b->text() == label)
            return b;
    return nullptr;
}
static bool wait(const std::function<bool()> &predicate, int ms = 4000)
{
    return QTest::qWaitFor(predicate, ms);
}
int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    {
        flowguard::ChartPanel panel;
        flowguard::ProcessingSnapshot s;
        panel.refresh(s);
        auto view = [&](int i) { return panel.findChild<QChartView *>(QString("statisticsChart%1").arg(i)); };
        check(view(2)->chart()->title().contains(QStringLiteral("暂无数据")) &&
                  view(3)->chart()->title().contains(QStringLiteral("暂无数据")),
              "empty statistics have explicit empty states");
        s.statistics.totalPackets = 3;
        s.statistics.lengthFrequency = {{60, 3}};
        s.statistics.lengthGroups = {0, 3, 0};
        s.statistics.networkCounts[flowguard::NetworkProtocol::IPv4] = 3;
        panel.refresh(s, QStringLiteral("test.pcap"));
        auto *line = qobject_cast<QLineSeries *>(view(2)->chart()->series().front());
        check(line && line->count() == 1 && line->pointsVisible(), "single length remains visible as a point");
        for (int i : {2, 3, 4, 6})
        {
            auto *axis = qobject_cast<QValueAxis *>(view(i)->chart()->axes(Qt::Vertical).front());
            const double step = (axis->max() - axis->min()) / (axis->tickCount() - 1);
            check(std::abs(step - std::round(step)) < 1e-8 && axis->labelFormat() == "%.0f",
                  "packet count ticks are integers");
        }
        s.statistics.lengthFrequency = {{60, 1}, {100, 2}};
        s.history.push_back({std::chrono::system_clock::now(), 1, {3, 200, 1. / 3.}, {}, {}});
        panel.refresh(s, QStringLiteral("test.pcap"));
        line = qobject_cast<QLineSeries *>(view(2)->chart()->series().front());
        check(line->points().contains(QPointF(61, 0)) && line->points().contains(QPointF(99, 0)),
              "missing lengths have zero frequency instead of interpolated counts");
        auto *pie = qobject_cast<QPieSeries *>(view(5)->chart()->series().front());
        check(pie->slices().front()->label().contains(QStringLiteral("3 包")), "pie labels include counts");
        check(panel.findChild<QLabel *>("statisticsScope")->text().contains(QStringLiteral("test.pcap")) &&
                  panel.findChild<QLabel *>("statisticsScope")->text().contains("3600"),
              "statistics identify source and recent window limit");
        auto *dnsAxis = qobject_cast<QValueAxis *>(view(7)->chart()->axes(Qt::Vertical).front());
        check(dnsAxis->min() == 0 && dnsAxis->max() == 100, "DNS remains a percentage axis");
    }
    if (argc < 2)
        return 2;
    QTemporaryDir temp;
    qputenv("FLOWGUARD_LOG_ROOT", temp.path().toUtf8());
    qputenv("FLOWGUARD_ACCEPTANCE", "1");
    {
        flowguard::MainWindow w("integration-test");
        w.show();
        QTest::qWait(500);
        auto *adapters = w.findChild<QComboBox *>("captureDevice");
        check(adapters && wait([&] { return adapters->count() > 0; }), "capture selector populated");
        check(wait([&] { return button(w, QStringLiteral("开始采集"))->isEnabled(); }), "initial controls ready");
        auto *snaplen = w.findChild<QSpinBox *>("snapshotLength");
        check(snaplen && snaplen->isEnabled(), "snapshot length editable while idle");
        auto *increase = w.findChild<QToolButton *>("snapshotIncrease");
        auto *decrease = w.findChild<QToolButton *>("snapshotDecrease");
        check(increase && decrease, "independent snapshot step buttons exist");
        if (snaplen && increase && decrease)
        {
            snaplen->setValue(65533);
            const QList<QPoint> points{increase->rect().center(), QPoint(4, increase->height() / 2),
                                       QPoint(increase->width() - 5, increase->height() / 2)};
            for (const auto &point : points)
                QTest::mouseClick(increase, Qt::LeftButton, Qt::NoModifier, point);
            check(snaplen->value() == 65536, "visible up button works across its hit region");
            check(increase->cursor().shape() == Qt::ArrowCursor &&
                      !increase->geometry().intersects(snaplen->geometry()),
                  "up button is outside text edit region");
            QTest::mouseClick(decrease, Qt::LeftButton);
            check(snaplen->value() == 65535, "visible down button decrements");
        }
        const auto available = flowguard::enumerateDevices();
        check(available.result.ok() && adapters && adapters->count() == int(available.devices.size()),
              "UI includes every Npcap device without filtering");
        if (adapters)
            for (const auto &device : available.devices)
                check(adapters->findData(QString::fromStdString(device.id)) >= 0, "Npcap stable ID present in UI");
        const auto previewDirectory = qEnvironmentVariable("FLOWGUARD_SELECTOR_PREVIEW_DIR");
        if (adapters && !previewDirectory.isEmpty())
        {
            QDir().mkpath(previewDirectory);
            adapters->showPopup();
            QTest::qWait(100);
            adapters->view()->window()->grab().save(previewDirectory + "/devices.png");
            adapters->hidePopup();
            w.saveScreenshot(previewDirectory + "/selection.png");
        }
        auto *table = w.findChild<QTableView *>("packetTable");
        auto *tree = w.findChild<QTreeWidget *>("protocolFields");
        auto *protocol = w.findChild<QComboBox *>("protocolFilter");
        auto *ip = w.findChild<QLineEdit *>("ipFilter");
        check(table && tree && protocol && ip, "named UI components");
        w.openFile(QString::fromLocal8Bit(argv[1]), true, .1);
        check(wait([&] { return w.totalPackets() > 0; }), "paced file started");
        check(wait([&] {
                  auto *p = button(w, QStringLiteral("暂停回放"));
                  return p && p->isEnabled();
              }),
              "file control request acknowledged");
        auto *pause = button(w, QStringLiteral("暂停回放"));
        check(pause && pause->isEnabled(), "pause available for file");
        if (pause)
            pause->click();
        check(wait([&] { return button(w, QStringLiteral("继续回放")) != nullptr; }), "paused acknowledged");
        QTest::qWait(100);
        const auto paused = w.totalPackets();
        QTest::qWait(250);
        check(w.totalPackets() == paused, "pause stops progression");
        w.openFile(QString::fromLocal8Bit(argv[1]));
        check(w.totalPackets() == paused, "active source cannot be replaced");
        if (auto *resume = button(w, QStringLiteral("继续回放")))
            resume->click();
        check(wait([&] { return button(w, QStringLiteral("暂停回放")) != nullptr; }), "resume acknowledged");
        w.requestStop();
        check(wait([&] { return button(w, QStringLiteral("打开 PCAP"))->isEnabled(); }), "stop returns to idle");
        w.openFile(QString::fromLocal8Bit(argv[1]));
        check(wait([&] { return w.fileCompleted() && w.totalPackets() == 18; }), "complete fixture exactly18");
        auto *duration = w.findChild<QLabel *>("sessionDuration");
        check(duration && duration->text().contains(QStringLiteral("文件处理时长")), "file time is not capture time");
        check(wait([&] { return table->model()->rowCount() == 18; }), "new session batch delivered");
        table->selectRow(1);
        check(!tree->findItems("SYN", Qt::MatchExactly | Qt::MatchRecursive).isEmpty(), "TCP flags exposed");
        protocol->setCurrentIndex(4);
        button(w, QStringLiteral("应用"))->click();
        check(table->model()->rowCount() > 0 && table->model()->rowCount() < 18, "TCP filter");
        check(w.totalPackets() == 18, "filter does not change totals");
        const auto filtered = table->model()->rowCount();
        ip->setText("invalid");
        button(w, QStringLiteral("应用"))->click();
        check(table->model()->rowCount() == filtered, "bad filter keeps last valid one");
        button(w, QStringLiteral("重置"))->click();
        check(table->model()->rowCount() == 18, "reset restores history");
        protocol->setCurrentIndex(2);
        ip->setText("2001:0db8:0:0:0:0:0:1");
        button(w, QStringLiteral("应用"))->click();
        check(table->model()->rowCount() > 0, "normalized IPv6 filter in GUI");
        button(w, QStringLiteral("重置"))->click();
        const auto nav = w.findChildren<QListWidget *>();
        if (!nav.isEmpty())
            for (int i = 0; i < 3; ++i)
            {
                nav.front()->setCurrentRow(i);
                QTest::qWait(60);
                if (i == 1 && !previewDirectory.isEmpty())
                    w.findChild<QChartView *>("statisticsChart0")
                        ->parentWidget()
                        ->grab()
                        .save(previewDirectory + "/statistics-full.png");
            }
        check(w.totalPackets() == 18, "page changes preserve session");

        // Actual capture through the same Qt control path; localhost-only generated traffic.
        QUdpSocket receiver;
        check(receiver.bind(QHostAddress::LocalHost, 0), "local UDP receiver");
        const auto port = receiver.localPort();
        w.startDevice("\\Device\\NPF_Loopback", QString("udp and dst port %1").arg(port));
        check(wait([&] { return button(w, QStringLiteral("停止"))->isEnabled(); }), "GUI live capture started");
        check(!button(w, QStringLiteral("开始采集"))->isEnabled(), "start disabled while capturing");
        check(snaplen && !snaplen->isEnabled(), "snapshot length locked while capturing");
        QUdpSocket sender;
        for (int i = 0; i < 10; ++i)
        {
            sender.writeDatagram("stage3-local-test", QHostAddress::LocalHost, port);
            QTest::qWait(40);
        }
        check(wait([&] { return w.totalPackets() > 0; }), "GUI live packets received");
        QTest::qWait(1100);
        check(duration && duration->text().contains(QStringLiteral("采集时长")) &&
                  !duration->text().endsWith("00:00:00"),
              "live capture duration advances");
        if (!previewDirectory.isEmpty())
            w.saveScreenshot(previewDirectory + "/capturing.png");
        w.requestStop();
        check(wait([&] { return button(w, QStringLiteral("打开 PCAP"))->isEnabled(); }), "GUI live stopped");
        const QString stoppedDuration = duration ? duration->text() : QString();
        QTest::qWait(1100);
        check(duration && duration->text() == stoppedDuration, "capture duration freezes after stop");
        const auto realDevice = qEnvironmentVariable("FLOWGUARD_REAL_DEVICE");
        if (!realDevice.isEmpty())
        {
            w.startDevice(realDevice);
            check(wait([&] { return button(w, QStringLiteral("停止"))->isEnabled(); }),
                  "real NIC started through Qt controls");
            check(wait([&] { return w.totalPackets() > 0 && table->model()->rowCount() > 0; }, 6000),
                  "real NIC delivers packets into Qt model");
            if (table->model()->rowCount() > 0)
                table->selectRow(0);
            check(!tree->findItems("Ethernet", Qt::MatchExactly | Qt::MatchRecursive).isEmpty(),
                  "real Ethernet headers displayed in Qt tree");
            QTest::qWait(1000);
            w.requestStop();
            check(wait([&] { return button(w, QStringLiteral("打开 PCAP"))->isEnabled(); }),
                  "real NIC stopped through Qt controls");
            if (!previewDirectory.isEmpty())
                w.saveScreenshot(previewDirectory + "/wlan.png");
            std::cout << "REAL_NIC_QT packets=" << w.totalPackets() << '\n';
        }
        check(w.logDirectory().startsWith(temp.path()), "evidence directory connected");
        w.close();
        check(wait([&] { return !w.isVisible(); }), "asynchronous close finished");
        QFile result(w.logDirectory() + "/result.json");
        check(result.exists(), "exit result durable");
    }
    std::cout << "STAGE3_GUI_INTEGRATION " << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
