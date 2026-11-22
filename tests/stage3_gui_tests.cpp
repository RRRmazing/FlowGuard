// Primary author: Xie Fuxiang. AI-assisted integration tests, pending user review.
#include "core/module_contracts.h"
#include "ui/chart_panel.h"
#include "ui/main_window.h"
#include <QTemporaryDir>
#include <QUdpSocket>
#include <QNetworkDatagram>
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
        check(dnsAxis->min() == 0 && dnsAxis->max() > 100./3. && dnsAxis->max() < 100,
              "DNS auto scales its percentage axis with headroom");
        // DNS readout is selected by time across the plot, not by hitting the thin curve.
        panel.resize(1280,1800); panel.show(); QTest::qWait(100);
        auto *dnsView=view(7);
        auto *dnsReadout=dnsView->findChild<QLabel *>("dnsHoverReadout");
        auto pointInPlot=[&] {
            const auto plot=dnsView->chart()->plotArea();
            return dnsView->mapFromScene(dnsView->chart()->mapToScene(
                QPointF(plot.center().x(),plot.top()+plot.height()*.15)));
        };
        QTest::mouseMove(dnsView->viewport(),pointInPlot());
        check(wait([&] {return dnsReadout && dnsReadout->isVisible();}), "DNS readout works far away from the curve");
        check(dnsReadout && dnsReadout->text().contains("33.3333%") &&
              dnsReadout->text().contains(QStringLiteral("捕获时间")), "DNS readout has precise percentage and timestamp");
        check(view(0)->findChild<QLabel *>("dnsHoverReadout")==nullptr,
              "DNS-specific readout does not alter other charts");
        panel.refresh(s,QStringLiteral("test.pcap"));
        check(wait([&] {return dnsReadout && dnsReadout->isVisible() && dnsReadout->text().contains("33.3333%");}),
              "DNS readout persists across periodic chart replacement");
        const auto originalHistory=s.history;
        s.history.clear();
        for(int i=0;i<=100;++i) {
            auto sample=originalHistory.front();
            sample.timestamp+=std::chrono::seconds(i);
            sample.rate.dnsFraction=double(i)/100.;
            s.history.push_back(sample);
        }
        panel.refresh(s); QTest::qWait(50);
        auto moveDnsTo=[&](double seconds,double percent) {
            const auto position=dnsView->chart()->mapToPosition({seconds,percent},dnsView->chart()->series().front());
            QTest::mouseMove(dnsView->viewport(),dnsView->mapFromScene(dnsView->chart()->mapToScene(position)));
        };
        moveDnsTo(20.25,80);
        check(wait([&] {return dnsReadout->isVisible() && dnsReadout->property("sampleSeconds").toDouble()==20.;}),
              "dense DNS chart snaps to nearest real sample without requiring a curve hit");
        check(dnsReadout->text().contains("20.0000%"), "DNS readout shows sample value rather than interpolated cursor height");
        const auto dnsPreview=qEnvironmentVariable("FLOWGUARD_DNS_PREVIEW");
        if (!dnsPreview.isEmpty()) check(dnsView->grab().save(dnsPreview),"DNS preview saved");
        moveDnsTo(0,80);
        check(wait([&] {return dnsReadout->isVisible() && dnsReadout->text().contains("0.0000%");}),
              "zero DNS baseline can be inspected from above the line");
        for(qsizetype i=0;i<qsizetype(s.history.size());++i)
            s.history[static_cast<std::size_t>(i)].rate.dnsFraction=i==50 ? 0.0001 : 0.;
        panel.refresh(s); QTest::qWait(50);
        dnsAxis=qobject_cast<QValueAxis *>(dnsView->chart()->axes(Qt::Vertical).front());
        check(dnsAxis->min()==0 && dnsAxis->max()>.01 && dnsAxis->max()<.02,
              "0.01-percent DNS peak is enlarged without changing its value");
        const auto lowPlot=dnsView->chart()->plotArea();
        const auto smallPeak=dnsView->chart()->mapToPosition({50,.01},dnsView->chart()->series().front());
        check(smallPeak.y()<lowPlot.center().y(), "small DNS peak is visibly lifted away from x axis");
        const auto belowAxis=dnsView->mapFromScene(dnsView->chart()->mapToScene({smallPeak.x(),lowPlot.bottom()+14}));
        QTest::mouseMove(dnsView->viewport(),belowAxis);
        check(wait([&] {return dnsReadout->isVisible() && dnsReadout->text().contains("0.0100%");}),
              "readout remains accessible below the x-axis without hitting a tiny peak");
        const auto lowPreview=qEnvironmentVariable("FLOWGUARD_DNS_PREVIEW");
        if (!lowPreview.isEmpty()) check(dnsView->grab().save(lowPreview),"low DNS peak preview saved");
        s.history.clear();
        for(int i=0;i<=3600;++i) {
            auto sample=originalHistory.front(); sample.timestamp+=std::chrono::seconds(i);
            sample.rate.dnsFraction=i==1800 ? .0001 : 0.; s.history.push_back(sample);
        }
        panel.refresh(s); QTest::qWait(50);
        moveDnsTo(1800,.01);
        check(wait([&] {return dnsReadout->isVisible() && dnsReadout->property("sampleSeconds").toDouble()==1800 &&
                              dnsReadout->text().contains("0.0100%");}),
              "dense single-sample DNS peak is selected instead of nearby zero samples sharing its pixel");
        QTest::mouseMove(dnsView->viewport(),{belowAxis.x(),2});
        check(!dnsReadout->isVisible(), "readout hides outside the expanded inspection area");
        QEvent leaveDns(QEvent::Leave); QApplication::sendEvent(dnsView,&leaveDns);
        check(dnsReadout && !dnsReadout->isVisible(), "leaving DNS chart hides readout");
        s.history=originalHistory;
        panel.refresh(s); QTest::qWait(50);
        for(int index : {0,1,2}) {
            auto *v=view(index);
            const auto plot=v->chart()->plotArea();
            const auto position=v->mapFromScene(v->chart()->mapToScene(plot.center()));
            QTest::mouseMove(v->viewport(),position);
            auto *card=v->findChild<QLabel *>("chartHoverReadout");
            check(wait([&] {return card && card->isVisible();}), "other line charts use easy-to-read inspection cards");
        }
        auto *barView=view(3);
        auto *barCard=barView->findChild<QLabel *>("chartHoverReadout");
        const auto barPlot=barView->chart()->plotArea();
        QTest::mouseMove(barView->viewport(),barView->mapFromScene(barView->chart()->mapToScene(
            QPointF(barPlot.left()+barPlot.width()/6,barPlot.center().y()))));
        check(wait([&] {return barCard && barCard->isVisible() && barCard->property("sampleValue").toDouble()==0.;}),
              "zero-height bar can be read anywhere in its category band");
        QTest::mouseMove(barView->viewport(),barView->mapFromScene(barView->chart()->mapToScene(barPlot.center())));
        check(wait([&] {return barCard->property("sampleValue").toDouble()==3.;}),
              "bar card reports category count without needing to hit the bar");
        panel.refresh(s); QTest::qWait(50);
        check(barCard->isVisible() && barCard->property("sampleValue").toDouble()==3.,
              "bar card survives periodic refresh");
        auto *pieView=view(5);
        auto *pieCard=pieView->findChild<QLabel *>("chartHoverReadout");
        auto *readPie=qobject_cast<QPieSeries *>(pieView->chart()->series().front());
        const auto piePlot=pieView->chart()->plotArea();
        const auto radius=std::min(piePlot.width(),piePlot.height())*readPie->pieSize()/2;
        QTest::mouseMove(pieView->viewport(),pieView->mapFromScene(pieView->chart()->mapToScene(
            piePlot.center()+QPointF(radius*.9,0))));
        check(wait([&] {return pieCard && pieCard->isVisible();}), "pie sector shows the shared inspection card");
        check(pieCard && pieCard->text().contains("IPv4") && pieCard->text().contains("100.0000%"),
              "pie card reports protocol, count and percentage");
        panel.refresh(s); QTest::qWait(50);
        check(wait([&] {return pieCard && pieCard->isVisible() && pieCard->text().contains("100.0000%");}),
              "pie hover and highlight survive chart replacement");
        {
            std::unique_ptr<QChartView> resource(flowguard::createInteractiveChartView(&panel));
            resource->setGeometry(20,20,620,300);resource->show();resource->raise();
            flowguard::replaceInteractiveChart(resource.get(),flowguard::lineChart(QStringLiteral("CPU 占用"),
                {{0,.02},{1,.03}},QStringLiteral("记录经过秒"),"%",QColor("#07968e"),true));
            QTest::qWait(50);
            auto *axis=qobject_cast<QValueAxis *>(resource->chart()->axes(Qt::Vertical).front());
            check(axis->max()>.03 && axis->max()<1,"low CPU usage gets the same automatic percentage scaling");
            const auto position=resource->chart()->mapToPosition({0,.02},resource->chart()->series().front());
            const auto pointer=resource->mapFromScene(resource->chart()->mapToScene(position));
            QMouseEvent move(QEvent::MouseMove,QPointF(pointer),QPointF(resource->viewport()->mapToGlobal(pointer)),
                             Qt::NoButton,Qt::NoButton,Qt::NoModifier);
            QApplication::sendEvent(resource->viewport(),&move);
            auto *card=resource->findChild<QLabel *>("chartHoverReadout");
            check(wait([&] {return card && card->isVisible() && card->property("sampleValue").toDouble()==.02;}),
                  "resource chart uses accurate shared curve inspection");
            flowguard::replaceInteractiveChart(resource.get(),flowguard::lineChart(QStringLiteral("内存占用"),
                {{0,.1},{1,.2}},QStringLiteral("记录经过秒"),"MiB",QColor("#4285ed")));
            QTest::qWait(50);
            check(wait([&] {return card->isVisible() && card->text().contains("MiB");}),
                  "memory readout retains its actual units during refresh");
        }
        panel.hide();
        auto *summary = panel.findChild<QTableWidget *>("protocolSummaryTable");
        check(summary && summary->rowCount() == 9 && summary->columnCount() == 5,
              "required protocol summary table is distinct from packet list");
        if (summary) {
            s.statistics.networkCounts = {{flowguard::NetworkProtocol::IPv4,1},
                {flowguard::NetworkProtocol::IPv6,1},{flowguard::NetworkProtocol::Arp,1}};
            s.statistics.transportCounts = {{flowguard::TransportProtocol::Tcp,1},
                {flowguard::TransportProtocol::Udp,2}};
            s.statistics.dnsPackets = 1;
            panel.refresh(s);
            check(summary->item(0,2)->text()=="1" && summary->item(1,2)->text()=="1" &&
                  summary->item(2,2)->text()=="1" && summary->item(3,2)->text()=="0" &&
                  summary->item(4,2)->text()=="1" && summary->item(5,2)->text()=="2" &&
                  summary->item(8,2)->text()=="1", "protocol table uses correct layered counters including DNS");
            check(summary->item(8,3)->text()=="33.33%" && summary->item(5,3)->text()=="66.67%",
                  "table percentages use all session packets as denominator");
            check(!(summary->item(0,2)->flags() & Qt::ItemIsEditable), "protocol statistics cannot be edited");
            const auto large=(std::uint64_t{1}<<53)+7;
            s.statistics.totalPackets=large;s.statistics.networkCounts[flowguard::NetworkProtocol::IPv4]=large;
            panel.refresh(s);
            check(summary->item(0,2)->text()==QString::number(qulonglong(large)) &&
                  summary->item(0,2)->data(Qt::UserRole).toULongLong()==large,
                  "table preserves exact uint64 counts above double precision");
            s={};panel.refresh(s);
            for (int row=0;row<summary->rowCount();++row)
                check(summary->item(row,2)->text()=="0" && summary->item(row,3)->text()=="0.00%",
                      "new empty session resets protocol summary");
        }
    }
    if (argc < 2)
        return 2;
    QTemporaryDir temp;
    // Respect CTest's isolated evidence directory, including inherited overrides.
    const QString evidenceRoot = qEnvironmentVariable("FLOWGUARD_LOG_ROOT", temp.path());
    qputenv("FLOWGUARD_LOG_ROOT", evidenceRoot.toUtf8());
    qputenv("FLOWGUARD_ACCEPTANCE", "1");
    {
        flowguard::MainWindow w("integration-test");
        w.show();
        QTest::qWait(500);
        auto *adapters = w.findChild<QComboBox *>("captureDevice");
        auto *openPcap=w.findChild<QAction *>("openPcapAction");
        check(adapters && wait([&] { return adapters->count() > 0; }), "capture selector populated");
        check(wait([&] { return button(w, QStringLiteral("开始采集"))->isEnabled(); }), "initial controls ready");
        auto *storageAction = w.findChild<QAction *>("storageLocationsAction");
        auto *recordButton=w.findChild<QPushButton *>("recordPackets");
        check(recordButton && recordButton->isEnabled(), "recording can be armed before capture");
        check(storageAction && storageAction->isEnabled(), "storage selection available while idle");
        if (storageAction) {
            QTimer::singleShot(0, &w, [&] {
                auto *dialog = w.findChild<QDialog *>("storageLocationsDialog");
                check(dialog != nullptr, "storage locations dialog opens");
                if (!dialog) return;
                auto *logs = dialog->findChild<QLineEdit *>("storageLogRoot");
                auto *captures = dialog->findChild<QLineEdit *>("storageCaptureDirectory");
                check(logs && captures && QDir::isAbsolutePath(logs->text()) && QDir::isAbsolutePath(captures->text()),
                      "separate absolute log and packet destinations");
                dialog->reject();
            });
            storageAction->trigger();
        }
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
        check(wait([&] {
            auto *resumed = button(w, QStringLiteral("暂停回放"));
            return resumed && resumed->isEnabled() && button(w, QStringLiteral("停止"))->isEnabled();
        }), "resume acknowledged and stop control ready");
        w.requestStop();
        check(wait([&] { return openPcap && openPcap->isEnabled(); }), "stop restores file-menu opening");
        w.openFile(QString::fromLocal8Bit(argv[1]));
        check(wait([&] { return w.fileCompleted() && w.totalPackets() == 18; }), "complete fixture exactly18");
        auto *duration = w.findChild<QLabel *>("sessionDuration");
        check(duration && duration->text().contains(QStringLiteral("文件处理时长")), "file time is not capture time");
        check(wait([&] { return table->model()->rowCount() == 18; }), "new session batch delivered");
        auto *filePageNumber = w.findChild<QSpinBox *>("filePageNumber");
        auto pageReady = [&] { return filePageNumber && filePageNumber->isEnabled(); };
        check(wait(pageReady), "complete file first page indexed");
        check(table->model()->index(0,0).data().toULongLong() == 1, "file numbering starts at one");
        table->selectRow(1);
        check(!tree->findItems("SYN", Qt::MatchExactly | Qt::MatchRecursive).isEmpty(), "TCP flags exposed");
        protocol->setCurrentIndex(4);
        button(w, QStringLiteral("应用"))->click();
        check(wait(pageReady), "whole-file TCP filter index ready");
        check(table->model()->rowCount() > 0 && table->model()->rowCount() < 18, "TCP filter");
        check(w.totalPackets() == 18, "filter does not change totals");
        const auto filtered = table->model()->rowCount();
        ip->setText("invalid");
        button(w, QStringLiteral("应用"))->click();
        check(table->model()->rowCount() == filtered, "bad filter keeps last valid one");
        button(w, QStringLiteral("重置"))->click();
        check(wait(pageReady), "whole-file reset ready");
        check(table->model()->rowCount() == 18, "reset restores history");
        protocol->setCurrentIndex(2);
        ip->setText("2001:0db8:0:0:0:0:0:1");
        button(w, QStringLiteral("应用"))->click();
        check(wait(pageReady), "whole-file IPv6 filter ready");
        check(table->model()->rowCount() > 0, "normalized IPv6 filter in GUI");
        button(w, QStringLiteral("重置"))->click();
        check(wait(pageReady), "whole-file final reset ready");
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
        check(storageAction && !storageAction->isEnabled(),
              "storage settings locked during capture to preserve run evidence");
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
        check(wait([&] { return openPcap && openPcap->isEnabled(); }), "GUI live stopped");
        const QString stoppedDuration = duration ? duration->text() : QString();
        QTest::qWait(1100);
        check(duration && duration->text() == stoppedDuration, "capture duration freezes after stop");
        // Save interval/final-dialog and >2000-packet reimport integration is
        // covered by recording_workflow, using the agreed end-of-recording UI.
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
            check(wait([&] { return openPcap && openPcap->isEnabled(); }),
                  "real NIC stopped through Qt controls");
            if (!previewDirectory.isEmpty())
                w.saveScreenshot(previewDirectory + "/wlan.png");
            std::cout << "REAL_NIC_QT packets=" << w.totalPackets() << '\n';
        }
        const QString evidenceParent = QFileInfo(w.logDirectory()).absolutePath();
        const QString expectedParent = QDir(evidenceRoot).absolutePath();
        if (evidenceParent != expectedParent)
            std::cerr << "Evidence actual=" << w.logDirectory().toStdString()
                      << " expected root=" << expectedParent.toStdString() << '\n';
        check(evidenceParent == expectedParent, "evidence directory connected");
        w.close();
        check(wait([&] { return !w.isVisible(); }), "asynchronous close finished");
        QFile result(w.logDirectory() + "/result.json");
        check(result.exists(), "exit result durable");
    }
    std::cout << "STAGE3_GUI_INTEGRATION " << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
