// Primary author: Xie Fuxiang. AI-assisted integration tests, pending user review.
#include "ui/main_window.h"
#include <QTemporaryDir>
#include <QUdpSocket>
#include <QtTest/QTest>
#include <QtWidgets>
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
    if (argc < 2)
        return 2;
    QTemporaryDir temp;
    qputenv("FLOWGUARD_LOG_ROOT", temp.path().toUtf8());
    qputenv("FLOWGUARD_ACCEPTANCE", "1");
    {
        flowguard::MainWindow w("integration-test");
        w.show();
        QTest::qWait(500);
        auto *table = w.findChild<QTableView *>("packetTable");
        auto *tree = w.findChild<QTreeWidget *>("protocolFields");
        auto *protocol = w.findChild<QComboBox *>("protocolFilter");
        auto *ip = w.findChild<QLineEdit *>("ipFilter");
        check(table && tree && protocol && ip, "named UI components");
        w.openFile(QString::fromLocal8Bit(argv[1]), true, .1);
        check(wait([&] { return w.totalPackets() > 0; }), "paced file started");
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
            }
        check(w.totalPackets() == 18, "page changes preserve session");
        // Actual capture through the same Qt control path; localhost-only generated traffic.
        QUdpSocket receiver;
        check(receiver.bind(QHostAddress::LocalHost, 0), "local UDP receiver");
        const auto port = receiver.localPort();
        w.startDevice("\\Device\\NPF_Loopback", QString("udp and dst port %1").arg(port));
        check(wait([&] { return button(w, QStringLiteral("停止"))->isEnabled(); }), "GUI live capture started");
        QUdpSocket sender;
        for (int i = 0; i < 10; ++i)
        {
            sender.writeDatagram("stage3-local-test", QHostAddress::LocalHost, port);
            QTest::qWait(40);
        }
        check(wait([&] { return w.totalPackets() > 0; }), "GUI live packets received");
        w.requestStop();
        check(wait([&] { return button(w, QStringLiteral("打开 PCAP"))->isEnabled(); }), "GUI live stopped");
        check(w.logDirectory().startsWith(temp.path()), "evidence directory connected");
        w.close();
        check(wait([&] { return !w.isVisible(); }), "asynchronous close finished");
        QFile result(w.logDirectory() + "/result.json");
        check(result.exists(), "exit result durable");
    }
    std::cout << "STAGE3_GUI_INTEGRATION " << (failures ? "FAIL" : "PASS") << '\n';
    return failures ? 1 : 0;
}
