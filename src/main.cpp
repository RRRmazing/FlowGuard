// Stage-3 integration: Xie Fuxiang; AI-assisted, pending user review.
#include "core/packet_types.h"
#include "ui/main_window.h"
#include "storage/recording_files.h"
#include <QTemporaryDir>
#include <memory>

#include <QApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QListWidget>
#include <QTableView>
#include <QTimer>
#include <QUdpSocket>
#include <pcap.h>

#include <QMessageBox>
#include <windows.h>
#include <string>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("FlowGuard"));
    app.setApplicationVersion(QStringLiteral("0.1.0"));

    // Load Npcap before the first call to a delay-loaded pcap function.
    wchar_t systemDirectory[MAX_PATH] = {};
    const UINT length = GetSystemDirectoryW(systemDirectory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        QMessageBox::critical(nullptr, QStringLiteral("启动失败"),
                            QStringLiteral("无法获取 Windows 系统目录。"));
        return 1;
    }

    const std::wstring npcapLibrary =
        std::wstring(systemDirectory) + L"\\Npcap\\wpcap.dll";

    if (!LoadLibraryExW(npcapLibrary.c_str(), nullptr,
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                    LOAD_LIBRARY_SEARCH_SYSTEM32)) {
        const DWORD error = GetLastError();
        QMessageBox::critical(
            nullptr, QStringLiteral("无法加载 Npcap"),
            QStringLiteral("请从 https://npcap.com/ 安装或修复 x64 Npcap 后重试。\n"
                        "Windows 错误码：%1")
                .arg(static_cast<qulonglong>(error)));
        return 1;
    }
    const QString captureVersion = QString::fromLocal8Bit(pcap_lib_version());
    // Acceptance runs must not read or modify a real user's storage settings.
    std::unique_ptr<QTemporaryDir> acceptanceSettings;
    const auto arguments=app.arguments();
    if(arguments.contains("--smoke-test") || arguments.contains("--accept-file") || arguments.contains("--accept-live")) {
        acceptanceSettings=std::make_unique<QTemporaryDir>();
        if(!acceptanceSettings->isValid()) return 2;
        flowguard::RecordingFiles::useConfigurationFile(acceptanceSettings->path()+"/storage.ini");
        qputenv("FLOWGUARD_ACCEPTANCE","1");
        if(qEnvironmentVariable("FLOWGUARD_LOG_ROOT").isEmpty())
            qputenv("FLOWGUARD_LOG_ROOT",(acceptanceSettings->path()+"/logs").toUtf8());
    }
    flowguard::MainWindow window(captureVersion);
    window.show();

    // Repeatable Qt acceptance run; no desktop automation and no fake traffic.
    const auto args = app.arguments();
    const int inputIndex = args.indexOf("--accept-file");
    const bool liveAcceptance = args.contains("--accept-live");
    if (liveAcceptance)
    {
        qputenv("FLOWGUARD_ACCEPTANCE", "1");
        const int secondsIndex = args.indexOf("--accept-seconds");
        bool valid = false;
        const int seconds =
            secondsIndex >= 0 && secondsIndex + 1 < args.size() ? args[secondsIndex + 1].toInt(&valid) : 5;
        if ((secondsIndex >= 0 && !valid) || seconds < 1 || seconds > 300)
            return 2;
        auto *receiver = new QUdpSocket(&app);
        if (!receiver->bind(QHostAddress::LocalHost, 0))
            return 2;
        auto *sender = new QUdpSocket(&app);
        auto *traffic = new QTimer(&app);
        QObject::connect(receiver, &QUdpSocket::readyRead, receiver, [receiver] {
            while (receiver->hasPendingDatagrams())
            {
                QByteArray packet;
                packet.resize(int(receiver->pendingDatagramSize()));
                receiver->readDatagram(packet.data(), packet.size());
            }
        });
        QObject::connect(traffic, &QTimer::timeout, &app, [sender, receiver] {
            sender->writeDatagram("FlowGuard-owned-GUI-soak", QHostAddress::LocalHost, receiver->localPort());
        });
        QTimer::singleShot(1000, &window, [&window, receiver, traffic] {
            window.startDevice("\\Device\\NPF_Loopback", QString("udp and dst port %1").arg(receiver->localPort()),
                               window.logDirectory() + "/owned-traffic.pcap");
            traffic->start(20);
        });
        QTimer::singleShot((seconds + 1) * 1000, &window, [&window, traffic] {
            traffic->stop();
            window.requestStop();
        });
        QTimer::singleShot((seconds + 3) * 1000, &window, [&window] {
            const bool good = window.totalPackets() > 0;
            qApp->setProperty("acceptancePassed", good);
            window.saveScreenshot(window.logDirectory() + "/live.png");
            window.close();
        });
        QTimer::singleShot((seconds + 15) * 1000, &app, [] { qApp->exit(2); });
    }
    if (inputIndex >= 0 && inputIndex + 1 < args.size())
    {
        qputenv("FLOWGUARD_ACCEPTANCE", "1");
        const QString input = args[inputIndex + 1];
        QTimer::singleShot(1000, &window, [&window, input] { window.openFile(input); });
        QTimer::singleShot(4500, &window, [&window] {
            auto *table = window.findChild<QTableView *>("packetTable");
            if (table && table->model()->rowCount() > 0)
                table->selectRow(0);
            const auto dir = window.logDirectory();
            window.saveScreenshot(dir + "/workbench.png");
            const auto navs = window.findChildren<QListWidget *>();
            if (!navs.isEmpty())
            {
                navs.front()->setCurrentRow(1);
                window.saveScreenshot(dir + "/statistics.png");
                navs.front()->setCurrentRow(2);
                window.saveScreenshot(dir + "/resources.png");
            }
            const bool passed =
                window.fileCompleted() && window.totalPackets() > 0 && table && table->model()->rowCount() > 0;
            qInfo().noquote() << "STAGE3_GUI" << (passed ? "PASS" : "FAIL") << "packets" << window.totalPackets()
                              << "logs" << dir;
            qApp->setProperty("acceptancePassed", passed);
            window.close();
        });
        QTimer::singleShot(15000, &app, [] { qApp->exit(2); });
    }

    // Stage 0 smoke check: load the real Qt/Npcap DLLs and process GUI events.
    // No adapter is opened and no packets are captured here.
    if (app.arguments().contains(QStringLiteral("--smoke-test")))
    {
        QTimer::singleShot(500, &app, [&app, &window, captureVersion] {
            const bool passed = window.isVisible() && !captureVersion.isEmpty();
            qInfo().noquote() << "STAGE0_SMOKE" << (passed ? "PASS" : "FAIL") << "Qt" << qVersion() << captureVersion;
            app.exit(passed ? 0 : 1);
        });
    }
    const int result = app.exec();
    return inputIndex >= 0 || liveAcceptance ? (app.property("acceptancePassed").toBool() ? 0 : 1) : result;
}
