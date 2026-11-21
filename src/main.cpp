#include "core/packet_types.h"
#include "ui/main_window.h"

#include <QApplication>
#include <QDebug>
#include <QTimer>
#include <pcap.h>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("FlowGuard"));
    app.setApplicationVersion(QStringLiteral("0.1.0"));
    const QString captureVersion = QString::fromLocal8Bit(pcap_lib_version());
    flowguard::MainWindow window(captureVersion);
    window.show();

    // Stage 0 smoke check: load the real Qt/Npcap DLLs and process GUI events.
    // No adapter is opened and no packets are captured here.
    if (app.arguments().contains(QStringLiteral("--smoke-test"))) {
        QTimer::singleShot(500, &app, [&app, &window, captureVersion] {
            const bool passed = window.isVisible() && !captureVersion.isEmpty();
            qInfo().noquote() << "STAGE0_SMOKE" << (passed ? "PASS" : "FAIL")
                              << "Qt" << qVersion() << captureVersion;
            app.exit(passed ? 0 : 1);
        });
    }
    return app.exec();
}
