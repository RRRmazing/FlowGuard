#include "ui/main_window.h"

#include <QLabel>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QWidget>

namespace flowguard {
MainWindow::MainWindow(const QString& captureLibraryVersion, QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle(QStringLiteral("FlowGuard 流量哨兵"));
    resize(960, 640);
    auto* panel = new QWidget(this);
    auto* layout = new QVBoxLayout(panel);
    auto* heading = new QLabel(QStringLiteral("流量哨兵——网络流量检测与分析系统"), panel);
    auto titleFont = heading->font();
    titleFont.setPointSize(18);
    heading->setFont(titleFont);
    layout->addWidget(heading);
    layout->addWidget(new QLabel(QStringLiteral("阶段 0：工程与工具链验收"), panel));
    layout->addWidget(new QLabel(QStringLiteral("已连接 Qt Widgets 与 Npcap。当前版本尚未实现报文采集。"), panel));
    auto* version = new QLabel(captureLibraryVersion, panel);
    version->setWordWrap(true);
    version->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(version);
    layout->addStretch();
    setCentralWidget(panel);
    statusBar()->showMessage(QStringLiteral("工程已启动 · Qt %1 · C++17").arg(QString::fromLatin1(qVersion())));
}
} // namespace flowguard
