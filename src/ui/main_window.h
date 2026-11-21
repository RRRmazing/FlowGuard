#pragma once
#include <QMainWindow>

namespace flowguard {
class MainWindow final : public QMainWindow {
public:
    explicit MainWindow(const QString& captureLibraryVersion, QWidget* parent = nullptr);
};
} // namespace flowguard
