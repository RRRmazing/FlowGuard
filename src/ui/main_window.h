// Stage-3 UI: Xie Fuxiang; AI-assisted, pending user review.
#pragma once
#include <QMainWindow>
#include <memory>

namespace flowguard
{
class MainWindow final : public QMainWindow
{
  public:
    explicit MainWindow(const QString &captureLibraryVersion, QWidget *parent = nullptr);
    ~MainWindow() override;
    void openFile(const QString &, bool paced = false, double speed = 1);
    void startDevice(const QString &, const QString &bpf = {}, const QString &initialSavePath = {});
    void requestStop();
    bool fileCompleted() const;
    quint64 totalPackets() const;
    QString logDirectory() const;
    bool saveScreenshot(const QString &);

  protected:
    void closeEvent(QCloseEvent *) override;

  private:
    struct Impl;
    std::unique_ptr<Impl> d;
};
} // namespace flowguard
