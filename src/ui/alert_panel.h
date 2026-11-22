#pragma once
#include "alerts/alert_engine.h"
#include <QWidget>
#include <functional>
#include <set>
class QLabel;
class QPushButton;
class QTableWidget;
class QSpinBox;
class QCheckBox;
namespace flowguard {
class AlertPanel final : public QWidget {
public:
    explicit AlertPanel(QWidget* parent = nullptr);
    std::function<void(const AlertRules&)> applyRules;
    std::function<void(bool)> pauseDetection;
    std::function<void(const AlertRecord&)> relatedPackets;
    void refresh(const AlertSnapshot& snapshot, const QString& source, bool running, bool playbackPaused);
    std::size_t unconfirmedCount() const;
private:
    AlertSnapshot snapshot_;
    QLabel *status_, *scope_, *counts_, *detail_;
    QPushButton *pause_, *confirm_, *related_, *export_;
    QTableWidget* table_;
    std::array<QCheckBox*,alertRuleCount> enabled_{};
    std::array<QSpinBox*,alertRuleCount> window_{}, threshold_{};
    std::set<std::string> confirmed_;
    std::string selectedKey_;
    void showDetail();
    void updateCounts();
    void exportCsv();
    const AlertRecord* selected() const;
};
QString alertRuleName(AlertRule);
} // namespace flowguard
