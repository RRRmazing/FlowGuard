// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#pragma once
#include "core/processing_session.h"
#include <QLabel>
#include <QPointF>
#include <QWidget>
#include <QTableWidget>
#include <QtCharts/QChartView>
#include <array>

namespace flowguard
{
// Rebuild charts at 1 Hz only, never for individual packets.
class ChartPanel final : public QWidget
{
  public:
    explicit ChartPanel(QWidget *parent = nullptr);
    void refresh(const ProcessingSnapshot &, const QString &source = {});

  private:
    std::array<QChartView *, 8> views_{};
    QLabel *scope_ = nullptr;
    QTableWidget *protocolTable_ = nullptr;
};
QChart *lineChart(const QString &, const QList<QPointF> &, const QString &, const QString &, const QColor &,
                  bool percent = false);
QChartView *createInteractiveChartView(QWidget *parent = nullptr);
// The view must be created by createInteractiveChartView().
void replaceInteractiveChart(QChartView *, QChart *, const std::vector<TimeSample> &history = {});
} // namespace flowguard
