// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#pragma once
#include "core/processing_session.h"
#include <QPointF>
#include <QWidget>
#include <QtCharts/QChartView>
#include <array>

namespace flowguard
{
// Rebuild charts at 1 Hz only, never for individual packets.
class ChartPanel final : public QWidget
{
  public:
    explicit ChartPanel(QWidget *parent = nullptr);
    void refresh(const ProcessingSnapshot &);

  private:
    std::array<QChartView *, 8> views_{};
};
QChart *lineChart(const QString &, const QList<QPointF> &, const QString &, const QString &, const QColor &,
                  bool percent = false);
} // namespace flowguard
