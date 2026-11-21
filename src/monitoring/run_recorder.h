// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#pragma once
#include "core/processing_session.h"
#include <QElapsedTimer>
#include <QFile>
#include <QJsonObject>

namespace flowguard
{
class RunRecorder
{
  public:
    bool open(const QString &root);
    void event(const QString &name, const QJsonObject &detail = {});
    void sample(const ProcessingSnapshot &, const ResourceSample &, double guiDelayMs, std::uint64_t listEvicted = 0);
    void finish(const ProcessingSnapshot &);
    QString directory() const
    {
        return directory_;
    }
    QString error() const
    {
        return error_;
    }
    double elapsed() const
    {
        return timer_.isValid() ? timer_.elapsed() / 1000. : 0;
    }

  private:
    bool write(QFile &, const QByteArray &);
    void metadata(const QString &, QJsonObject);
    QString directory_, error_, start_;
    QFile resources_, events_;
    QElapsedTimer timer_;
    bool finished_ = false;
};
} // namespace flowguard
