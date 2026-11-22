// Primary author: Xie Fuxiang. AI-assisted implementation, pending user review.
#include "monitoring/run_recorder.h"
#include "build_info.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSaveFile>
#include <QStorageInfo>
#include <QStringList>
#include <QSysInfo>
#include <QUuid>
#include <windows.h>

namespace flowguard
{
static QString timestamp()
{
    return QDateTime::currentDateTime().toUTC().toString(Qt::ISODateWithMs);
}
static QString integer(std::uint64_t v)
{
    return QString::number(qulonglong(v));
}
template <class T> static QString optionalNumber(const std::optional<T> &v)
{
    return v ? QString::number(*v) : QString();
}
bool RunRecorder::write(QFile &file, const QByteArray &data)
{
    if (!file.isOpen() || file.write(data) != data.size() || !file.flush())
    {
        if (error_.isEmpty())
            error_ = file.fileName() + ": " + file.errorString();
        return false;
    }
    return true;
}
void RunRecorder::metadata(const QString &name, QJsonObject data)
{
    QSaveFile file(directory_ + '/' + name);
    const auto payload = QJsonDocument(data).toJson();
    if (!file.open(QIODevice::WriteOnly) || file.write(payload) != payload.size() || !file.commit())
        if (error_.isEmpty())
            error_ = file.fileName() + ": " + file.errorString();
}
bool RunRecorder::open(const QString &root)
{
    if(root.trimmed().isEmpty() || !QDir::isAbsolutePath(root)) {
        error_=QStringLiteral("尚未选择有效的日志目录。");return false;
    }
    timer_.start();
    start_ = timestamp();
    directory_ = QDir(root).absoluteFilePath(QDateTime::currentDateTime().toString("yyyyMMdd-HHmmss-zzz") + '-' +
                                             QUuid::createUuid().toString(QUuid::Id128));
    if (!QDir().mkpath(directory_))
    {
        error_ = QStringLiteral("不能创建运行日志目录：") + directory_;
        return false;
    }
    resources_.setFileName(directory_ + "/resources.csv");
    events_.setFileName(directory_ + "/events.jsonl");
    if (!resources_.open(QIODevice::WriteOnly | QIODevice::NewOnly) ||
        !events_.open(QIODevice::WriteOnly | QIODevice::NewOnly))
    {
        error_ = QStringLiteral("不能创建资源/事件日志：") + directory_;
        return false;
    }
    write(resources_, "timestamp,elapsed_seconds,session_id,source,state,cpu_percent,working_set_bytes,process_read_"
                      "bytes,process_write_bytes,total_packets,total_bytes,saved_packets,queued_packets,queued_bytes,"
                      "queue_dropped,driver_received,driver_dropped,interface_dropped,display_dropped,late_history_"
                      "packets,gui_delay_ms,saving_active,error_code,saving_error_code,list_evicted\n");
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    GlobalMemoryStatusEx(&memory);
    QFile executable(QCoreApplication::applicationFilePath());
    QString binaryHash;
    if (executable.open(QIODevice::ReadOnly))
        binaryHash =
            QString::fromLatin1(QCryptographicHash::hash(executable.readAll(), QCryptographicHash::Sha256).toHex());
    const QStorageInfo storage(directory_);
    metadata("run.json",
             {{"schema", 2},
              {"started", start_},
              {"run_id", QFileInfo(directory_).fileName()},
              {"commit", FLOWGUARD_GIT_COMMIT},
              {"dirty_at_configure", FLOWGUARD_GIT_DIRTY},
              {"version", QCoreApplication::applicationVersion()},
              {"qt", qVersion()},
              {"executable_sha256", binaryHash},
              {"log_disk_available_bytes", QString::number(storage.bytesAvailable())},
              {"os", QSysInfo::prettyProductName()},
              {"architecture", QSysInfo::currentCpuArchitecture()},
              {"logical_processors", int(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS))},
              {"total_memory_bytes", integer(memory.ullTotalPhys)},
              {"cpu", qEnvironmentVariable("PROCESSOR_IDENTIFIER")},
              {"scope", "GUI process; CPU normalized by all logical processors; I/O is process cumulative"}});
    event("application_started");
    return error_.isEmpty();
}
void RunRecorder::event(const QString &name, const QJsonObject &detail)
{
    if(!timer_.isValid()) return;
    write(events_, QJsonDocument(QJsonObject{{"timestamp", timestamp()},
                                             {"elapsed_seconds", elapsed()},
                                             {"event", name},
                                             {"detail", detail}})
                           .toJson(QJsonDocument::Compact) +
                       '\n');
}
void RunRecorder::sample(const ProcessingSnapshot &s, const ResourceSample &r, double delay, std::uint64_t listEvicted)
{
    if(!timer_.isValid()) return;
    QStringList v{timestamp(),
                  QString::number(elapsed(), 'f', 3),
                  integer(s.sessionId),
                  QString::number(int(s.source)),
                  QString::number(int(s.state)),
                  optionalNumber(r.cpuPercent),
                  optionalNumber(r.workingSetBytes),
                  optionalNumber(r.processReadBytes),
                  optionalNumber(r.processWriteBytes),
                  integer(s.statistics.totalPackets),
                  integer(s.statistics.totalBytes),
                  integer(s.savedPackets),
                  integer(s.capture.queuedPackets),
                  integer(s.capture.queuedBytes),
                  integer(s.capture.queueDroppedPackets),
                  optionalNumber(s.capture.driverReceived),
                  optionalNumber(s.capture.driverDropped),
                  optionalNumber(s.capture.interfaceDropped),
                  integer(s.displayDroppedPackets),
                  integer(s.lateHistoryPackets),
                  QString::number(delay, 'f', 3),
                  s.savingActive ? "1" : "0",
                  QString::number(int(s.error.code)),
                  QString::number(int(s.savingError.code)),
                  integer(listEvicted)};
    write(resources_, (v.join(',') + '\n').toUtf8());
}
void RunRecorder::finish(const ProcessingSnapshot &s)
{
    if (finished_ || !timer_.isValid())
        return;
    finished_ = true;
    event("application_stopped", {{"session_id", integer(s.sessionId)},
                                  {"packets", integer(s.statistics.totalPackets)},
                                  {"saved_packets", integer(s.savedPackets)}});
    resources_.close();
    events_.close();
    metadata("result.json", {{"started", start_},
                             {"ended", timestamp()},
                             {"duration_seconds", elapsed()},
                             {"normal_exit", true},
                             {"logging_error", error_},
                             {"session_id", integer(s.sessionId)},
                             {"total_packets", integer(s.statistics.totalPackets)},
                             {"saved_packets", integer(s.savedPackets)},
                             {"source_error", QString::fromStdString(s.error.message)},
                             {"saving_error", QString::fromStdString(s.savingError.message)}});
}
} // namespace flowguard
