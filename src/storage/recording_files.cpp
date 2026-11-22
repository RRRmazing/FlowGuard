#include "storage/recording_files.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QSettings>
#include <QStandardPaths>
#include <QUuid>
#include <filesystem>
namespace flowguard {
QString RecordingFiles::defaultDirectory() {
    QSettings settings("FlowGuard","FlowGuard");
    const auto selected=settings.value("pcap/defaultDirectory").toString();
    if(!selected.isEmpty()) return QDir::cleanPath(selected);
    const auto desktop=QStandardPaths::writableLocation(QStandardPaths::DesktopLocation);
    return desktop.isEmpty()?QString():QDir(desktop).filePath("FlowGuard-PCAP");
}
QString RecordingFiles::setDefaultDirectory(const QString& directory) {
    QSettings settings("FlowGuard","FlowGuard");
    settings.setValue("pcap/defaultDirectory",QFileInfo(directory).absoluteFilePath());
    settings.sync();
    return settings.status()==QSettings::NoError?QString():QStringLiteral("无法记住默认保存位置，请检查用户设置的写入权限。");
}
QString RecordingFiles::prepare(const QString& directory,QString& error) {
    error.clear();
    if(directory.isEmpty() || !QDir().mkpath(directory)) {
        error=QStringLiteral("无法创建 PCAP 保存目录：")+directory;return {};
    }
    return QDir(directory).absoluteFilePath(".recording-"+QUuid::createUuid().toString(QUuid::WithoutBraces)+".pcap");
}
QString RecordingFiles::suggestedName(const QDateTime& first,const QDateTime& last) {
    return first.toString("yyyy-MM-dd_HH-mm-ss-zzz")+QStringLiteral("_至_")+last.toString("yyyy-MM-dd_HH-mm-ss-zzz")+".pcap";
}
QString RecordingFiles::discard(const QString& staging) {
    if(staging.isEmpty() || !QFileInfo::exists(staging)) return {};
    QFile file(staging);if(file.remove())return {};
    return QStringLiteral("无法删除临时文件：%1\n%2").arg(staging,file.errorString());
}
QString RecordingFiles::publish(const QString& staging,const QString& destination,bool overwrite) {
    if(QFileInfo(staging).absoluteFilePath()==QFileInfo(destination).absoluteFilePath())
        return QStringLiteral("正式文件名不能与临时文件名相同。");
    if(QFileInfo::exists(destination) && !overwrite) return QStringLiteral("目标文件已存在，原记录保留。");
    if(!QFileInfo::exists(destination)) {
        std::error_code ec;
        std::filesystem::rename(std::filesystem::path(staging.toStdWString()),std::filesystem::path(destination.toStdWString()),ec);
        if(!ec)return {}; // Same-volume finalization needs no second copy of a large recording.
    }
    QFile source(staging);
    if(!source.open(QIODevice::ReadOnly))return source.errorString();
    QSaveFile target(destination);target.setDirectWriteFallback(false);
    if(!target.open(QIODevice::WriteOnly))return target.errorString();
    while(!source.atEnd()) {
        const auto chunk=source.read(1024*1024);
        if(chunk.isEmpty() && source.error()!=QFileDevice::NoError)return source.errorString();
        if(target.write(chunk)!=chunk.size())return target.errorString();
    }
    source.close();
    if(!target.commit())return target.errorString();
    const auto cleanup=discard(staging);
    return cleanup.isEmpty()?QString():QStringLiteral("正式文件已保存至 %1，但临时副本清理失败：%2").arg(destination,cleanup);
}
} // namespace flowguard
