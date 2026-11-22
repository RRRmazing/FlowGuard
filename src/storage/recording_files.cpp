#include "storage/recording_files.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSaveFile>
#include <QSettings>
#include <QCoreApplication>
#include <QTemporaryFile>
#include <QStorageInfo>
#include <QUuid>
#include <filesystem>
namespace flowguard {
namespace {
QString configurationOverride;
QString persistDirectories(const QString *logs,const QString *packets) {
    const auto file=RecordingFiles::configurationFile();
    if(!QDir().mkpath(QFileInfo(file).absolutePath()))
        return QStringLiteral("无法创建程序配置目录：")+QFileInfo(file).absolutePath();
    QSettings settings(file,QSettings::IniFormat);
    if(logs) settings.setValue("logRoot",*logs);
    if(packets) {settings.setValue("captureDirectory",*packets);settings.remove("pcap/defaultDirectory");}
    if(logs && packets) settings.setValue("storage/confirmed",true);
    settings.sync();
    return settings.status()==QSettings::NoError?QString():QStringLiteral("无法保存配置，请检查程序配置文件的写入权限：")+file;
}
}
QString RecordingFiles::configurationFile() {
    return configurationOverride.isEmpty()?QCoreApplication::applicationDirPath()+"/data/storage.ini":configurationOverride;
}
void RecordingFiles::useConfigurationFile(const QString& file) {
    configurationOverride=file.isEmpty()?QString():QFileInfo(file).absoluteFilePath();
}
QString RecordingFiles::logDirectory() {
    QSettings settings(configurationFile(),QSettings::IniFormat);
    return settings.value("logRoot").toString().trimmed();
}
bool RecordingFiles::selectionConfirmed() {
    QSettings settings(configurationFile(),QSettings::IniFormat);
    return settings.value("storage/confirmed",false).toBool();
}
QString RecordingFiles::defaultDirectory() {
    QSettings settings(configurationFile(),QSettings::IniFormat);
    // Preserve previously chosen portable settings; never infer a drive or desktop.
    const auto selected=settings.value("captureDirectory",settings.value("pcap/defaultDirectory")).toString().trimmed();
    return selected.isEmpty()?QString():QDir::cleanPath(selected);
}
QString RecordingFiles::validateDirectory(const QString& directory,bool create) {
    if(directory.trimmed().isEmpty()) return QStringLiteral("尚未选择保存目录，请先在“保存设置”中选择位置。");
    if(!QDir::isAbsolutePath(directory)) return QStringLiteral("请选择完整的绝对目录：")+directory;
    if(create && !QDir().mkpath(directory)) return QStringLiteral("无法创建保存目录：")+directory;
    if(!QFileInfo(directory).isDir()) return QStringLiteral("保存目录不存在或磁盘未连接，请重新选择：")+directory;
    QTemporaryFile probe(QDir(directory).filePath(".flowguard-write-check-XXXXXX"));
    if(!probe.open() || probe.write("ok")!=2 || !probe.flush())
        return QStringLiteral("保存目录不可写，请重新选择：")+directory;
    const QStorageInfo storage(directory);
    if(!storage.isReady() || storage.isReadOnly() || storage.bytesAvailable()<1024*1024)
        return QStringLiteral("保存盘不可用或剩余空间不足1 MiB，请重新选择：")+directory;
    return {};
}
QString RecordingFiles::setDirectories(const QString& logs,const QString& packets) {
    for(const auto& path:{logs,packets}) if(!path.isEmpty()) {
        const auto problem=validateDirectory(path,true);if(!problem.isEmpty())return problem;
    }
    return persistDirectories(&logs,&packets);
}
QString RecordingFiles::setDefaultDirectory(const QString& directory) {
    const auto problem=validateDirectory(directory,true);if(!problem.isEmpty())return problem;
    const auto selected=QDir::cleanPath(directory);
    return persistDirectories(nullptr,&selected);
}
QString RecordingFiles::prepare(const QString& directory,QString& error) {
    error.clear();
    error=validateDirectory(directory);if(!error.isEmpty())return {};
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
