#pragma once
#include <QDateTime>
#include <QString>
namespace flowguard {
// File operations run on the UI control worker; no packet buffering in RAM.
class RecordingFiles {
public:
    static QString configurationFile();
    static void useConfigurationFile(const QString& file, const QString& legacyPortable = {}, const QString& legacyUser = {}); // Tests use only owned files.
    static QString initialize(); // Migrate old choices and prepare fresh defaults; empty on success.
    static QString logDirectory();
    static bool selectionConfirmed();
    static QString setDirectories(const QString& logs,const QString& packets);
    static QString validateDirectory(const QString& directory,bool create = false);
    static QString defaultDirectory(); // Previously selected directory; empty when unset.
    static QString setDefaultDirectory(const QString&); // Empty on success.
    static QString prepare(const QString& directory, QString& error); // Name only; does not create PCAP.
    static QString suggestedName(const QDateTime& first,const QDateTime& last);
    static QString discard(const QString& staging); // Empty on success, otherwise preserves path.
    static QString publish(const QString& staging,const QString& destination,bool overwrite = false);
};
} // namespace flowguard
