#include "storage/recording_files.h"
#include "monitoring/run_recorder.h"
#include "ui/main_window.h"
#include <QtTest/QTest>
#include <QtWidgets>
#include <iostream>

int main(int argc,char **argv) {
    QApplication app(argc,argv);
    QTemporaryDir owned(QDir::currentPath()+"/storage-selection-XXXXXX");
    if(!owned.isValid())return 2;
    const auto config=owned.path()+"/配置/storage.ini";
    flowguard::RecordingFiles::useConfigurationFile(config);
    int failures=0;
    auto check=[&](bool value,const char *name) {if(!value){++failures;std::cerr<<"FAIL "<<name<<'\n';}};
    using Files=flowguard::RecordingFiles;
    check(Files::defaultDirectory().isEmpty()&&Files::logDirectory().isEmpty(),"first use has no implicit data directories");
    check(Files::initialize().isEmpty(),"fresh defaults initialize successfully");
    const auto defaultPackets=Files::defaultDirectory(),defaultLogs=Files::logDirectory();
    check(QFileInfo(defaultPackets).isDir()&&QFileInfo(defaultLogs).isDir(),"fresh packet and log directories are created outside program installation");
    check(defaultPackets.startsWith(owned.path())&&defaultLogs.startsWith(owned.path()),"test defaults remain inside owned directory");
    auto startupPrompt=[&](bool expected) {
        const auto acceptance=qgetenv("FLOWGUARD_ACCEPTANCE");
        const bool hadAcceptance=qEnvironmentVariableIsSet("FLOWGUARD_ACCEPTANCE");
        qunsetenv("FLOWGUARD_ACCEPTANCE");
        bool prompted=false;
        {
            flowguard::MainWindow window("storage-startup-test");
            window.setAttribute(Qt::WA_DontShowOnScreen);
            QTimer dismiss;
            QObject::connect(&dismiss,&QTimer::timeout,&window,[&] {
                if(auto *dialog=window.findChild<QDialog *>("storageLocationsDialog")) {
                    prompted=true;dialog->reject();
                }
            });
            dismiss.start(10);window.show();
            auto *action=window.findChild<QAction *>("storageLocationsAction");
            check(QTest::qWaitFor([&]{return action&&action->isEnabled();},6000),"startup controls settle");
            QTest::qWait(250);
            check(prompted==expected,expected?"invalid directory still prompts for correction":"usable storage launches without a redundant setup dialog");
            window.close();
            check(QTest::qWaitFor([&]{return !window.isVisible();},6000),"startup-check window closes");
        }
        if(hadAcceptance)qputenv("FLOWGUARD_ACCEPTANCE",acceptance);else qunsetenv("FLOWGUARD_ACCEPTANCE");
    };
    startupPrompt(false); // Exercise production startup, without the acceptance suppression flag.
    check(Files::setDirectories({},defaultPackets).isEmpty(),"user can explicitly disable logging");
    QString error;
    check(Files::prepare({},error).isEmpty()&&!error.isEmpty(),"unset packet directory cannot begin writing");

    check(!Files::validateDirectory("relative/path",true).isEmpty(),"relative destinations rejected");
    const auto blocked=owned.path()+"/不是文件夹";
    {QFile file(blocked);check(file.open(QIODevice::WriteOnly),"create owned non-directory fixture");}
    check(!Files::validateDirectory(blocked,true).isEmpty(),"file cannot be used as a directory");
    {
        flowguard::RunRecorder dormant;
        dormant.event("not-configured"); dormant.sample({}, {},0); dormant.finish({});
        check(dormant.directory().isEmpty()&&dormant.error().isEmpty(),"unconfigured recorder does not attempt any file writes");
    }
    {
        // Invalid initial logging must be recoverable in the same window, without a restart.
        {QSettings settings(config,QSettings::IniFormat);settings.setValue("logRoot",blocked);settings.sync();}
        flowguard::MainWindow window("log-retry-test");window.setAttribute(Qt::WA_DontShowOnScreen);window.show();
        auto *action=window.findChild<QAction *>("storageLocationsAction");
        check(QTest::qWaitFor([&]{return action&&action->isEnabled();},6000),"failed-log startup settles");
        check(window.logDirectory().isEmpty(),"failed startup is not exposed as an active log directory");
        const auto retryRoot=owned.path()+"/重试日志";
        QTimer::singleShot(0,&window,[&] {
            auto *dialog=window.findChild<QDialog *>("storageLocationsDialog");
            check(dialog!=nullptr,"log recovery settings opens");if(!dialog)return;
            dialog->findChild<QLineEdit *>("storageLogRoot")->setText(retryRoot);
            dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Save)->click();
        });
        if(action)action->trigger();
        check(QTest::qWaitFor([&]{return window.logDirectory().startsWith(retryRoot+"/");},6000),
              "corrected log directory starts recording without restarting the application");
        QTest::qWait(1100); // Include the asynchronous recorder sample/error refresh.
        bool staleWarning=false;
        for(auto *label:window.findChildren<QLabel *>())
            staleWarning=staleWarning || label->text().contains(QStringLiteral("日志目录已修改，下次启动生效")) || label->text().contains(blocked);
        check(!staleWarning,"successful retry clears old error and does not request a restart");
        const auto run=window.logDirectory();
        check(QFileInfo::exists(run+"/resources.csv"),"retried GUI logging creates resource data");
        const auto nextRoot=owned.path()+"/下一次日志";
        QTimer::singleShot(0,&window,[&] {
            auto *dialog=window.findChild<QDialog *>("storageLocationsDialog");
            check(dialog!=nullptr,"running log destination settings opens");if(!dialog)return;
            dialog->findChild<QLineEdit *>("storageLogRoot")->setText(nextRoot);
            dialog->findChild<QDialogButtonBox *>()->button(QDialogButtonBox::Save)->click();
        });
        if(action)action->trigger();
        check(window.logDirectory()==run&&QDir(nextRoot).entryList(QDir::Dirs|QDir::NoDotAndDotDot).isEmpty(),
              "healthy active log is not moved or reopened when changing the next-run directory");
        window.close();check(QTest::qWaitFor([&]{return !window.isVisible();},6000),"retried-log window closes");
        QFile result(run+"/result.json");
        check(result.open(QIODevice::ReadOnly),"retried GUI run has an exit record");
        check(QJsonDocument::fromJson(result.readAll()).object()["logging_error"].toString().isEmpty(),
              "GUI retry exit record has no stale logging error");
    }
    check(Files::setDirectories({},defaultPackets).isEmpty(),"restore explicit log opt-out for following scenarios");
    {
        flowguard::MainWindow window("storage-selection-test");window.setAttribute(Qt::WA_DontShowOnScreen);window.show();
        auto *action=window.findChild<QAction *>("storageLocationsAction");
        check(action!=nullptr,"user can open storage selection");
        check(QTest::qWaitFor([&]{return action&&action->isEnabled();},6000),"initial operations settle");
        auto select=[&](const QString &logs,const QString &packets,bool cancel,bool invalid) {
            bool handled=false;
            QTimer::singleShot(0,&window,[&] {
                auto *dialog=window.findChild<QDialog *>("storageLocationsDialog");
                check(dialog!=nullptr,"storage selection dialog opens");if(!dialog)return;
                auto *logEdit=dialog->findChild<QLineEdit *>("storageLogRoot");
                auto *packetEdit=dialog->findChild<QLineEdit *>("storageCaptureDirectory");
                check(logEdit&&packetEdit,"independent log and packet choices");
                if(!logEdit||!packetEdit){dialog->reject();return;}
                if(cancel) {
                    check(logEdit->text().isEmpty()&&packetEdit->text()==defaultPackets,"dialog preserves defaults and explicitly disabled logs");
                    dialog->reject();handled=true;return;
                }
                logEdit->setText(logs);packetEdit->setText(packets);
                auto *buttons=dialog->findChild<QDialogButtonBox *>();
                buttons->button(QDialogButtonBox::Save)->click();
                if(invalid) {check(dialog->isVisible(),"invalid path keeps dialog open for correction");dialog->reject();}
                handled=true;
            });
            if(action)action->trigger();check(handled,"dialog interaction completed");
        };
        select({}, {},true,false);
        check(Files::defaultDirectory()==defaultPackets&&window.logDirectory().isEmpty(),"cancel preserves usable defaults and explicit log opt-out");
        auto *record=window.findChild<QPushButton *>("recordPackets");
        if(record)record->click();else check(false,"recording control exists");
        check(record&&record->text()==QStringLiteral("取消保存等待"),"valid default allows saving to arm without a path prompt");
        if(record)record->click();
        select({},"relative/path",false,true);
        check(Files::defaultDirectory()==defaultPackets,"invalid selection does not replace valid settings");
        const auto packets=owned.path()+"/用户选择的报文";
        select({},packets,false,false);
        check(Files::defaultDirectory()==packets&&Files::logDirectory().isEmpty(),"packet-only choice does not invent a log directory");
        check(Files::selectionConfirmed(),"explicitly leaving logging disabled is remembered without repeated startup prompts");
        check(window.logDirectory().isEmpty(),"logging remains disabled until selected");
        const auto logs=owned.path()+"/用户选择的日志";
        select(logs,packets,false,false);
        check(QTest::qWaitFor([&]{return window.logDirectory().startsWith(logs+"/");},6000),"first chosen log directory starts logging immediately");
        check(QFileInfo::exists(window.logDirectory()+"/resources.csv"),"log files only appear in the selected location");
        const auto run=window.logDirectory();
        window.close();check(QTest::qWaitFor([&]{return !window.isVisible();},6000),"window closes cleanly");
        check(QFileInfo::exists(run+"/result.json"),"selected logging has a durable exit record");
    }
    const auto disconnected=owned.path()+"/模拟断开的目录";
    check(Files::setDefaultDirectory(disconnected).isEmpty(),"remember selected directory");
    check(QDir().rmdir(disconnected),"remove empty owned directory to simulate disconnection");
    check(Files::prepare(Files::defaultDirectory(),error).isEmpty()&&!QFileInfo::exists(disconnected),
          "missing stored directory is rejected without fallback or recreation");
    const auto legacy=owned.path()+"/legacy.ini";
    {QSettings old(legacy,QSettings::IniFormat);old.setValue("captureDirectory",owned.path()+"/旧版选定的报文");old.setValue("logRoot",owned.path()+"/旧版日志");old.sync();}
    Files::useConfigurationFile(legacy);
    check(Files::defaultDirectory()==owned.path()+"/旧版选定的报文"&&Files::logDirectory()==owned.path()+"/旧版日志",
          "portable legacy choices are retained rather than replaced with desktop defaults");
    // Migrate the actual predecessor sources, with new INI > old INI > old user settings.
    const auto portable=owned.path()+"/portable.ini",user=owned.path()+"/old-user.ini";
    const auto migrated=owned.path()+"/升级配置/storage.ini";
    const auto oldPackets=owned.path()+"/旧用户报文",oldLogs=owned.path()+"/旧日志";
    QDir().mkpath(oldPackets);QDir().mkpath(oldLogs);
    {QSettings old(user,QSettings::IniFormat);old.setValue("pcap/defaultDirectory",oldPackets);old.sync();}
    {QSettings old(portable,QSettings::IniFormat);old.setValue("logRoot",oldLogs);old.sync();}
    Files::useConfigurationFile(migrated,portable,user);
    check(Files::initialize().isEmpty()&&Files::defaultDirectory()==oldPackets&&Files::logDirectory()==oldLogs,
          "old user-setting PCAP location and portable log setting migrate together");
    startupPrompt(false);
    check(Files::setDirectories({},defaultPackets).isEmpty(),"new choice overrides migrated settings");
    check(Files::initialize().isEmpty()&&Files::logDirectory().isEmpty()&&Files::defaultDirectory()==defaultPackets,
          "reinitialization preserves new choices and explicit empty values");
    QDir().rmdir(oldPackets);
    Files::useConfigurationFile(owned.path()+"/失效升级/storage.ini",portable,user);
    check(!Files::initialize().isEmpty()&&Files::defaultDirectory()==oldPackets&&!QFileInfo::exists(oldPackets),
          "missing migrated custom directory is retained with an error and not silently recreated");
    startupPrompt(true);
    Files::useConfigurationFile(blocked+"/storage.ini");
    check(!Files::setDirectories({},owned.path()+"/新选择").isEmpty(),"configuration write failure is explicit");
    std::cout<<"STORAGE_SELECTION "<<(failures?"FAIL":"PASS")<<'\n';return failures?1:0;
}
