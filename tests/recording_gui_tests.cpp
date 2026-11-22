#include "ui/main_window.h"
#include "storage/recording_files.h"
#include "core/processing_session.h"
#include <QUdpSocket>
#include <QtTest/QTest>
#include <QtWidgets>
#include <iostream>
#include <algorithm>
#include <stdexcept>
using namespace flowguard;
int main(int argc,char** argv) {
    QApplication app(argc,argv);
    if(argc<2)return 2;
    int checks=0;
    auto check=[&](bool ok,const char* label){++checks;if(!ok)throw std::runtime_error(label);};
    auto wait=[&](const auto& f,const char* label){check(QTest::qWaitFor(f,6000),label);};
    QTemporaryDir owned(QDir::currentPath()+"/recording-tests-XXXXXX");
    if(!owned.isValid())return 2;
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat,QSettings::UserScope,owned.path()+"/settings");
    qputenv("FLOWGUARD_LOG_ROOT",(owned.path()+"/logs").toUtf8());qputenv("FLOWGUARD_ACCEPTANCE","1");
    try {
        const auto folder=owned.path()+"/recordings";
        RecordingFiles::setDefaultDirectory(folder);
        check(RecordingFiles::defaultDirectory()==folder,"default directory is remembered");
        QString problem;
        auto temporary=RecordingFiles::prepare(folder,problem);
        check(!temporary.isEmpty()&&problem.isEmpty()&&!QFileInfo::exists(temporary),"prepare chooses unique name without creating PCAP");
        {QFile f(temporary);check(f.open(QIODevice::WriteOnly),"create owned transfer fixture");f.write("recording-test");}
        const auto destination=owned.path()+"/confirmed.pcap";
        check(RecordingFiles::publish(temporary,destination).isEmpty()&&QFileInfo::exists(destination)&&!QFileInfo::exists(temporary),"publish and remove temporary");
        temporary=RecordingFiles::prepare(folder,problem);
        {QFile f(temporary);check(f.open(QIODevice::WriteOnly),"create second transfer fixture");f.write("second");}
        check(!RecordingFiles::publish(temporary,destination).isEmpty()&&QFileInfo::exists(temporary),"unapproved overwrite preserves temporary");
        check(!RecordingFiles::publish(temporary,owned.path()+"/missing/output.pcap").isEmpty()&&QFileInfo::exists(temporary),"transfer failure preserves source");
        check(RecordingFiles::publish(temporary,destination,true).isEmpty()&&!QFileInfo::exists(temporary),"confirmed replacement commits before removing source");
        {QFile f(destination);check(f.open(QIODevice::ReadOnly)&&f.readAll()=="second","confirmed replacement has exact bytes");}
        temporary=RecordingFiles::prepare(folder,problem);
        {QFile f(temporary);check(f.open(QIODevice::WriteOnly),"create explicit discard fixture");f.write("discard");}
        check(RecordingFiles::discard(temporary).isEmpty()&&!QFileInfo::exists(temporary),"explicit discard deletes temporary");
        // Backend close acknowledgement and per-segment packet metadata.
        ProcessingSession session;ProcessingOptions options;options.savePath=std::filesystem::path((owned.path()+"/backend.pcap").toStdWString());
        check(session.startFile(std::filesystem::path(QString::fromLocal8Bit(argv[1]).toStdWString()),options).ok(),"start backend metadata fixture");
        wait([&]{return session.snapshot().state==ProcessingState::Completed;},"backend metadata fixture complete");
        check(session.finishSaving().ok(),"close acknowledgement after source EOF");
        auto s=session.snapshot();check(s.savedSegmentPackets==18&&s.savedPackets==18&&s.savedFirstTimestamp&&s.savedLastTimestamp,"segment counts and timestamps reflect written packets");

        const auto devices=enumerateDevices();
        const auto loop=std::find_if(devices.devices.begin(),devices.devices.end(),[](const auto& d){return d.loopback;});
        if(loop==devices.devices.end()){std::cout<<"SKIP: no loopback adapter\n";return 77;}
        MainWindow w("recording-tests");w.setAttribute(Qt::WA_DontShowOnScreen);w.show();
        auto* save=w.findChild<QPushButton*>("recordPackets");auto* status=w.findChild<QLabel*>("recordingStatus");
        check(save&&status,"recording UI available");
        auto button=[&](QString name){for(auto* b:w.findChildren<QPushButton*>())if(b->text()==name)return b;return static_cast<QPushButton*>(nullptr);};
        auto files=[&]{return QDir(folder).entryList({".recording-*.pcap"},QDir::Files|QDir::Hidden);};
        auto chooseCapture=[&](const QString& choice) {
            bool handled=false;
            QTimer::singleShot(0,&w,[&] {
                auto* dialog=w.findChild<QDialog*>("captureSavingChoice");
                check(dialog!=nullptr,"every capture-button click opens saving choice");
                check(dialog->findChildren<QPushButton*>().size()==2&&dialog->findChildren<QCheckBox*>().empty(),"capture choice has only two direct buttons");
                handled=true;
                if(choice.isEmpty())dialog->reject();
                else dialog->findChild<QPushButton*>(choice)->click();
            });
            button(QStringLiteral("开始采集"))->click();check(handled,"capture choice handled");
        };
        wait([&]{return save->isEnabled();},"initial saving enabled before capture");
        save->click();check(status->text()==QStringLiteral("等待采集")&&files().empty(),"arming before capture creates no file");
        chooseCapture({});check(status->text()==QStringLiteral("等待采集")&&files().empty()&&!button(QStringLiteral("停止"))->isEnabled(),"closing capture choice preserves pre-armed waiting and does not capture");
        w.openFile(owned.path()+"/not-found.pcap");
        wait([&]{return save->isEnabled();},"failed file open settled");
        check(status->text()==QStringLiteral("等待采集"),"failed file open preserves waiting state");
        w.openFile(QString::fromLocal8Bit(argv[1]));wait([&]{return w.fileCompleted();},"PCAP open completes");
        wait([&]{return button(QStringLiteral("开始采集"))->isEnabled();},"file paging finishes before live preparation");
        check(!save->isEnabled()&&files().empty(),"PCAP mode disables saving and cancels empty waiting");
        chooseCapture({});check(w.fileCompleted()&&w.totalPackets()==18&&!save->isEnabled()&&files().empty(),"closing choice preserves PCAP result and file mode");
        for(auto* action:w.findChildren<QAction*>())check(action->text()!=QStringLiteral("准备实时采集"),"unnecessary preparation menu removed");

        QUdpSocket receiver,sender;check(receiver.bind(QHostAddress::LocalHost,0),"own localhost UDP socket");
        QObject::connect(&receiver,&QUdpSocket::readyRead,&receiver,[&]{while(receiver.hasPendingDatagrams())receiver.readDatagram(nullptr,0);});
        auto send=[&](int n){for(int i=0;i<n;++i){check(sender.writeDatagram("owned-recording-test",QHostAddress::LocalHost,receiver.localPort())>0,"send owned localhost packet");QTest::qWait(20);}};
        auto startCapture=[&]{w.startDevice(QString::fromStdString(loop->id),QString("udp and dst port %1").arg(receiver.localPort()));
            wait([&]{return button(QStringLiteral("停止"))->isEnabled();},"live capture started");};
        auto* adapters=w.findChild<QComboBox*>("captureDevice");const auto adapterIndex=adapters->findData(QString::fromStdString(loop->id));
        check(adapterIndex>=0,"loopback selectable in capture UI");adapters->setCurrentIndex(adapterIndex);
        w.findChild<QLineEdit*>("captureBpf")->setText(QString("udp and dst port %1").arg(receiver.localPort()));
        QString answer;bool answerReady=false,dialogHandled=false;QString suggested;
        QTimer watcher;watcher.setInterval(10);
        QObject::connect(&watcher,&QTimer::timeout,&app,[&]{if(!answerReady)return;
            for(auto* top:QApplication::topLevelWidgets())if(auto* dialog=qobject_cast<QFileDialog*>(top))if(dialog->objectName()=="recordingSaveDialog"){
                answerReady=false;dialogHandled=true;
                if(!dialog->selectedFiles().isEmpty())suggested=QFileInfo(dialog->selectedFiles().front()).fileName();
                if(answer.isEmpty())dialog->reject();else{dialog->selectFile(answer);QMetaObject::invokeMethod(dialog,"accept",Qt::QueuedConnection);}break;
            }});watcher.start();
        auto readCount=[&](const QString& path){PcapReader reader;check(reader.open(std::filesystem::path(path.toStdWString())).ok(),"open finalized PCAP");
            RawPacket raw;OperationResult error;unsigned count=0;while(reader.readNext(raw,error)==ReadStatus::Packet)++count;check(error.ok(),"finalized PCAP readable to EOF");return count;};
        chooseCapture("captureAndSave");wait([&]{return button(QStringLiteral("停止"))->isEnabled();},"file-to-live saving choice starts capture directly");
        send(10);wait([&]{return w.totalPackets()>=10;},"initial captured packets processed");
        const auto initial=w.totalPackets();answer=owned.path()+"/from-first-packet.pcap";answerReady=true;dialogHandled=false;save->click();
        wait([&]{return QFileInfo::exists(answer)&&save->isEnabled();},"end recording confirms final file");
        check(dialogHandled&&suggested.contains(QStringLiteral("_至_"))&&!suggested.contains(':'),"end dialog suggests Windows-safe actual time range");
        check(readCount(answer)==initial&&files().empty(),"pre-armed recording contains every captured packet including first");
        check(button(QStringLiteral("停止"))->isEnabled(),"ending recording does not stop capture");

        const auto unsavedBefore=w.totalPackets();send(8);wait([&]{return w.totalPackets()>=unsavedBefore+8;},"unsaved interval processed");
        save->click();wait([&]{return save->isEnabled()&&save->text()==QStringLiteral("结束保存");},"start large later-only recording");
        const auto largeBefore=w.totalPackets();bool sent=true;
        for(int i=0;i<2600;++i){sent=sender.writeDatagram("owned-large-recording",QHostAddress::LocalHost,receiver.localPort())>0&&sent;
            if(i%50==0)QTest::qWait(5);}
        check(sent,"send owned large localhost interval");wait([&]{return w.totalPackets()>=largeBefore+2600;},"large interval processed");
        const auto largeFile=owned.path()+"/later-2600.pcap";answer=largeFile;answerReady=true;save->click();
        wait([&]{return QFileInfo::exists(largeFile)&&save->isEnabled();},"large interval finalized");
        check(readCount(largeFile)==2600,"saved file contains all later packets beyond UI retention and excludes unsaved interval");

        save->click();wait([&]{return save->isEnabled()&&save->text()==QStringLiteral("结束保存");},"start second recording while live");
        const auto before=w.totalPackets();send(5);wait([&]{return w.totalPackets()>=before+5;},"second segment packets processed");
        answer.clear();answerReady=true;dialogHandled=false;save->click();
        wait([&]{return save->isEnabled()&&status->text()==QStringLiteral("本次记录已丢弃");},"cancel final dialog discards recording");
        check(dialogHandled&&files().empty(),"cancel removes staging file");

        save->click();wait([&]{return save->isEnabled()&&save->text()==QStringLiteral("结束保存");},"start empty segment");
        dialogHandled=false;answerReady=true;save->click();
        wait([&]{return save->isEnabled()&&status->text()==QStringLiteral("没有可保存的报文");},"zero packet segment ends without save dialog");
        check(!dialogHandled&&files().empty(),"zero packet segment has no leftover file");answerReady=false;

        save->click();wait([&]{return save->isEnabled()&&save->text()==QStringLiteral("结束保存");},"start automatic-stop segment");
        send(4);answer=owned.path()+"/on-stop.pcap";answerReady=true;dialogHandled=false;w.requestStop();
        wait([&]{return QFileInfo::exists(answer)&&button(QStringLiteral("开始采集"))->isEnabled();},"stopping capture also offers final save");
        check(dialogHandled&&readCount(answer)>=4&&files().empty(),"automatic stop closes and finalizes PCAP");
        w.openFile(largeFile);
        auto* page=w.findChild<QSpinBox*>("filePageNumber");auto* packetTable=w.findChild<QTableView*>("packetTable");
        wait([&]{return w.fileCompleted()&&w.totalPackets()==2600&&page&&page->isEnabled();},"own saved PCAP indexed for complete browsing");
        check(packetTable&&packetTable->model()->rowCount()==2000&&packetTable->model()->index(0,0).data().toULongLong()==1,"saved PCAP first page starts at one");
        w.findChild<QPushButton*>("nextFilePage")->click();wait([&]{return page->isEnabled()&&page->value()==2;},"saved PCAP second page loads");
        check(packetTable->model()->rowCount()==600&&packetTable->model()->index(0,0).data().toULongLong()==2001&&packetTable->model()->index(599,0).data().toULongLong()==2600,"saved PCAP retains complete second page and original numbering");
        w.findChild<QPushButton*>("firstFilePage")->click();wait([&]{return page->isEnabled()&&page->value()==1;},"saved PCAP can return to first page");
        chooseCapture("captureWithoutSaving");wait([&]{return button(QStringLiteral("停止"))->isEnabled();},"file-to-live choice can start without saving");
        check(files().empty()&&save->text()==QStringLiteral("开始保存报文"),"without-saving choice creates no recording");
        w.requestStop();wait([&]{return button(QStringLiteral("开始采集"))->isEnabled();},"nonrecording capture stopped");
        save->click();chooseCapture("captureWithoutSaving");wait([&]{return button(QStringLiteral("停止"))->isEnabled();},"pre-armed start still shows direct saving choice");
        check(status->text()!=QStringLiteral("等待采集")&&files().empty()&&save->text()==QStringLiteral("开始保存报文"),"latest no-save choice overrides earlier waiting switch");
        w.requestStop();wait([&]{return button(QStringLiteral("开始采集"))->isEnabled();},"override test capture stopped");
        save->click();w.startDevice("\\Device\\NPF_{00000000-0000-0000-0000-000000000000}");
        wait([&]{return save->isEnabled();},"failed capture startup settled");
        check(status->text()==QStringLiteral("等待采集")&&files().empty(),"failed start preserves waiting without creating a file");
        save->click(); // Cancel waiting before final close.
        save->click();startCapture();send(3);wait([&]{return w.totalPackets()>=3;},"close-path packets captured");
        answer.clear();answerReady=true;dialogHandled=false;
        w.close();wait([&]{return !w.isVisible();},"recording window closes cleanly");
        check(dialogHandled&&files().empty(),"window close settles recording before shutdown");
        std::cout<<checks<<" recording checks passed\n";return 0;
    } catch(const std::exception& error){std::cerr<<"FAIL "<<error.what()<<'\n';return 1;}
}
