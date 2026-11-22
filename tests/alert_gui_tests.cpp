#include "ui/main_window.h"
#include "ui/alert_panel.h"
#include <QTemporaryDir>
#include <QtTest/QTest>
#include <QtWidgets>
#include <iostream>
using namespace flowguard;
int main(int argc,char** argv){
    std::cerr<<"Starting alert GUI test\n";
    QApplication app(argc,argv);
    std::cerr<<"QApplication ready\n";
    if(argc<3)return 2;
    int failures=0;
    auto check=[&](bool ok,const char* label){if(!ok){++failures;std::cerr<<"FAIL "<<label<<'\n';}};
    auto wait=[](const auto& f){return QTest::qWaitFor(f,10000);};
    QTemporaryDir logs(QDir::currentPath()+"/alert-gui-logs-XXXXXX");
    check(logs.isValid(),"create writable test log directory");
    qputenv("FLOWGUARD_LOG_ROOT",logs.path().toUtf8());qputenv("FLOWGUARD_ACCEPTANCE","1");
    {
        AlertPanel panel;
        AlertSnapshot ended;ended.sessionId=1;ended.file=true;ended.finished=true;ended.paused=true;
        panel.refresh(ended,"paused-file.pcap",false,false);
        auto* resume=panel.findChild<QPushButton*>("pauseAlerts");
        check(resume&&resume->isEnabled(),"paused detection can resume after file ends");
        bool resumed=false;panel.pauseDetection=[&](bool paused){resumed=!paused;};resume->click();
        check(resumed,"resume callback available after file ends");
    }
    {
        std::cerr<<"Creating MainWindow\n";
        MainWindow w("alert-integration");w.setAttribute(Qt::WA_DontShowOnScreen);w.show();
        std::cerr<<"MainWindow ready\n";
        auto* nav=w.findChild<QListWidget*>();
        check(nav&&nav->count()==4,"four navigation entries");if(!nav)return 1;
        nav->setCurrentRow(3);
        auto* panel=w.findChild<QWidget*>("alertPanel");
        auto* table=w.findChild<QTableWidget*>("alertTable");
        auto* status=w.findChild<QLabel*>("alertStatus");
        auto* apply=w.findChild<QPushButton*>("applyAlertRules");
        auto* settings=w.findChild<QPushButton*>("alertSettings");
        auto* threshold=w.findChild<QSpinBox*>("alertThreshold0");
        check(panel&&table&&status&&apply&&settings&&threshold,"alert controls available");
        if(!panel||!table||!status||!apply||!settings||!threshold)return 1;
        auto* start=[&](){for(auto* b:w.findChildren<QPushButton*>())if(b->text()==QStringLiteral("开始采集"))return b;return static_cast<QPushButton*>(nullptr);}();
        check(wait([&]{return start&&start->isEnabled();}),"initial commands settled");
        w.openFile(QString::fromLocal8Bit(argv[1]));
        check(wait([&]{return w.fileCompleted();}),"anomaly file completed");
        check(wait([&]{return table->rowCount()==5;}),"all five anomaly rules displayed");
        check(w.totalPackets()==2082,"demo PCAP packet count");
        const std::map<QString,QString> expected{{QStringLiteral("疑似 SYN 泛洪"),"600 / 500"},
            {QStringLiteral("疑似 TCP 端口扫描"),"30 / 20"},{QStringLiteral("回声请求频率异常"),"350 / 300"},
            {QStringLiteral("UDP 高频流量"),"1100 / 1000"},{QStringLiteral("ARP 地址映射变化/冲突"),"1 / 1"}};
        for(int row=0;row<table->rowCount();++row){const auto found=expected.find(table->item(row,1)->text());
            check(found!=expected.end()&&table->item(row,3)->text()==found->second,"demo rule peak matches independently specified expectation");}
        check(nav->item(3)->text().contains("5"),"navigation alert badge");
        check(status->text().contains(QStringLiteral("结束")),"offline completion shown");
        check(w.findChild<QLabel*>("alertDetail")->text().contains(QStringLiteral("窗口")),"selected alert explains window and threshold");
        auto* pages=w.findChild<QStackedWidget*>();
        QTest::qWait(100);
        if(pages&&argc>3){w.grab().save(QString::fromLocal8Bit(argv[3])+"/alert-monitor.png");}
        settings->click();check(w.findChild<QWidget*>("alertRuleSettings")->isVisible(),"settings expand");
        threshold->setValue(1000);apply->click();threshold->setValue(100);apply->click();
        check(wait([&]{for(int row=0;row<table->rowCount();++row)
            if(table->item(row,1)->text().contains("SYN")&&table->item(row,3)->text()=="600 / 100")return true;return false;}),
            "rapid UI applications retain the latest threshold");
        threshold->setValue(1000);apply->click();
        check(wait([&]{return table->rowCount()==4;}),"raising threshold automatically removes SYN alert");
        threshold->setValue(100);apply->click();
        check(wait([&]{return table->rowCount()==5;}),"lowering threshold automatically re-adds SYN alert");
        auto* enabled=w.findChild<QCheckBox*>("alertEnabled3");enabled->setChecked(false);apply->click();
        check(wait([&]{return table->rowCount()==4;}),"disable UDP affects only its rule");
        enabled->setChecked(true);apply->click();check(wait([&]{return table->rowCount()==5;}),"enable UDP rechecks file");
        // Select SYN evidence and navigate to the existing packet workbench.
        for(int i=0;i<table->rowCount();++i)if(table->item(i,1)->text().contains("SYN"))table->selectRow(i);
        auto* related=w.findChild<QPushButton*>("alertRelatedPackets");related->click();check(nav->currentRow()==0,"related packets returns to workbench");
        nav->setCurrentRow(3);
        if(argc>3)w.grab().save(QString::fromLocal8Bit(argv[3])+"/alert-settings.png");
        check(wait([&]{return start->isEnabled();}),"controls ready for next session");
        w.openFile(QString::fromLocal8Bit(argv[2]));
        check(wait([&]{return w.fileCompleted();}),"normal file completed");
        check(wait([&]{return table->rowCount()==0;}),"normal file clears old-session alerts");
        check(wait([&]{return w.totalPackets()==52&&w.fileCompleted();}),"normal PCAP packet count and completion");
        w.close();check(wait([&]{return !w.isVisible();}),"window closes cleanly");
    }
    std::cout<<"Alert GUI failures: "<<failures<<'\n';return failures?1:0;
}
