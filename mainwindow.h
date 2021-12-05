#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "mypcap.h"
#include "datapackage.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void showNetworkDevices();
    int capture();

private slots:
    void on_comboBox_currentIndexChanged(int index);

public slots:
    void HandleMessage(DataPackage data);

private:
    Ui::MainWindow *ui;
    MyPcap m_myPcap;
    QVector<DataPackage> m_dataPackage;     // 数据包
    int m_dataPackageCount;                 // 数据包个数

};
#endif // MAINWINDOW_H
