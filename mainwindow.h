#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "mypcap.h"

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

private:
    Ui::MainWindow *ui;
    MyPcap m_myPcap;

};
#endif // MAINWINDOW_H
