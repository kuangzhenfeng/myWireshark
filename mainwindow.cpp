#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QString>
#include <QDebug>
#include "commonDebug.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkDevices();
    m_myPcap.setCurDevice(11);   // kzf for test
    static bool bStart = false;
    connect(ui->actionrun_and_stop, &QAction::triggered, this, [=](){
        bStart = !bStart;
        if(bStart)
        {
            int res = m_myPcap.capture();
            if(0 == res)
            {
                statusBar()->showMessage(m_myPcap.getCurDeviceDescription());
                ui->actionrun_and_stop->setIcon(QIcon(":/resources/stop.png"));
                ui->comboBox->setEnabled(false);
            }
        }
        else
        {
            m_myPcap.stopCapture();
            ui->actionrun_and_stop->setIcon(QIcon(":/resources/start.png"));
            ui->comboBox->setEnabled(true);
        }
    });
    connect(&m_myPcap, &MyPcap::send, this, &MainWindow::HandleMessage);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::showNetworkDevices()
{
    QStringList descriptionList;
    int devNum = 0;
    m_myPcap.getAllDevicesDescription(descriptionList);
    if(-1 == devNum)
    {
        ui->comboBox->addItem("get devices error!");
    }
    else
    {
        ui->comboBox->clear();
        ui->comboBox->addItem("please choose a device");
        ui->comboBox->addItems(descriptionList);
    }
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    if(0 == index)
    {
        return;
    }
    m_myPcap.setCurDevice(index - 1);
    DEBUG("%s", m_myPcap.getCurDeviceDescription().toStdString().data());
    return;
}

void MainWindow::HandleMessage(DataPackage data)
{
    qDebug() << data.getTimeStamp() << " " << data.getInfo();
}

