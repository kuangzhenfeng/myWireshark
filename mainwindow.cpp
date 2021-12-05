#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include <QString>
#include <QDebug>
#include "commonDebug.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    m_dataPackageCount = 0;
    m_currentRow = -1;
    ui->setupUi(this);
    statusBar()->showMessage("myWireshark");
    ui->toolBar->addAction(ui->actionrun_and_stop);
    ui->toolBar->addAction(ui->actionclear);
    ui->toolBar->setMovable(false);

    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    QStringList title = {"NO", "Time", "Source", "Destination", "Protocol", "Length", "Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);
    ui->tableWidget->setColumnWidth(0, 50);
    ui->tableWidget->setColumnWidth(1, 150);
    ui->tableWidget->setColumnWidth(2, 300);
    ui->tableWidget->setColumnWidth(3, 300);
    ui->tableWidget->setColumnWidth(4, 100);
    ui->tableWidget->setColumnWidth(5, 100);
    ui->tableWidget->setColumnWidth(6, 1000);

    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->verticalHeader()->setVisible(false);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);

    showNetworkDevices();
    m_myPcap.setCurDevice(11);   // kzf for test
    static bool bStart = false;
    connect(ui->actionrun_and_stop, &QAction::triggered, this, [=](){
        bStart = !bStart;
        if(bStart)
        {
            // 开始
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            m_dataPackageCount = 0;
            int dataSize = m_dataPackage.size();
            for(int i = 0; i < dataSize; ++i)
            {
                m_dataPackage[i].resetPktContent();
            }
            QVector<DataPackage>().swap(m_dataPackage); // 清空m_dataPackage
            int res = m_myPcap.capture();
            if(0 == res)
            {
                statusBar()->showMessage(m_myPcap.getCurDeviceDescription());
                ui->actionrun_and_stop->setIcon(QIcon(":/resources/stop.png"));
                ui->comboBox->setEnabled(false);
            }
            else
            {
                bStart = !bStart;
                m_dataPackageCount = 0;
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
    int dataSize = m_dataPackage.size();
    for(int i = 0; i < dataSize; ++i)
    {
        m_dataPackage[i].resetPktContent();
    }
    QVector<DataPackage>().swap(m_dataPackage); // 清空m_dataPackage
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
    ui->tableWidget->insertRow(m_dataPackageCount);
    m_dataPackage.push_back(data);
    QString type = data.getPackageType();
    QColor color;
    if(type == "TCP")
        color = QColor(216, 191, 216);
    else if(type == "UDP")
        color = QColor(144, 238, 144);
    else if(type == "ARP")
        color = QColor(238, 238, 0);
    else if(type == "DNS")
        color = QColor(255, 255, 254);
    else
        color = QColor(255, 218, 185);

    ui->tableWidget->setItem(m_dataPackageCount, 0, new QTableWidgetItem(QString::number(m_dataPackageCount)));
    ui->tableWidget->setItem(m_dataPackageCount, 1, new QTableWidgetItem(data.getTimeStamp()));
    ui->tableWidget->setItem(m_dataPackageCount, 2, new QTableWidgetItem(data.getSource()));
    ui->tableWidget->setItem(m_dataPackageCount, 3, new QTableWidgetItem(data.getDestination()));
    ui->tableWidget->setItem(m_dataPackageCount, 4, new QTableWidgetItem(data.getPackageType()));
    ui->tableWidget->setItem(m_dataPackageCount, 5, new QTableWidgetItem(data.getDataLength()));
    ui->tableWidget->setItem(m_dataPackageCount, 6, new QTableWidgetItem(data.getInfo()));
    for(int i = 0; i < 7; ++i)
    {
        ui->tableWidget->item(m_dataPackageCount, i)->setBackground(color);
    }
    ++m_dataPackageCount;
}


void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    if(row == m_currentRow || row < 0)
    {
        return;
    }
    ui->treeWidget->clear();
    m_currentRow = row;
    QString desMac = m_dataPackage[m_currentRow].getDesMacAddr();
    QString srcMac = m_dataPackage[m_currentRow].getSrcMacAddr();
    QString type = m_dataPackage[m_currentRow].getMacType();
    QString tree = "Ethernet, Src: " + srcMac + " Dst: " + desMac;
//    QTreeWidgetItem *item = new QTreeWidgetItem(QStringList(tree));
     QTreeWidgetItem *item = new QTreeWidgetItem(QStringList() << tree);
     ui->treeWidget->addTopLevelItem(item);
     item->addChild(new QTreeWidgetItem(QStringList("Destination: " + desMac)));
     item->addChild(new QTreeWidgetItem(QStringList("Source: " + srcMac)));
     item->addChild(new QTreeWidgetItem(QStringList("type: " + type)));




}

