#include "mypcap.h"
#include <QDebug>

MyPcap::MyPcap()
{
    m_bRun = false;
}

QString MyPcap::getCurDeviceDescription()
{
    if(!m_pCurDevice)
    {
        return QString();
    }
    return m_pCurDevice->description;
}

int MyPcap::getAllDevicesDescription(QStringList &descriptionList)
{
    int devNum = 0;
    devNum = pcap_findalldevs(&m_pAllDevice, m_errBuf);
    if(-1 == devNum)
    {
        qDebug() << "error: " << m_errBuf;
        descriptionList = QStringList();
        return devNum;
    }
    for(pcap_if_t *device = m_pAllDevice; device != nullptr; device = device->next)
    {
        descriptionList.append(device->description);
    }
    return devNum;
}

void MyPcap::setCurDevice(int index)
{
    m_pCurDevice = m_pAllDevice;
    for(int i = 0; i < index; ++i)
    {
        m_pCurDevice = m_pCurDevice->next;
    }
}

int MyPcap::capture()
{
    qDebug("start capture");
    if(!m_pCurDevice)
    {
        return -1;
    }
    m_pPcap = pcap_open_live(m_pCurDevice->name, 65536, 1, 1000, m_errBuf);
    if(!m_pPcap)
    {
        pcap_freealldevs(m_pAllDevice);
        m_pCurDevice = nullptr;
        return -1;
    }
    if(pcap_datalink(m_pPcap) != DLT_EN10MB)
    {
        qDebug("Unsupported protocol, protocol=%d", pcap_datalink(m_pPcap));
        pcap_close(m_pPcap);
        m_pCurDevice = nullptr;
        m_pPcap = nullptr;
        return -1;
    }
    m_bRun = true;
    start();    // 开始线程
    return 0;
}

int MyPcap::stopCapture()
{
    qDebug("stop capture");
    if(!m_pPcap)
    {
        return -1;
    }
    m_bRun = false;
    quit();     // 退出线程
    wait();

    pcap_close(m_pPcap);
    m_pPcap = nullptr;
    return 0;
}

void MyPcap::run()
{
    int res = 0;
    struct tm localTime = {0};
    char timeString[16] = {0};
    while(m_bRun)
    {
        res = pcap_next_ex(m_pPcap, &m_pHeader, &m_pktData);
        if(0 == res)
        {
            continue;
        }
//        localtime_s(&localTime, &t);
//        strftime(timeString, sizeof(timeString), "%H:%M:%S", &localTime);
//        qDebug() << timeString;
//        localtime_s(&localTime, (time_t *)&m_pHeader->ts.tv_sec);     // 为什么不行
        time_t ts = m_pHeader->ts.tv_sec;
        localtime_s(&localTime, &ts);
        strftime(timeString, sizeof(timeString), "%H:%M:%S", &localTime);
        qDebug() << timeString;
    }
}
