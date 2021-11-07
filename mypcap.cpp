#include "mypcap.h"
#include <QDebug>
#include "commonDebug.h"

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
        DEBUG("error: %s", m_errBuf);
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
    DEBUG("curDevice=%s", m_pCurDevice->description);
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
        qDebug("Unsupported protocol, curDevice=%s protocol=%d", m_pCurDevice->description, pcap_datalink(m_pPcap));
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
    DEBUG("curDevice=%s", m_pCurDevice->description);
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
        DEBUG("[%s] len=%u", timeString, m_pHeader->len);
        for(int i = 0; i < m_pHeader->len; ++i)
        {
            printf("%02X ", m_pktData[i]);
        }
        printf("\n");
        unsigned char desMac[6] = {0};
        unsigned char srcMac[6] = {0};
        unsigned char ipType[2] = {0};
        unsigned char skip[9] = {0};
        unsigned char protocol[1] = {0};
        unsigned char headerChecksum[2] = {0};
        unsigned char srcAddress[4] = {0};
        unsigned char desAddress[4] = {0};
        unsigned char srcPort[2] = {0};
        unsigned char desPort[2] = {0};
        int count = 0;
        for(int i = 0; i < 6; ++i)
        {
            desMac[i] = m_pktData[count++];
        }
        for(int i = 0; i < 6; ++i)
        {
            srcMac[i] = m_pktData[count++];
        }
        for(int i = 0; i < 2; ++i)
        {
            ipType[i] = m_pktData[count++];
        }
        for(int i = 0; i < 9; ++i)
        {
            skip[i] = m_pktData[count++];
        }
        for(int i = 0; i < 1; ++i)
        {
            protocol[i] = m_pktData[count++];
        }
        for(int i = 0; i < 2; ++i)
        {
            headerChecksum[i] = m_pktData[count++];
        }
        for(int i = 0; i < 4; ++i)
        {
            srcAddress[i] = m_pktData[count++];
        }
        for(int i = 0; i < 4; ++i)
        {
            desAddress[i] = m_pktData[count++];
        }
        for(int i = 0; i < 2; ++i)
        {
            srcPort[i] = m_pktData[count++];
        }
        for(int i = 0; i < 2; ++i)
        {
            desPort[i] = m_pktData[count++];
        }
        DEBUG("desMac=%02X:%02X:%02X:%02X:%02X:%02X", desMac[0], desMac[1], desMac[2], desMac[3], desMac[4], desMac[5]);
        DEBUG("srcMac=%02X:%02X:%02X:%02X:%02X:%02X", srcMac[0], srcMac[1], srcMac[2], srcMac[3], srcMac[4], srcMac[5]);
        DEBUG("ipType=0x%02X%02X", ipType[0], ipType[1]);
        DEBUG("skip");
        DEBUG("protocol=%d isTCP=%d isUDP=%d", protocol[0], 6 == protocol[0], 17 == protocol[0]);
        DEBUG("headerChecksum=0x%02X%02X", headerChecksum[0], headerChecksum[1]);
        DEBUG("srcAddress=%u.%u.%u.%u", srcAddress[0], srcAddress[1], srcAddress[2], srcAddress[3]);
        DEBUG("desAddress=%u.%u.%u.%u", desAddress[0], desAddress[1], desAddress[2], desAddress[3]);
        DEBUG("srcPort=%u", ((unsigned int)srcPort[0] << 8) + srcPort[1]);
        DEBUG("desPort=%u", ((unsigned int)desPort[0] << 8) + desPort[1]);
    }
}
