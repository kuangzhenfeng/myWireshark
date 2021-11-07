#ifndef MYPCAP_H
#define MYPCAP_H

#include <QString>
#include <QThread>
#include "pcap.h"


class MyPcap: public QThread
{
    Q_OBJECT
public:
    MyPcap();
    QString getCurDeviceDescription();
    int getAllDevicesDescription(QStringList &descriptionList);
    void setCurDevice(int index);
    int capture();
    int stopCapture();
    void run() override;

private:
    pcap_if_t *m_pAllDevice;            // 所有网卡设备
    pcap_if_t *m_pCurDevice;            // 当前网卡设备
    pcap_t *m_pPcap;                    // 设备描述符
    char m_errBuf[PCAP_ERRBUF_SIZE];    // 存储错误信息

    struct pcap_pkthdr *m_pHeader;      // 数据包头
    const u_char *m_pktData;            // 数据包内容
    bool m_bRun;
};

#endif // MYPCAP_H