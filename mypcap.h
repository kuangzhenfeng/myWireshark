#ifndef MYPCAP_H
#define MYPCAP_H

#include <QString>
#include <QThread>
#include <QVector>
#include "pcap.h"
#include "datapackage.h"


class MyPcap: public QThread
{
    Q_OBJECT
public:
    MyPcap();
    ~MyPcap();
    QString getCurDeviceDescription();
    int getAllDevicesDescription(QStringList &descriptionList);
    void setCurDevice(int index);
    int capture();
    int stopCapture();
    void run() override;
    int ethernetPackageHandle(const u_char *pkgContent, QString &info);
    int ipPackageHandle(const u_char *pkgContent, int &ipPackage);
    int tcpPackageHandle(const u_char *pkgContent, QString &info, int ipPackage);
    int udpPackageHandle(const u_char *pkgContent, QString &info);
    QString arpPackageHandle(const u_char *pkgContent);
    QString dnsPackageHandle(const u_char *pkgContent);
    QString icmpPackageHandle(const u_char *pkgContent);

signals:
    void send(DataPackage data);

private:
    QString byteToString(u_char *str, int size);

    pcap_if_t *m_pAllDevice;            // 所有网卡设备
    pcap_if_t *m_pCurDevice;            // 当前网卡设备
    pcap_t *m_pPcap;                    // 设备描述符
    char m_errBuf[PCAP_ERRBUF_SIZE];    // 存储错误信息

    struct pcap_pkthdr *m_pHeader;      // 数据包头
    const u_char *m_pktData;            // 数据包内容
    bool m_bRun;
};

#endif // MYPCAP_H
