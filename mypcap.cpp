#include "mypcap.h"
#include <QDebug>
#include <winsock2.h>
#include "commonDebug.h"

MyPcap::MyPcap()
{
    m_bRun = false;
}

MyPcap::~MyPcap()
{
    stopCapture();
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
        // DEBUG("[%s] len=%u", timeString, m_pHeader->len);

        QString info = "";
        int type = ethernetPackageHandle(m_pktData, info);
        if(type)
        {
            DataPackage data;
            int len = m_pHeader->len;
            data.setInfo(info);
            data.setDataLength(len);
            data.setTimeStamp(timeString);
            data.setPackageType(type);
            data.setPktContent(m_pktData, len);
            emit send(data);
        }


#if 0
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
#endif
    }
}

int MyPcap::ethernetPackageHandle(const u_char *pkgContent, QString &info)
{
    ETHER_HEADER *ethenet;
    u_short contentType;
    ethenet = (ETHER_HEADER *)pkgContent;
    contentType = ntohs(ethenet->ether_type);
    switch(contentType)
    {
        case 0x0800:    // ip
        {
            int ipPackage = 0;
            int res = ipPackageHandle(pkgContent, ipPackage);
            if(1 == res)
            {
                // icmp
                info = icmpPackageHandle(pkgContent);
                return 2;
            }
            else if(6 == res)
            {
                // tcp
                return tcpPackageHandle(pkgContent, info, ipPackage);
            }
            else if(17 == res)
            {
                // udp
                return udpPackageHandle(pkgContent, info);
            }
            break;
        }
        case 0x806:     // arp
        {
            info = arpPackageHandle(pkgContent);
            return 1;
        }
        default:
            return 0;
    }
    return 0;
}

int MyPcap::ipPackageHandle(const u_char *pkgContent, int &ipPackage)
{
    IP_HEADER *ip;
    ip = (IP_HEADER *)(pkgContent + 14);
    int protocol = ip->protocol;
    ipPackage = ntohs(ip->total_length - ((ip->versiosn_head_length & 0x0F) * 4));
    return protocol;
}

int MyPcap::tcpPackageHandle(const u_char *pkgContent, QString &info, int ipPackage)
{
    TCP_HEADER *tcp;
    tcp = (TCP_HEADER *)(pkgContent + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);

    QString sendProtocol = "";
    QString recvProtocol = "";

    int type = 3;
    int tcpHeaderLen = (tcp->header_length >> 4) * 4;
    int tcpLoader = ipPackage - tcpHeaderLen;
    if(443 == src)
    {
        sendProtocol = "(https)";
    }
    else if(443 == des)
    {
        recvProtocol = "(https)";
    }
    if(443 == src || 443 == des)
    {
        u_char *ssl;
        ssl = (u_char *)(pkgContent + 14 + 20 + tcpHeaderLen);
        u_char isTls = *ssl;
        ++ssl;
        u_short version = ntohs(*ssl);
        if(isTls >= 20 && isTls <= 23 && version >=0x0301 && version <= 0x0304)
        {
            type = 6;
            switch(isTls) {
            case 20:
                info = "Change Cipher Spec";
                break;
            case 21:
                info = "Alert";
                break;
            case 22:
            {
                info = "Handshake";
                ssl += 4;
                u_char handShakeType = (*ssl);
                if(1 == handShakeType)
                {
                    info += " Client Hello";
                }
                else if(2 == handShakeType)
                {
                    info += " Server Hello";
                }
            }
                break;
            case 23:
                info = "Application Data";
                break;
            default:
                break;
            }
        }
        else
        {
            type = 7;
            info = "Continuation Data";
        }
    }
    info += QString::number(src) + sendProtocol + "->" + QString::number(des) + recvProtocol;

    QString flag = "";
    if(tcp->flags & 0x08) flag += "PSH,";
    if(tcp->flags & 0x10) flag += "ACK,";
    if(tcp->flags & 0x02) flag += "SYN,";
    if(tcp->flags & 0x20) flag += "URG,";
    if(tcp->flags & 0x01) flag += "FIN,";
    if(tcp->flags & 0x04) flag += "RST,";
    if(flag != "")
    {
        flag = flag.left(flag.length() - 1);
        info += "[" + flag + "]";
    }

    u_int sequence = ntohl(tcp->sequence);
    u_int ack = ntohl(tcp->ack);
    u_int windowSize = ntohl(tcp->window_size);

    info += " seq=" + QString::number(sequence) + "ack=" + QString::number(ack) + "win=" + QString::number(windowSize) + "len=" + QString::number(tcpLoader);

    return type;
}

int MyPcap::udpPackageHandle(const u_char *pkgContent, QString &info)
{
    UDP_HEADER *udp;
    udp = (UDP_HEADER *)(pkgContent + 14 + 20);
    u_short src = ntohs(udp->src_port);
    u_short des = ntohs(udp->des_port);
    if(53 == src || 53 == des)
    {
        // DNS
        info = dnsPackageHandle(pkgContent);
        return 5;
    }
    QString res = QString::number(src) + "->" + QString::number(des);
    u_short dataLen = ntohs(udp->data_length);
    res += "len=" + QString::number(dataLen);
    info = res;
    return 4;
}

QString MyPcap::arpPackageHandle(const u_char *pkgContent)
{
    ARP_HEADER *arp;
    arp = (ARP_HEADER *)(pkgContent + 14);

    u_short op = ntohs(arp->op_code);
    QString res = "";
    QString srcIp = QString::number(arp->src_ip_addr[0]) + "." +
                    QString::number(arp->src_ip_addr[1]) + "." +
                    QString::number(arp->src_ip_addr[2]) + "." +
                    QString::number(arp->src_ip_addr[3]);
    QString desIp = QString::number(arp->des_ip_addr[0]) + "." +
                    QString::number(arp->des_ip_addr[1]) + "." +
                    QString::number(arp->des_ip_addr[2]) + "." +
                    QString::number(arp->des_ip_addr[3]);

    QString srcEth = byteToString(&arp->src_eth_addr[0], 1) + ":" +
                     byteToString(&arp->src_eth_addr[1], 1) + ":" +
                     byteToString(&arp->src_eth_addr[2], 1) + ":" +
                     byteToString(&arp->src_eth_addr[3], 1) + ":" +
                     byteToString(&arp->src_eth_addr[4], 1) + ":" +
                     byteToString(&arp->src_eth_addr[5], 1);
//    QString desEth = byteToString(&arp->des_eth_addr[0], 1) + "." +
//                     byteToString(&arp->des_eth_addr[1], 1) + ":" +
//                     byteToString(&arp->des_eth_addr[2], 1) + ":" +
//                     byteToString(&arp->des_eth_addr[3], 1) + ":" +
//                     byteToString(&arp->des_eth_addr[4], 1) + ":" +
//                     byteToString(&arp->des_eth_addr[5], 1);

    if(1 == op)
    {
        // 询问
        res = "who has " +desIp + "? Tell " +srcIp;
    }
    else if(2 == op)
    {
        // 应答
       res = srcIp + " is at " + srcEth;
    }
    return res;
}

QString MyPcap::dnsPackageHandle(const u_char *pkgContent)
{
    DNS_HEADER *dns;
    dns = (DNS_HEADER *)(pkgContent + 14 + 20 + 8);
    u_short identification = ntohs(dns->identification);
    u_short type = dns->flags;
    QString info = "";
    if((type & 0xf800) == 0x0000)
    {
        info = "Standard query";
    }
    else if((type & 0xf800) == 0x8000)
    {
        info = "Standard query response";
    }
    QString name = "";
    char *domain = (char *)(pkgContent + 14 + 20 + 8 + 12);
    while(*domain != 0x00)
    {
        if(!domain)
        {
            break;
        }
        int length = *domain;
        ++domain;
        for(int i = 0; i < length; ++i)
        {
            name += *domain;
            ++domain;
        }
        name += ".";
    }
    if(name != "")
    {
        // 去掉最后一个'.'
        name = name.left(name.length() - 1);
    }
    return info + " 0x" +QString::number(identification, 16) + " " + name;
}

QString MyPcap::icmpPackageHandle(const u_char *pkgContent)
{
    ICMP_HEADER *icmp;
    icmp =(ICMP_HEADER *)(pkgContent + 14 + 20);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString res = "";
    switch(type)
    {
    case 0:
        if(!code)
        {
            res = "Echo response(ping)";
        }
        break;
    case 8:
        if(!code)
        {
            res = "Echo request(ping)";
        }
        break;
    default:
        break;
    }
    return res;
}

QString MyPcap::byteToString(u_char *str, int size)
{
    QString res = "";
    for(int i = 0; i < size; ++i)
    {
        char high = str[i] >> 4;
        if(high < 0x0A)
            high += '0';
        else
            high += 'A' - 0x0A;
        char low = str[i] & 0x0F;
        if(low < 0x0A)
            low += '0';
        else
            low += 'A' - 0x0A;
        res.append(high);
        res.append(low);
    }
    return res;
}

