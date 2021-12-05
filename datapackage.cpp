#include "datapackage.h"
#include <QMetaType>
#include "winsock2.h"
#include "commonDebug.h"


DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    m_dataLength = 0;
    m_timeStamp = "";
    m_info = "";
    m_packageType = 0;
    m_pktContent = nullptr;
}

void DataPackage::setDataLength(u_int dataLength)
{
    m_dataLength = dataLength;
}

void DataPackage::setTimeStamp(QString timeStamp)
{
    m_timeStamp = timeStamp;
}

void DataPackage::setInfo(QString info)
{
    m_info = info;
}

void DataPackage::setPackageType(int type)
{
    m_packageType = type;
}

const u_char *DataPackage::getPktContent()
{
    return m_pktContent;
}

void DataPackage::setPktContent(const u_char *pktContent, int size)
{
    m_pktContent = (u_char *)malloc(size);        // kzf TODO:使用共享指针优化
    memcpy((char *)m_pktContent, pktContent, size);
}

void DataPackage::resetPktContent()
{
    if(m_pktContent != nullptr)
    {
        free((void *)m_pktContent);
        m_pktContent = nullptr;
    }
}

QString DataPackage::getDataLength()
{
    return QString::number(m_dataLength);
}

QString DataPackage::getTimeStamp()
{
    return m_timeStamp;
}

QString DataPackage::getInfo()
{
    return m_info;
}

QString DataPackage::getPackageType()
{
    switch (m_packageType) {
        case 1: return "ARP";
        case 2: return "ICMP";
        case 3: return "TCP";
        case 4: return "UDP";
        case 5: return "DNS";
        case 6: return "TLS";
        case 7: return "SSL";
        default: return "";
    }
}

QString DataPackage::getSource()
{
    if(m_packageType == 1)
    {
        return getSrcMacAddr();
    }
    else
    {
        return getSrcIpAddr();
    }
}

QString DataPackage::getDestination()
{
    if(m_packageType == 1)
    {
        return getDesMacAddr();
    }
    else
    {
        return getDesIpAddr();
    }
}

QString DataPackage::getDesMacAddr()
{
    ETHER_HEADER *eth;
    eth = (ETHER_HEADER *)(m_pktContent);
    u_char *addr = eth->ether_des_host;
    if(addr)
    {
        QString res = byteToString(addr, 1) + ":"
                + byteToString(addr + 1, 1) + ":"
                + byteToString(addr + 2, 1) + ":"
                + byteToString(addr + 3, 1) + ":"
                + byteToString(addr + 4, 1) + ":"
                + byteToString(addr + 5, 1);
        if(res == "FF:FF:FF:FF:FF:FF")
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        else
            return res;
    }
    return "";
}

QString DataPackage::getSrcMacAddr()
{
    ETHER_HEADER *eth;
    eth = (ETHER_HEADER *)(m_pktContent);
    u_char *addr = eth->ether_src_host;
    if(addr)
    {
        QString res = byteToString(addr, 1) + ":"
                + byteToString(addr + 1, 1) + ":"
                + byteToString(addr + 2, 1) + ":"
                + byteToString(addr + 3, 1) + ":"
                + byteToString(addr + 4, 1) + ":"
                + byteToString(addr + 5, 1);
        if(res == "FF:FF:FF:FF:FF:FF")
            return "FF:FF:FF:FF:FF:FF(Broadcast)";
        else
            return res;
    }
    return "";
}

QString DataPackage::getMacType()
{
    ETHER_HEADER *eth;
    eth = (ETHER_HEADER *)(m_pktContent);
    u_short type = ntohs(eth->ether_type);
    if(0x0800 == type) return "IPv4(0x0800)";
    else if(0x0806 == type) return "ARP(0x0806)";
    else return "";
}

QString DataPackage::getDesIpAddr()
{
    IP_HEADER *ip;
    ip = (IP_HEADER *)(m_pktContent + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}

QString DataPackage::getSrcIpAddr()
{
    IP_HEADER *ip;
    ip = (IP_HEADER *)(m_pktContent + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}

QString DataPackage::byteToString(u_char *str, int size)
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
