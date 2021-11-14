#include "datapackage.h"
#include <QMetaType>

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

void DataPackage::setPktContent(const u_char *pktContent, int size)
{
    memcpy((char *)m_pktContent, pktContent, size);
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

QString DataPackage::byteToString(char *str, int size)
{
    QString res = "";
    for(int i = 0; i < size; ++i)
    {
        char high = str[i] >> 4;
        char low = str[i] & 0x0F;
        high += '0';
        low += '0';
        res.append(high);
        res.append(low);
    }
    return res;
}

