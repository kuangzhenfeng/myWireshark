#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H

#include <QString>
#include "Format.h"



class DataPackage
{
public:
    DataPackage();
    void setDataLength(u_int dataLength);
    void setTimeStamp(QString timeStamp);
    void setInfo(QString info);
    void setPackageType(int type);
    const u_char *getPktContent();
    void setPktContent(const u_char *pktContent, int size);
    void resetPktContent();



    QString getDataLength();
    QString getTimeStamp();
    QString getInfo();
    QString getPackageType();
    QString getSource();
    QString getDestination();
    QString getDesMacAddr();
    QString getSrcMacAddr();
    QString getDesIpAddr();
    QString getSrcIpAddr();



protected:
    static QString byteToString(u_char *str, int size);

private:
    const u_char *m_pktContent;
    u_int m_dataLength;
    QString m_timeStamp;
    QString m_info;
    int m_packageType;

};

#endif // DATAPACKAGE_H
