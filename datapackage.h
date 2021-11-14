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
    void setPktContent(const u_char *pktContent, int size);


    QString getDataLength();
    QString getTimeStamp();
    QString getInfo();
    QString getPackageType();
//    QString getPktContent();

    const u_char *m_pktContent;

protected:
    static QString byteToString(char *str, int size);

private:
    u_int m_dataLength;
    QString m_timeStamp;
    QString m_info;
    int m_packageType;

};

#endif // DATAPACKAGE_H
