#ifndef STRUCTURE_H
#define STRUCTURE_H

#include <QString>
#include <QByteArray>
#include <QStringList>

struct Structure
{
    //type
    int type_ {};
    //length of data block (exclude strings block)
    int length_ {};
    //handle
    int handle_ {};
    //data block
    QByteArray data_ {};
    //strings block
    QStringList strings_ {};

    explicit Structure()=default;
    explicit Structure(int type, int length,int handle,const QByteArray& data,const QStringList& strings)
        :type_{type},length_{length},handle_{handle},data_{data},strings_{strings}{
    }
};

#endif // STRUCTURE_H
