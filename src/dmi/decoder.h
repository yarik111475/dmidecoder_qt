#ifndef DECODER_H
#define DECODER_H

#include <QPair>
#include <QString>
#include <QVector>
#include <QByteArray>
#include <QJsonArray>
#include <QJsonObject>
#include <QStringList>

#include "entry.h"
#include "structure.h"

class Decoder
{
private:
    QString errorStr_ {};
    //const std::string entry_path_ {"/home/yaroslav/dmi_tables/centos/smbios_entry_point"};
    //const std::string table_path_ {"/home/yaroslav/dmi_tables/centos/DMI"};

    //const std::string entry_path_ {"C:\\tables\\smbios_entry_point"};
    //const std::string table_path_ {"C:\\tables\\DMI"};


    const QString entryPath_ {"/sys/firmware/dmi/tables/smbios_entry_point"};
    const QString tablePath_ {"/sys/firmware/dmi/tables/DMI"};
    QStringList anchors_ {};
    bool checksum(const QByteArray &data);

    Entry t_point_;
    Structure t_structure_;
    QVector<Structure> structureList_ {};
    QVector<QPair<QString,QString>> dmiList_{};

    bool decodeEntry();
    QVector<Structure> decodeTable();
    QJsonObject decodeStructure(const Structure& dmi, int type);

public:
    explicit Decoder(){
        //fill predefined anchors
        anchors_.push_back("_SM_");
        anchors_.push_back("_SM3_");
    };
    ~Decoder()=default;
    inline QString error()const{
        return errorStr_;
    } 
    QVector<QPair<QString,QString>> decodeInformation();

private:
    //Type 0
    QJsonObject biosInformation(const Structure& dmi);

    //Type 1
    QJsonObject systemInformation(const Structure& dmi);

    //Type 2
    QJsonObject baseboardInformation(const Structure& dmi);

    //Type 3
    QJsonObject chassisInformation(const Structure& dmi);

    //Type 4
    QJsonObject processorInformation(const Structure& dmi);

    //Type 5, Obsolete
    QJsonObject memoryControllerInformation(const Structure& dmi);

    //Type 6, Obsolete
    QJsonObject memoryModuleInformation(const Structure& dmi);

    //Type 7
    QJsonObject cacheInformation(const Structure& dmi);

    //Type 8
    QJsonObject portConnectorInformation(const Structure& dmi);

    //Type 9
    QJsonObject systemSlotInformation(const Structure& dmi);

    //Type 10
    QJsonObject onboardDeviceInformation(const Structure& dmi);

    //Type 11
    QJsonObject oemStrings(const Structure& dmi);

    //Type 12
    QJsonObject systemConfigurationOptions(const Structure& dmi);

    //Type 13
    QJsonObject biosLanguageInformation(const Structure& dmi);

    //for decode additional structures with associations
    void groupAssociations(const Structure& dmi);

    //Type 16
    QJsonObject physicalMemoryArray(const Structure& dmi);

    //Type 17
    QJsonObject memoryDevice(const Structure& dmi);

    //Type 18
    QJsonObject memoryErrorInformation(const Structure& dmi);

    //Type 21
    QJsonObject builtinPointingDevice(const Structure& dmi);

    //Type 22
    QJsonObject portableBattery(const Structure& dmi);

    //Type 26
    QJsonObject voltageProbe(const Structure& dmi);

    //Type 27
    QJsonObject coolingDevice(const Structure& dmi);

    //Type 28
    QJsonObject temperatureProbe(const Structure& dmi);

    //Type 29
    QJsonObject electricalCurrentProbe(const Structure& dmi);

    //Type 34
    QJsonObject managementDeviceInformation(const Structure& dmi);

    //Type 41, Obsolete
    QJsonObject onboardDeviceExtendedInformation(const Structure& dmi);

    //Type 44
    QJsonObject processorAdditionalInformation(const Structure& dmi);
};

#endif // DECODER_H
