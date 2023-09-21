#include <QPair>
#include <QDebug>
#include <QVector>
#include <QString>
#include <QJsonDocument>
#include <iostream>

#include "dmi/decoder.h"
#include "dmi/structure.h"

int main(int argc,char* argv[]){
    Decoder dmi_decoder{};
    try{
        const QVector<QPair<QString,QString>>& dmiList {dmi_decoder.decodeInformation()};
        if(!dmiList.empty()){
            for(const QPair<QString,QString>& dmi: dmiList){
                if(!dmi.second.isEmpty()){
                    QJsonDocument doc=QJsonDocument::fromJson(dmi.second.toUtf8());
                    std::cout<<dmi.second.toStdString();
                }
            }
        }
        else{
            if(!dmi_decoder.error().isEmpty()){
                std::cerr<<dmi_decoder.error().toStdString()<<std::endl;
                std::getchar();
                return EXIT_FAILURE;
            }
        }
    }catch(const std::exception& ex){
        std::cout<<"error: "<<ex.what()<<std::endl;
    }

    std::getchar();
    return EXIT_SUCCESS;
}
