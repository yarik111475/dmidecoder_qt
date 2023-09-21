#ifndef ENTRY_H
#define ENTRY_H

#include <QString>

struct Entry
{
    //dmi anchor (must be _SM_, _SM3_ or _DMI_)
    QString epAnchor_ {};

    //entry point length
    unsigned short epLength_ {0};

    //smbios major version
    unsigned short epMajorVersion_ {};

    //smbios minor version
    unsigned short epMinorVersion_ {};

    //structures size
    int epMaxStructureSize_ {};

    //revision
    unsigned short epRevision_ {};

    //length of dmi table
    int epTableLength_ {};

    //structures count in dmi table
    int epNumberOfStructures_ {};
};

#endif // ENTRY_H
