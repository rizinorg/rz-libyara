// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef YARA_DESCRIPTION_H
#define YARA_DESCRIPTION_H

#include <QMetaType>

struct YaraDescription
{
    RVA offset;
    RVA size;
    QString name;
};

Q_DECLARE_METATYPE(YaraDescription)

struct MetadataDescription
{
    QString name;
    QString value;
};

Q_DECLARE_METATYPE(MetadataDescription)

#endif // YARA_DESCRIPTION_H