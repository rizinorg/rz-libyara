// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_YARA_COMMON_H
#define RZ_YARA_COMMON_H
#include <yara.h>
#include <rz_yara.h>

#define YARA_ERROR(f, ...) RZ_LOG_ERROR("YARA: " f, ##__VA_ARGS__)
#define YARA_WARN(f, ...)  RZ_LOG_WARN("YARA: " f, ##__VA_ARGS__)
#define YARA_INFO(f, ...)  RZ_LOG_INFO("YARA: " f, ##__VA_ARGS__)

#endif /* RZ_YARA_COMMON_H */
