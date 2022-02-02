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

#define YARA_CFG_TAGS_DFLT       ""
#define YARA_CFG_EXTENSIONS_DFLT ".yar,.yara"
#define YARA_CFG_DATE_FMT_DFLT   "%Y-%m-%d"
#define YARA_CFG_TIMEOUT_DFLT    (5 * 60)
#define YARA_CFG_FASTMODE_DFLT   false

#define YARA_CFG_TAGS_DETAILS       "yara rule tags uses when generating rules (space separated)."
#define YARA_CFG_EXTENSIONS_DETAILS "yara file extensions, comma separated (default " YARA_CFG_EXTENSIONS_DFLT ")."
#define YARA_CFG_DATE_FMT_DETAILS   "yara metadata date format (uses strftime for formatting)."
#define YARA_CFG_TIMEOUT_DETAILS    "yara scanner timeout in seconds (default: 5mins)."
#define YARA_CFG_FASTMODE_DETAILS   "yara scanner fast mode, skips multiple matches (default: false)."

#define YARA_KEYWORD_HASH_MD5     "md5"
#define YARA_KEYWORD_HASH_SHA1    "sha1"
#define YARA_KEYWORD_HASH_SHA2    "sha2"
#define YARA_KEYWORD_HASH_SHA256  "sha256"
#define YARA_KEYWORD_HASH_CRC32   "crc32"
#define YARA_KEYWORD_HASH_ENTROPY "entropy"
#define YARA_KEYWORD_DATE         "date"
#define YARA_KEYWORD_TIME         "time"
#define YARA_KEYWORD_CREATION     "creation"
#define YARA_KEYWORD_TIMESTAMP    "timestamp"
#define YARA_KEYWORD_TRUE         "true"
#define YARA_KEYWORD_FALSE        "false"

#define yara_stricmp(s, c) rz_str_ncasecmp(s, c, strlen(c))

static inline bool is_keyword_hash(const char *key) {
	return !yara_stricmp(key, YARA_KEYWORD_HASH_MD5) ||
		!yara_stricmp(key, YARA_KEYWORD_HASH_SHA1) ||
		!yara_stricmp(key, YARA_KEYWORD_HASH_SHA2) || // alias for sha256
		!yara_stricmp(key, YARA_KEYWORD_HASH_SHA256) ||
		!yara_stricmp(key, YARA_KEYWORD_HASH_CRC32) ||
		!yara_stricmp(key, YARA_KEYWORD_HASH_ENTROPY);
}

static inline bool is_keyword_date(const char *key) {
	return !yara_stricmp(key, YARA_KEYWORD_DATE) ||
		!yara_stricmp(key, YARA_KEYWORD_TIME) ||
		!yara_stricmp(key, YARA_KEYWORD_TIMESTAMP) ||
		!yara_stricmp(key, YARA_KEYWORD_CREATION);
}

static inline bool is_keyword_boolean(const char *key) {
	return !yara_stricmp(key, YARA_KEYWORD_TRUE) ||
		!yara_stricmp(key, YARA_KEYWORD_FALSE);
}

#endif /* RZ_YARA_COMMON_H */
