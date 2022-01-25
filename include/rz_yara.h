// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_YARA_H
#define RZ_YARA_H
#include <rz_core.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_YARA_FLAG_SPACE        "yara"
#define RZ_YARA_FLAG_SPACE_STRING RZ_YARA_FLAG_SPACE ".str"
#define RZ_YARA_FLAG_SPACE_BYTES  RZ_YARA_FLAG_SPACE ".bytes"
#define RZ_YARA_FLAG_SPACE_ASM    RZ_YARA_FLAG_SPACE ".asm"

#define RZ_YARA_FLAG_PREFIX_STRING RZ_YARA_FLAG_SPACE_STRING "."
#define RZ_YARA_FLAG_PREFIX_BYTES  RZ_YARA_FLAG_SPACE_BYTES "."
#define RZ_YARA_FLAG_PREFIX_ASM    RZ_YARA_FLAG_SPACE_ASM "."

typedef HtPP /*<const char*, const char*>*/ RzYaraMeta;

typedef struct YR_RULE RzYaraRule;
typedef struct YR_RULES RzYaraRules;
typedef struct _YR_COMPILER RzYaraCompiler;
typedef struct YR_SCAN_CONTEXT RzYaraScanner;
typedef void (*RzYaraCompilerErrorCb)(bool is_warning, const char* file_name, int line_number,
    const RzYaraRule* rule, const char* message, void* user_data);
typedef void (*RzYaraRulesCb)(void *cb_data, const char* identifier, const char* tags);

RZ_API void rz_yara_rules_free(RZ_NULLABLE RzYaraRules *rules);
RZ_API void rz_yara_rules_foreach(RZ_NONNULL RzYaraRules *rules, RZ_NONNULL RzYaraRulesCb callback, void *cb_data);

RZ_API RZ_OWN RzYaraCompiler *rz_yara_compiler_new(RZ_NULLABLE RzYaraCompilerErrorCb callback, RZ_NULLABLE void *cb_data);
RZ_API bool rz_yara_compiler_parse_string(RZ_NONNULL RzYaraCompiler *compiler, RZ_NONNULL char *string);
RZ_API bool rz_yara_compiler_parse_file(RZ_NONNULL RzYaraCompiler *compiler, RZ_NONNULL const char *filename);
RZ_API void rz_yara_compiler_free(RZ_NULLABLE RzYaraCompiler *compiler);
RZ_API RZ_OWN RzYaraRules *rz_yara_compiler_get_rules_and_free(RZ_NONNULL RzYaraCompiler *compiler);

RZ_API RZ_OWN RzYaraScanner *rz_yara_scanner_new(RZ_NONNULL RzYaraRules *rules, int timeout_secs);
RZ_API void rz_yara_scanner_free(RZ_NULLABLE RzYaraScanner *scanner);
RZ_API RzList /*<char *>*/ *rz_yara_scanner_search(RZ_NONNULL RzYaraScanner *scanner, RZ_NONNULL RzCore *core);

RZ_API RZ_OWN RzYaraMeta *rz_yara_metadata_new();
RZ_API void rz_yara_metadata_free(RZ_NULLABLE RzYaraMeta *metadata);
RZ_API char *rz_yara_create_rule_from_bytes(RZ_NONNULL RzCore *core, RZ_NULLABLE RzYaraMeta *metadata, RZ_NONNULL const char *name);


#ifdef __cplusplus
}
#endif

#endif /* RZ_YARA_H */
