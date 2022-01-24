// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include "yara_common.h"

/** \file yara_parser.c
 * Rizin wrapper around libyara for parsing and applying rules
 */

#define YARA_BUFFER_SIZE (1024 * 1024)

typedef struct yara_rz_io_t {
	RzCore *core;
	ut64 offset;
	ut8 *buffer;
	ut64 buffer_size;
	YR_MEMORY_BLOCK block;
} YaraRzIO;

RZ_API void rz_yara_rules_free(RZ_NULLABLE RzYaraRules *rules) {
	if (!rules) {
		return;
	}
	yr_rules_destroy(rules);
}

RZ_API void rz_yara_rules_foreach(RZ_NONNULL RzYaraRules *rules, RZ_NONNULL RzYaraRulesCb callback, void *cb_data) {
	rz_return_if_fail(rules && callback);
	YR_RULE *rule;
	yr_rules_foreach(rules, rule) {
		callback(cb_data, rule->identifier, rule->tags);
	}
}

RZ_API RZ_OWN RzYaraCompiler *rz_yara_compiler_new(RZ_NULLABLE RzYaraCompilerErrorCb callback, RZ_NULLABLE void *cb_data) {
	RzYaraCompiler *compiler = NULL;
	if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
		YARA_ERROR("Cannot allocate yara compiler\n");
		return NULL;
	}

	if (callback) {
		yr_compiler_set_callback(compiler, (YR_COMPILER_CALLBACK_FUNC)callback, cb_data);
	}

	return compiler;
}

RZ_API void rz_yara_compiler_free(RZ_NULLABLE RzYaraCompiler *compiler) {
	if (!compiler) {
		return;
	}
	yr_compiler_destroy(compiler);
}

// Per Yara APIs, you cannot add more rules (via the compiler) after you get them.
RZ_API RZ_OWN RzYaraRules *rz_yara_compiler_get_rules_and_free(RZ_NULLABLE RzYaraCompiler *compiler) {
	rz_return_val_if_fail(compiler, NULL);
	YR_RULES *rules = NULL;
	if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS) {
		YARA_ERROR("Cannot allocate memory for the yara rules\n");
	}
	yr_compiler_destroy(compiler);
	return rules;
}

RZ_API bool rz_yara_compiler_parse_string(RZ_NONNULL RzYaraCompiler *compiler, RZ_NONNULL char *string) {
	rz_return_val_if_fail(compiler && RZ_STR_ISNOTEMPTY(string), false);
	return yr_compiler_add_string(compiler, string, NULL) != ERROR_SUCCESS;
}

RZ_API bool rz_yara_compiler_parse_file(RZ_NONNULL RzYaraCompiler *compiler, RZ_NONNULL const char *filename) {
	rz_return_val_if_fail(compiler && filename, false);
	bool ret = true;
	FILE *fd = rz_sys_fopen(filename, "rb");
	if (!fd) {
		YARA_ERROR("'%s' does not exists\n", filename);
		return false;
	}
	const char *basename = rz_file_basename(filename);
	if (yr_compiler_add_file(compiler, fd, NULL, basename) != ERROR_SUCCESS) {
		ret = false;
	}
	fclose(fd);
	return ret;
}

RZ_API RZ_OWN RzYaraScanner *rz_yara_scanner_new(RZ_NONNULL RzYaraRules *rules, int timeout_secs) {
	rz_return_val_if_fail(rules, NULL);
	YR_SCANNER *scanner = NULL;
	if (yr_scanner_create(rules, &scanner) != ERROR_SUCCESS) {
		YARA_ERROR("Cannot allocate yara scanner\n");
		return NULL;
	}
	yr_scanner_set_timeout(scanner, timeout_secs);
	yr_scanner_set_flags(scanner, SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING);
	return scanner;
}

RZ_API void rz_yara_scanner_free(RZ_NULLABLE RzYaraScanner *scanner) {
	if (!scanner) {
		return;
	}
	yr_scanner_destroy(scanner);
}

static int yara_scanner_add_match_to_list(YR_SCAN_CONTEXT *context, int msg_type, void *data, void *cb_data) {
	if (msg_type == CALLBACK_MSG_RULE_MATCHING) {
		RzList *matches = (RzList *)cb_data;
		YR_RULE *rule = (YR_RULE *)data;
		char *identifier = strdup(rule->identifier);
		if (!identifier || !rz_list_append(matches, identifier)) {
			free(identifier);
			return CALLBACK_ABORT;
		}
	}
	return CALLBACK_CONTINUE;
}

static YR_MEMORY_BLOCK *yara_rz_io_next_block(YR_MEMORY_BLOCK_ITERATOR *iterator) {
	YaraRzIO *yio = (YaraRzIO *)iterator->context;
	int read = rz_io_pread_at(yio->core->io, yio->offset, yio->buffer, YARA_BUFFER_SIZE);
	if (read < 1) {
		return NULL;
	} else {
		yio->block.size = read;
		yio->offset += read;
	}
	return &yio->block;
}

static YR_MEMORY_BLOCK *yara_rz_io_get_first_block(YR_MEMORY_BLOCK_ITERATOR *iterator) {
	YaraRzIO *yio = (YaraRzIO *)iterator->context;
	yio->offset = 0;
	return yara_rz_io_next_block(iterator);
}

static uint64_t yara_rz_io_file_size(YR_MEMORY_BLOCK_ITERATOR *iterator) {
	YaraRzIO *yio = (YaraRzIO *)iterator->context;
	return rz_io_size(yio->core->io);
}

static const uint8_t *yara_rz_io_fetch_block(YR_MEMORY_BLOCK *block) {
	YaraRzIO *yio = (YaraRzIO *)block->context;
	return yio->buffer + block->base;
}

RZ_API RzList /*<char *>*/ *rz_yara_scanner_search(RZ_NONNULL RzYaraScanner *scanner, RZ_NONNULL RzCore *core) {
	rz_return_val_if_fail(scanner && core, NULL);
	YR_MEMORY_BLOCK_ITERATOR it = { 0 };
	YaraRzIO yio = { 0 };
	RzList *matches = rz_list_newf(free);
	if (!matches) {
		YARA_ERROR("Cannot allocate yara matches list\n");
		return NULL;
	}

	ut8 *buffer = malloc(YARA_BUFFER_SIZE);
	if (!buffer) {
		YARA_ERROR("Cannot allocate memory buffer\n");
		return NULL;
	}
	yio.core = core;
	yio.buffer = buffer;
	yio.block.context = &yio;
	yio.block.fetch_data = yara_rz_io_fetch_block;
	it.context = &yio;
	it.last_error = ERROR_SUCCESS;
	it.first = yara_rz_io_get_first_block;
	it.next = yara_rz_io_next_block;
	it.file_size = yara_rz_io_file_size;

	yr_scanner_set_callback(scanner, yara_scanner_add_match_to_list, matches);
	yr_scanner_scan_mem_blocks(scanner, &it);
	yr_scanner_set_callback(scanner, NULL, NULL);
	free(buffer);
	return matches;
}