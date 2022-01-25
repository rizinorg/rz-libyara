// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include "yara_common.h"
#include <stdio.h>
#include <time.h>

/** \file yara_generator.c
 * YARA rule generator
 * Generates rules like below:
 *
 * rule some_rule_name : Foo Bar Baz
 * {
 *     meta:
 *         author = "john foo"
 *         project = "the foo project"
 *         creation_date = "Mon Jan 24 12:56:21 2022 UTC+1"
 *
 *     strings:
 *         $chunk_0 = {
 *             6A 40 68 00
 *             30 00 00 6A
 *             14 8D 91
 *         }
 *
 *     condition:
 *         $chunk_0
 * }
 */

typedef struct yara_cb_data_t {
	RzStrBuf *sb;
	RzCore *core;
	const char *date_format;
} YaraCbData;

static void yara_metadata_free_kv(HtPPKv *kv) {
	free(kv->key);
	free(kv->value);
}

RZ_API RZ_OWN RzYaraMeta *rz_yara_metadata_new() {
	return ht_pp_new((HtPPDupValue)strdup, (HtPPKvFreeFunc)yara_metadata_free_kv, (HtPPCalcSizeV)strlen);
}

RZ_API void rz_yara_metadata_free(RZ_NULLABLE RzYaraMeta *metadata) {
	ht_pp_free(metadata);
}

static bool add_metadata(YaraCbData *cd, const char *k, const char *v) {
	if (!strcmp(v, "true") || !strcmp(v, "false") || rz_is_valid_input_num_value(NULL, v)) {
		rz_strbuf_appendf(cd->sb, "\t\t%s = %s\n", k, v);
	} else if ((!strcmp(k, "date") || !strcmp(k, "timestamp")) && RZ_STR_ISEMPTY(v)) {
		char buffer[0x100];
		const char *fmt = rz_config_get(cd->core->config, RZ_YARA_CFG_DATE_FMT);
		if (RZ_STR_ISEMPTY(fmt)) {
			YARA_WARN("date format is invalid.\n");
		} else {
			time_t timer = time(NULL);
			struct tm *tm_info = localtime(&timer);
			strftime(buffer, sizeof(buffer), fmt, tm_info);
			rz_strbuf_appendf(cd->sb, "\t\t%s = \"%s\"\n", k, buffer);
		}
	} else {
		rz_strbuf_appendf(cd->sb, "\t\t%s = \"%s\"\n", k, v);
	}
	return true;
}

static bool flag_foreach_add_string(RzFlagItem *fi, YaraCbData *cd) {
	ut8 buffer[0x1000] = { 0 };
	const char *name = fi->name + strlen(RZ_YARA_FLAG_PREFIX_STRING);
	if (RZ_STR_ISEMPTY(name)) {
		YARA_WARN("invalid flag name: %s (skipping)\n", fi->name);
		return true;
	}

	int read = RZ_MIN(fi->size, sizeof(buffer));
	if (!rz_io_read_at_mapped(cd->core->io, fi->offset, buffer, read)) {
		YARA_WARN("cannot read yara string %s (skipping)\n", fi->name);
		return true;
	}
	buffer[RZ_MIN(fi->size, sizeof(buffer) - 1)] = 0;

	rz_strbuf_appendf(cd->sb, "\t\t// offset: 0x%" PFMT64x ", size: 0x%x\n", fi->offset, read);

	char *ek = rz_str_escape_utf8_for_json((char *)buffer, -1);
	rz_strbuf_appendf(cd->sb, "\t\t$%s = \"%s\"\n\n", name, ek);
	free(ek);

	return true;
}

static bool flag_foreach_add_bytes(RzFlagItem *fi, YaraCbData *cd) {
	ut8 buffer[0x1000];
	const char *name = fi->name + strlen(RZ_YARA_FLAG_PREFIX_BYTES);
	if (RZ_STR_ISEMPTY(name)) {
		YARA_WARN("invalid flag name: %s (skipping)\n", fi->name);
		return true;
	}

	int read = RZ_MIN(fi->size, sizeof(buffer));
	if (!rz_io_read_at_mapped(cd->core->io, fi->offset, buffer, read)) {
		YARA_WARN("cannot read yara string %s (skipping)\n", fi->name);
		return true;
	}
	rz_strbuf_appendf(cd->sb, "\t\t// offset: 0x%" PFMT64x ", size: 0x%x\n", fi->offset, read);
	rz_strbuf_appendf(cd->sb, "\t\t$%s = {\n\t\t\t", name);
	for (int i = 0; i < read; ++i) {
		if (i > 0 && !(i & 7)) {
			rz_strbuf_append(cd->sb, "\n\t\t\t");
		}
		rz_strbuf_appendf(cd->sb, "%02X ", buffer[i]);
	}
	rz_strbuf_append(cd->sb, "\n\t\t}\n\n");
	return true;
}

static bool flag_foreach_add_asm(RzFlagItem *fi, YaraCbData *cd) {
	ut8 buffer[0x1000];
	ut8 *mask = NULL;
	const char *name = fi->name + strlen(RZ_YARA_FLAG_PREFIX_ASM);
	if (RZ_STR_ISEMPTY(name)) {
		YARA_WARN("invalid flag name: %s (skipping)\n", fi->name);
		return true;
	}

	int read = RZ_MIN(fi->size, sizeof(buffer));
	if (!rz_io_read_at_mapped(cd->core->io, fi->offset, buffer, read)) {
		YARA_WARN("cannot read yara string %s (skipping)\n", fi->name);
		return true;
	}
	mask = rz_analysis_mask(cd->core->analysis, read, buffer, fi->offset);

	while (read > 0 && mask[read - 1] == 0) {
		read--;
	}
	if (read < 1) {
		YARA_WARN("all the bytes of yara string %s have been masked out (skipping)\n", fi->name);
		return true;
	}

	rz_strbuf_appendf(cd->sb, "\t\t// offset: 0x%" PFMT64x ", size: 0x%x\n", fi->offset, read);
	rz_strbuf_appendf(cd->sb, "\t\t$%s = {\n\t\t\t", name);
	for (int i = 0; i < read; ++i) {
		if (i > 0 && !(i & 7)) {
			rz_strbuf_append(cd->sb, "\n\t\t\t");
		}
		if (mask[i] == 0xFF) {
			rz_strbuf_appendf(cd->sb, "%02X ", buffer[i]);
		} else if ((mask[i] & 0xF0) != 0xF0 && (mask[i] & 0x0F) != 0x0F) {
			rz_strbuf_append(cd->sb, "?? ");
		} else if ((mask[i] & 0xF0) != 0xF0) {
			rz_strbuf_appendf(cd->sb, "?%X ", buffer[i] & 0xF);
		} else {
			rz_strbuf_appendf(cd->sb, "%X? ", (buffer[i] >> 8));
		}
	}
	rz_strbuf_append(cd->sb, "\n\t\t}\n\n");
	return true;
}

RZ_API char *rz_yara_create_rule_from_bytes(RZ_NONNULL RzCore *core, RZ_NULLABLE RzYaraMeta *metadata, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(core && metadata && name, NULL);
	YaraCbData cd;

	RzStrBuf *sb = rz_strbuf_new("rule ");
	if (!sb) {
		YARA_ERROR("Cannot allocate string buffer\n");
		return NULL;
	}

	cd.sb = sb;
	cd.core = core;

	const char *tags = rz_config_get(core->config, RZ_YARA_CFG_TAGS);

	rz_strbuf_append(sb, name);
	if (RZ_STR_ISNOTEMPTY(tags)) {
		rz_strbuf_appendf(sb, ": %s", tags);
	}
	rz_strbuf_append(sb, "\n{\n");

	if (metadata && metadata->count > 0) {
		rz_strbuf_append(sb, "\tmeta:\n");
		ht_pp_foreach(metadata, (HtPPForeachCallback)add_metadata, &cd);
		rz_strbuf_append(sb, "\n");
	}

	rz_strbuf_append(sb, "\tstrings:\n");

	rz_flag_foreach_glob(core->flags, RZ_YARA_FLAG_SPACE_STRING, (RzFlagItemCb)flag_foreach_add_string, &cd);
	rz_flag_foreach_glob(core->flags, RZ_YARA_FLAG_SPACE_BYTES, (RzFlagItemCb)flag_foreach_add_bytes, &cd);
	rz_flag_foreach_glob(core->flags, RZ_YARA_FLAG_SPACE_ASM, (RzFlagItemCb)flag_foreach_add_asm, &cd);

	rz_strbuf_append(sb, "\tcondition:\n\t\tall of them\n}\n");
	return rz_strbuf_drain(sb);
}