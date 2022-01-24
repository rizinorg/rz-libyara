// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include "yara_common.h"

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

static bool add_metadata(RzStrBuf *sb, const char *k, const char *v) {
	if (!strcmp(v, "true") || !strcmp(v, "false") || rz_is_valid_input_num_value(NULL, v)) {
		rz_strbuf_appendf(sb, "\t\t%s = %s\n", k, v);
	} else if ((!strcmp(k, "date") || !strcmp(k, "timestamp")) && RZ_STR_ISEMPTY(v)) {
		char *time = rz_time_to_string(rz_time_now());
		rz_strbuf_appendf(sb, "\t\t%s = \"%s\"\n", k, time);
		free(time);
	} else {
		rz_strbuf_appendf(sb, "\t\t%s = \"%s\"\n", k, v);
	}
	return true;
}

RZ_API char *rz_yara_create_rule_from_bytes(RZ_NONNULL const ut8 *buffer, ut32 size, RZ_NONNULL const char *name, RZ_NULLABLE const char *tags, RZ_NULLABLE RzYaraMeta *metadata) {
	rz_return_val_if_fail(buffer && size > 0 && name, NULL);
	RzStrBuf *sb = rz_strbuf_new("rule ");
	if (!sb) {
		YARA_ERROR("Cannot allocate string buffer\n");
		return NULL;
	}

	rz_strbuf_append(sb, name);
	if (RZ_STR_ISNOTEMPTY(tags)) {
		rz_strbuf_appendf(sb, ": %s", tags);
	}
	rz_strbuf_append(sb, "\n{\n");

	if (metadata && metadata->count > 0) {
		rz_strbuf_append(sb, "\tmeta:\n");
		ht_pp_foreach(metadata, (HtPPForeachCallback)add_metadata, sb);
		rz_strbuf_append(sb, "\n");
	}

	rz_strbuf_append(sb, "\tstrings:\n\t\t$chunk_0 = {\n\t\t\t");
	for (ut32 i = 0; i < size; ++i) {
		if (i > 0 && !(i & 7)) {
			rz_strbuf_append(sb, "\n\t\t\t");
		}
		rz_strbuf_appendf(sb, "%02X ", buffer[i]);
	}
	rz_strbuf_append(sb, "\n\t\t}\n\n\tcondition:\n\t\t$chunk_0\n}\n");
	return rz_strbuf_drain(sb);
}