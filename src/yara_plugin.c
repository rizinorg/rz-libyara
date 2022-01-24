// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include "yara_common.h"

/** \file yara_plugin.c
 * Adds core plugin to rizin to handle yara rules
 */

static HtPP *yara_metadata = NULL;

#undef RZ_API
#define RZ_API static
#undef RZ_IPI
#define RZ_IPI static

#define SETDESC(x, y)     rz_config_node_desc(x, y)
#define SETPREF(x, y, z)  SETDESC(rz_config_set(cfg, x, y), z)
#define SETPREFI(x, y, z) SETDESC(rz_config_set_i(cfg, x, y), z)

static const RzCmdDescHelp yara_command_grp_help = {
	.summary = "Rizin custom yara parser and generator of YARA rules.",
};

static const RzCmdDescArg yara_command_main_args[] = {
	{ 0 },
};

static const RzCmdDescHelp yara_command_main_help = {
	.summary = "yara commands and examples.",
	.args = yara_command_main_args,
};

static const RzCmdDescArg yara_command_create_args[] = {
	{
		.name = "rulename",
		.type = RZ_CMD_ARG_TYPE_STRING,
	},
	{
		.name = "#bytes",
		.type = RZ_CMD_ARG_TYPE_NUM,
	},
	{ 0 },
};

static const RzCmdDescHelp yara_command_create_help = {
	.summary = "Creates a new rule at the current offset",
	.args = yara_command_create_args,
};

static const RzCmdDescArg yara_command_load_args[] = {
	{
		.name = "file",
		.type = RZ_CMD_ARG_TYPE_FILE,
	},
	{ 0 },
};

static const RzCmdDescHelp yara_command_load_help = {
	.summary = "Parse a .yar file and applies the rules",
	.args = yara_command_load_args,
};

static const RzCmdDescArg yara_command_folder_args[] = {
	{
		.name = "folder",
		.type = RZ_CMD_ARG_TYPE_FILE,
	},
	{ 0 },
};

static const RzCmdDescHelp yara_command_folder_help = {
	.summary = "Searches for .yar files in a folder recursively and applies the rules",
	.args = yara_command_folder_args,
};

static const RzCmdDescArg yara_command_metadata_args[] = {
	{
		.name = "add|del|list",
		.type = RZ_CMD_ARG_TYPE_STRING,
	},
	{
		.name = "name",
		.type = RZ_CMD_ARG_TYPE_STRING,
		.optional = true,
	},
	{
		.name = "value",
		.type = RZ_CMD_ARG_TYPE_STRING,
		.optional = true,
	},
	{ 0 },
};

static const RzCmdDescHelp yara_command_metadata_help = {
	.summary = "Adds/Removes/Lists metadata used when generating rules.",
	.args = yara_command_metadata_args,
};

static void yara_command_load_error(bool is_warning, const char *file, int line, const RzYaraRule *rule, const char *message, void *user_data) {
	if (is_warning) {
		YARA_WARN("%s:%d: %s\n", file, line, message);
		return;
	}
	YARA_ERROR("%s:%d: %s\n", file, line, message);
}

RZ_IPI RzCmdStatus yara_command_load_handler(RzCore *core, int argc, const char **argv) {
	char *identifier;
	int timeout_secs = 0;
	RzList *matches = NULL;
	RzListIter *it = NULL;
	RzYaraRules *rules = NULL;
	RzYaraScanner *scanner = NULL;
	RzYaraCompiler *comp = NULL;

	comp = rz_yara_compiler_new(yara_command_load_error, NULL);
	if (!comp || !rz_yara_compiler_parse_file(comp, argv[1])) {
		rz_warn_if_reached();
		rz_yara_compiler_free(comp);
		return RZ_CMD_STATUS_ERROR;
	}

	timeout_secs = rz_config_get_i(core->config, "yara.timeout");
	if (timeout_secs < 1) {
		YARA_WARN("yara.timeout is set to an invalid number. using 5min timeout.\n");
		// timeout 5 Mins
		timeout_secs = 5 * 60;
	}
	rules = rz_yara_compiler_get_rules_and_free(comp);
	scanner = rz_yara_scanner_new(rules, timeout_secs);
	if (!scanner) {
		rz_warn_if_reached();
		rz_yara_rules_free(rules);
		return RZ_CMD_STATUS_ERROR;
	}

	matches = rz_yara_scanner_search(scanner, core);
	rz_yara_scanner_free(scanner);
	rz_yara_rules_free(rules);

	if (matches && rz_list_length(matches) < 1) {
		rz_cons_printf("no matches\n");
	} else {
		rz_list_foreach (matches, it, identifier) {
			rz_cons_printf("matches %s\n", identifier);
		}
	}
	rz_list_free(matches);

	return matches ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus yara_command_folder_handler(RzCore *core, int argc, const char **argv) {
	const char *extension = NULL;
	char *element;
	int dir_depth = 0;
	ut32 loaded = 0;
	int timeout_secs = 0;
	RzList *list = NULL;
	RzListIter *it = NULL;
	RzYaraRules *rules = NULL;
	RzYaraScanner *scanner = NULL;
	RzYaraCompiler *comp = NULL;
	char path[1024];

	if (!rz_file_is_directory(argv[1])) {
		YARA_ERROR("'%s' is not a directory.\n", argv[1]);
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	dir_depth = rz_config_get_i(core->config, "dir.depth");
	extension = rz_config_get(core->config, "yara.extension");
	if (RZ_STR_ISEMPTY(extension)) {
		extension = ".yar";
	}
	timeout_secs = rz_config_get_i(core->config, "yara.timeout");
	if (timeout_secs < 1) {
		YARA_WARN("yara.timeout is set to an invalid number. using 5min timeout.\n");
		// timeout 5 Mins
		timeout_secs = 5 * 60;
	}

	rz_strf(path, "%s" RZ_SYS_DIR "**", argv[1]);
	list = rz_file_globsearch(path, dir_depth);
	if (rz_list_length(list) < 1) {
		YARA_ERROR("'%s' directory does not contain any *%s files.\n", argv[1], extension);
		rz_list_free(list);
		return RZ_CMD_STATUS_ERROR;
	}

	if (!(comp = rz_yara_compiler_new(yara_command_load_error, NULL))) {
		rz_list_free(list);
		return RZ_CMD_STATUS_ERROR;
	}

	rz_list_foreach (list, it, element) {
		if (!rz_str_endswith(element, extension)) {
			continue;
		} else if (!rz_yara_compiler_parse_file(comp, element)) {
			rz_yara_compiler_free(comp);
			rz_list_free(list);
			return RZ_CMD_STATUS_ERROR;
		}
		YARA_INFO("loaded file %s\n", element);
		loaded++;
	}
	rz_list_free(list);

	if (loaded < 1) {
		YARA_ERROR("'%s' directory does not contain any *%s files.\n", argv[1], extension);
		rz_yara_compiler_free(comp);
		return RZ_CMD_STATUS_ERROR;
	}

	rules = rz_yara_compiler_get_rules_and_free(comp);
	scanner = rz_yara_scanner_new(rules, timeout_secs);
	if (!scanner) {
		rz_warn_if_reached();
		rz_yara_rules_free(rules);
		return RZ_CMD_STATUS_ERROR;
	}

	list = rz_yara_scanner_search(scanner, core);
	rz_yara_scanner_free(scanner);
	rz_yara_rules_free(rules);

	if (list) {
		if (rz_list_length(list) < 1) {
			rz_cons_printf("no yara rules matches\n");
		} else {
			rz_list_foreach (list, it, element) {
				rz_cons_printf("matches yara rule %s\n", element);
			}
		}
	}
	rz_list_free(list);

	return list ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus yara_command_create_handler(RzCore *core, int argc, const char **argv) {
	const char *name = argv[1];
	ut64 n_bytes = rz_get_input_num_value(NULL, argv[2]);
	if (n_bytes < 1 || n_bytes > 0x1000) {
		YARA_ERROR("usage: number of bytes is invalid (expected n between 1 and 0x1000)\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	ut32 block_size = core->blocksize;
	if (n_bytes > block_size) {
		rz_core_block_size(core, n_bytes);
	}

	const char *tags = rz_config_get(core->config, "yara.tags");
	char *rule = rz_yara_create_rule_from_bytes(core->block, n_bytes, name, tags, yara_metadata);

	if (n_bytes > block_size) {
		rz_core_block_size(core, block_size);
	}

	if (!rule) {
		return RZ_CMD_STATUS_ERROR;
	}

	rz_cons_printf("%s", rule);
	free(rule);
	return RZ_CMD_STATUS_OK;
}

static bool print_all_metadata_stored(void *unused, const char *k, const char *v) {
	(void)unused;
	rz_cons_printf("%s = %s\n", k, v);
	return true;
}

RZ_IPI RzCmdStatus yara_command_metadata_handler(RzCore *core, int argc, const char **argv) {
	if (!strcmp(argv[1], "add")) {
		if (argc != 4) {
			YARA_ERROR("usage: yaram add author \"john foo\"\n");
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		ht_pp_update(yara_metadata, argv[2], (void *)argv[3]);
		return RZ_CMD_STATUS_OK;
	} else if (!strcmp(argv[1], "del")) {
		if (argc != 3) {
			YARA_ERROR("usage: yaram del author\n");
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		ht_pp_delete(yara_metadata, argv[2]);
		return RZ_CMD_STATUS_OK;
	} else if (!strcmp(argv[1], "list")) {
		if (argc != 2) {
			YARA_ERROR("usage: yaram list\n");
			return RZ_CMD_STATUS_WRONG_ARGS;
		}
		ht_pp_foreach(yara_metadata, (HtPPForeachCallback)print_all_metadata_stored, NULL);
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_WRONG_ARGS;
}

RZ_IPI RzCmdStatus yara_command_main_handler(RzCore *core, int argc, const char **argv) {
	const char *usage = ""
			    "commands:\n"
			    "  yarac <rulename> <#bytes> # to create a new rule\n"
			    "  yaral <file>              # to load a yara file and apply to the binary\n"
			    "  yarad <directory>         # to loads all yara files and applies to the binary\n"
			    "  yaram add <key> <value>   # adds a metadata key value (used by yarac)\n"
			    "  yaram del <key>           # removes a metadata key\n"
			    "  yaram list <key>          # lists all metadata keys\n"
			    "\nusage examples:\n"
			    "  to add metadata when creating a rule\n"
			    "    yaram add author \"john foo\"\n"
			    "    yaram add author \"john foo\"\n"
			    "    yaram add thread_level 3\n"
			    "    yaram add is_elf true\n"
			    "    yaram add date \"\" # leave it empty to automatically generate one\n"
			    "\nto remove a metadata key\n"
			    "    yaram del is_elf\n"
			    "\nto list all the metadata key/values\n"
			    "    yaram list";

	rz_cons_println(usage);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI bool yara_plugin_init(RzCore *core) {
	yara_metadata = rz_yara_metadata_new();
	if (!yara_metadata) {
		YARA_ERROR("cannot allocate metadata hashmap\n");
		return false;
	}

	RzCmd *rcmd = core->rcmd;
	RzConfig *cfg = core->config;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		rz_warn_if_reached();
		return false;
	}

	rz_config_lock(cfg, false);
	SETPREF("yara.tags", "", "yara rule tags to use in the rule tag location when generating rules (space separated).");
	SETPREF("yara.extension", ".yar", "yara file extension (default .yar).");
	SETPREFI("yara.timeout", 5 * 60, "yara scanner timeout in seconds (default: 5mins).");
	rz_config_lock(cfg, true);

	RzCmdDesc *yara_cd = rz_cmd_desc_group_new(rcmd, root_cd, "yara", yara_command_main_handler, &yara_command_main_help, &yara_command_grp_help);
	rz_return_val_if_fail(yara_cd, false);

	RzCmdDesc *yara_create_cd = rz_cmd_desc_argv_new(rcmd, yara_cd, "yarac", yara_command_create_handler, &yara_command_create_help);
	rz_return_val_if_fail(yara_create_cd, false);

	RzCmdDesc *yara_folder_cd = rz_cmd_desc_argv_new(rcmd, yara_cd, "yarad", yara_command_folder_handler, &yara_command_folder_help);
	rz_return_val_if_fail(yara_folder_cd, false);

	RzCmdDesc *yara_load_cd = rz_cmd_desc_argv_new(rcmd, yara_cd, "yaral", yara_command_load_handler, &yara_command_load_help);
	rz_return_val_if_fail(yara_load_cd, false);

	RzCmdDesc *yara_metadata_cd = rz_cmd_desc_argv_new(rcmd, yara_cd, "yaram", yara_command_metadata_handler, &yara_command_metadata_help);
	rz_return_val_if_fail(yara_metadata_cd, false);

	if (yr_initialize() != ERROR_SUCCESS) {
		rz_warn_if_reached();
		return false;
	}

	return true;
}

RZ_IPI bool yara_plugin_fini(RzCore *core) {
	yr_finalize();
	ht_pp_free(yara_metadata);
	return true;
}

RzCorePlugin rz_core_plugin_yara = {
	.name = "rz_yara",
	.author = "deroad",
	.desc = "Rizin YARA rules parser and generator.",
	.license = "LGPL-3.0",
	.init = yara_plugin_init,
	.fini = yara_plugin_fini,
};

#ifdef _MSC_VER
#define RZ_EXPORT __declspec(dllexport)
#else
#define RZ_EXPORT
#endif

#ifndef CORELIB
RZ_EXPORT RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_yara,
	.version = RZ_VERSION,
	.pkgname = "rz_yara"
};
#endif
