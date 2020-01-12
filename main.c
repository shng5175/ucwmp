/*
 * cwmpd - CPE WAN Management Protocol daemon
 * Copyright (C) 2014 Felix Fietkau <nbd@openwrt.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <sys/stat.h>

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uci.h>

#include <libubox/utils.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>

#include "state.h"

#ifdef DUMMY_MODE
#define CWMP_ETC_DIR "./etc"
#define CWMP_CONFIG_DIR	CWMP_ETC_DIR "/config"
#define CWMP_SESSION_BIN "./cwmp-session"
#define CWMP_SCRIPT_DIR "./scripts"
#else
#define CWMP_CONFIG_DIR	NULL /* UCI default */
#define CWMP_ETC_DIR "/etc"
#define CWMP_SESSION_BIN "cwmp-session"
#define CWMP_SCRIPT_DIR "/usr/share/cwmp/scripts"
#endif

#define CWMP_CACHE_FILE	CWMP_ETC_DIR "/cwmp-cache.json"
#define CWMP_STARTUP_FILE	CWMP_ETC_DIR "/cwmp-startup.json"

#define CWMP_SESSION_ERR_RETRY_MSEC	(10 * 1000)

static struct uci_context *uci_ctx;
static const char *session_path = CWMP_SESSION_BIN;
static const char *config_path = CWMP_CONFIG_DIR;
static const char *cache_file = CWMP_CACHE_FILE;

bool session_success = false;
static bool session_pending;
static int debug_level;

struct cwmp_config config;
enum pending_cmd pending_cmd = CMD_NONE;

static struct blob_buf b;

static const struct uci_parse_option server_opts[__SERVER_INFO_MAX] = {
	[SERVER_INFO_URL] = { "url", UCI_TYPE_STRING },
	[SERVER_INFO_USERNAME] = { "username", UCI_TYPE_STRING },
	[SERVER_INFO_PASSWORD] = { "password", UCI_TYPE_STRING },

	[SERVER_INFO_PERIODIC_INTERVAL] = { "periodic_interval", UCI_TYPE_STRING },
	[SERVER_INFO_PERIODIC_ENABLED] = { "periodic_enabled", UCI_TYPE_STRING },
	[SERVER_INFO_CONN_REQ_PORT] = { "connection_port", UCI_TYPE_STRING },

	[SERVER_INFO_LOCAL_USERNAME] = { "local_username", UCI_TYPE_STRING },
	[SERVER_INFO_LOCAL_PASSWORD] = { "local_password", UCI_TYPE_STRING },
};

static char *cwmp_get_event_str(bool pending)
{
	void *c;

	blob_buf_init(&b, 0);
	c = blobmsg_open_array(&b, NULL);
	cwmp_state_get_events(&b, pending);
	blobmsg_close_array(&b, c);
	return blobmsg_format_json(blob_data(b.head), false);
}

static void __cwmp_save_cache(struct uloop_timeout *timeout)
{
	char *str;
	FILE *f;
	void *c;

	if (!config.acs_info[0])
		return;

	blob_buf_init(&b, 0);

	f = fopen(cache_file, "w+");
	if (!f)
		return;

	blobmsg_add_string(&b, "acs_url", config.acs_info[0]);

	c = blobmsg_open_array(&b, "events");
	cwmp_state_get_events(&b, false);
	blobmsg_close_array(&b, c);

	c = blobmsg_open_array(&b, "downloads");
	cwmp_state_get_downloads(&b);
	blobmsg_close_array(&b, c);

	str = blobmsg_format_json(b.head, true);
	if (debug_level)
		fprintf(stderr, "Updated cache: %s\n", str);
	fwrite(str, strlen(str), 1, f);
	free(str);

	fclose(f);
}

static struct uloop_timeout save_cache = {
	.cb = __cwmp_save_cache,
};

static void session_cb(struct uloop_process *c, int ret);
static struct uloop_process session_proc = {
	.cb = session_cb
};

static void cwmp_exec_session(const char *event_data)
{
	static char debug_str[8] = "0";
	static char port_str[8] = "8080";
	const char *argv[16] = {
		session_path,
		"-d",
		debug_str,
		"-e",
		event_data,
		"-P",
		port_str,
		NULL
	};
	int argc = 7;

	if (config.acs_info[1]) {
		argv[argc++] = "-u";
		argv[argc++] = config.acs_info[1];
	}
	if (config.acs_info[2]) {
		argv[argc++] = "-p";
		argv[argc++] = config.acs_info[2];
	}

	if (config.conn_req_port)
		snprintf(port_str, sizeof(port_str), "%d", config.conn_req_port);

	argv[argc++] = config.acs_info[0];
	argv[argc] = NULL;
	snprintf(debug_str, sizeof(debug_str), "%d", debug_level);

	if (execvp(argv[0], (char * const *) argv) == -1)
		fprintf(stderr, "execvp of %s failed: %s\n", argv[0], strerror(errno));
	exit(255);
}

void cwmp_download_apply_exec(const char *path, const char *type, const char *file, const char *url)
{
	const char *argv[] = {
		CWMP_SCRIPT_DIR "/apply.sh",
		path,
		type,
		file,
		url,
		NULL,
	};

	execvp(argv[0], (char **) argv);
	exit(255);
}

static void cwmp_run_session(void)
{
	char *ev = cwmp_get_event_str(true);
	int pid;

	session_pending = false;
	session_success = false;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return;
	}

	if (pid > 0) {
		session_proc.pid = pid;
		uloop_process_add(&session_proc);
		return;
	}

	cwmp_exec_session(ev);
	free(ev);
}

static void cwmp_process_pending_cmd(void)
{
	const char *cmd;

	switch (pending_cmd) {
	case CMD_FACTORY_RESET:
		cmd = CWMP_SCRIPT_DIR "/factory-reset.sh";
		break;
	case CMD_REBOOT:
		cmd = CWMP_SCRIPT_DIR "/reboot.sh";
		break;
	default:
		return;
	}

	system(cmd);
}

static void session_cb(struct uloop_process *c, int ret)
{
	cwmp_process_pending_cmd();
	cwmp_download_check_pending(true);

	if (debug_level)
		fprintf(stderr, "Session completed (rc: %d success: %d)\n",
			ret, session_success);

	if (ret)
		cwmp_schedule_session(CWMP_SESSION_ERR_RETRY_MSEC);
	else if (session_pending)
		cwmp_schedule_session(1);
}

static void __cwmp_run_session(struct uloop_timeout *timeout)
{
	if (session_proc.pending) {
		session_pending = true;
		return;
	}

	if (!cwmp_state_has_events())
		return;

	if (!config.acs_info[0])
		return;

	cwmp_run_session();
}

void cwmp_schedule_session(int delay_msec)
{
	static struct uloop_timeout timer = {
		.cb = __cwmp_run_session,
	};

	uloop_timeout_set(&timer, delay_msec);
}

static void cwmp_update_session_timer(void);
static void __cwmp_session_timer(struct uloop_timeout *timeout)
{
	cwmp_schedule_session(1);
	cwmp_flag_event("2 PERIODIC", NULL, NULL);
	cwmp_update_session_timer();
}

static void cwmp_update_session_timer(void)
{
	static struct uloop_timeout timer = {
		.cb = __cwmp_session_timer,
	};

	if (config.periodic_interval && config.periodic_enabled)
		uloop_timeout_set(&timer, config.periodic_interval * 1000);
	else
		uloop_timeout_cancel(&timer);
}

void cwmp_save_cache(bool immediate)
{
	if (immediate) {
		uloop_timeout_cancel(&save_cache);
		save_cache.cb(&save_cache);
	} else {
		uloop_timeout_set(&save_cache, 1);
	}
}

static int cwmp_get_config_section(struct uci_ptr *ptr)
{
	static char buf[32];

	strcpy(buf, "cwmp.@cwmp[0]");
	if (uci_lookup_ptr(uci_ctx, ptr, buf, true)) {
		uci_perror(uci_ctx, "Failed to load configuration");
		return -1;
	}

	return 0;
}

int cwmp_load_config(void)
{
	struct uci_option *tb[__SERVER_INFO_MAX], *cur;
	struct uci_ptr ptr = {};
	int i;

	memset(&config, 0, sizeof(config));
	config.conn_req_port = DEFAULT_CONNECTION_PORT;

	if (cwmp_get_config_section(&ptr))
		return -1;

	uci_parse_section(ptr.s, server_opts, ARRAY_SIZE(server_opts), tb);

	for (i = 0; i <= SERVER_INFO_PASSWORD; i++) {
		const char *val = tb[i] ? tb[i]->v.string : NULL;

		config.acs_info[i - SERVER_INFO_URL] = val;
	}

	if ((cur = tb[SERVER_INFO_PERIODIC_INTERVAL]))
		config.periodic_interval = atoi(cur->v.string);

	if ((cur = tb[SERVER_INFO_PERIODIC_ENABLED]))
		config.periodic_enabled = atoi(cur->v.string);

	if ((cur = tb[SERVER_INFO_CONN_REQ_PORT]))
		config.conn_req_port = atoi(cur->v.string);

	if ((cur = tb[SERVER_INFO_LOCAL_USERNAME]))
		config.local_username = cur->v.string;

	if ((cur = tb[SERVER_INFO_LOCAL_PASSWORD]))
		config.local_password = cur->v.string;

	return 0;
}

static void cwmp_set_string_option(struct uci_ptr *ptr, const char *name, const char *val)
{
	ptr->o = NULL;
	ptr->option = name;
	uci_lookup_ptr(uci_ctx, ptr, NULL, false);

	ptr->value = val;
	if (ptr->value)
		uci_set(uci_ctx, ptr);
	else if (ptr->o)
		uci_delete(uci_ctx, ptr);
}

static void cwmp_set_int_option(struct uci_ptr *ptr, const char *name, int val)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d", val);
	cwmp_set_string_option(ptr, name, buf);
}

int cwmp_update_config(enum cwmp_config_change changed)
{
	struct uci_ptr ptr = {};
	int i;

	if (cwmp_get_config_section(&ptr))
		return -1;

	switch (changed) {
	case CONFIG_CHANGE_ACS_INFO:
		for (i = 0; i < ARRAY_SIZE(config.acs_info); i++)
			cwmp_set_string_option(&ptr, server_opts[i].name, config.acs_info[i]);

		cwmp_flag_event("0 BOOTSTRAP", NULL, NULL);
		break;
	case CONFIG_CHANGE_PERIODIC_INFO:
		cwmp_set_int_option(&ptr, "periodic_interval", config.periodic_interval);
		cwmp_set_int_option(&ptr, "periodic_enabled", config.periodic_enabled);
		cwmp_update_session_timer();
		break;

	case CONFIG_CHANGE_LOCAL_INFO:
		cwmp_set_string_option(&ptr, "local_username", config.local_username);
		cwmp_set_string_option(&ptr, "local_password", config.local_password);
		break;
	}

	return 0;
}

void cwmp_commit_config(void)
{
	struct uci_ptr ptr = {};

	if (cwmp_get_config_section(&ptr))
		return;

	uci_commit(uci_ctx, &ptr.p, false);
	cwmp_load_config();
}

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <options>\n"
		"Options:\n"
		"	-c <path>       Path to UCI config file (default: %s)\n"
		"	-E <file>       CWMP cache storage file (default: " CWMP_CACHE_FILE ")\n"
		"	-d              Increase debug level\n"
		"	-s <path>       Path to session tool\n"
		"\n", prog, CWMP_CONFIG_DIR ? CWMP_CONFIG_DIR : UCI_CONFDIR);
	return 1;
}

static void cwmp_add_downloads(struct blob_attr *attr)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, attr, rem)
		cwmp_download_add(cur, true);
}

static void cwmp_load_cache(const char *filename)
{
	enum {
		CACHE_URL,
		CACHE_EVENTS,
		CACHE_DOWNLOADS,
		__CACHE_MAX,
	};
	static const struct blobmsg_policy policy[__CACHE_MAX] = {
		[CACHE_URL] = { "acs_url", BLOBMSG_TYPE_STRING },
		[CACHE_EVENTS] = { "events", BLOBMSG_TYPE_ARRAY },
		[CACHE_DOWNLOADS] = { "downloads", BLOBMSG_TYPE_ARRAY }
	};
	struct blob_attr *tb[__CACHE_MAX], *cur;
	struct stat st;

	if (stat(filename, &st) != 0)
		goto bootstrap;

	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_file(&b, filename))
		goto bootstrap;

	blobmsg_parse(policy, __CACHE_MAX, tb, blob_data(b.head), blob_len(b.head));

	if ((cur = tb[CACHE_EVENTS]))
		cwmp_add_events(cur);

	if ((cur = tb[CACHE_DOWNLOADS]))
		cwmp_add_downloads(cur);

	if (config.acs_info[0]) {
		cur = tb[CACHE_URL];
		if (!cur || strcmp(config.acs_info[0], blobmsg_data(cur)) != 0)
			goto bootstrap;
	}
	return;

bootstrap:
	cwmp_flag_event("0 BOOTSTRAP", NULL, NULL);
}

static void cwmp_load_startup(const char *filename)
{
	static const struct blobmsg_policy policy = {
		"commands", BLOBMSG_TYPE_ARRAY
	};
	struct blob_attr *attr, *cur;
	struct stat st;
	int rem;

	if (stat(filename, &st) != 0)
		return;

	blob_buf_init(&b, 0);
	blobmsg_add_json_from_file(&b, filename);
	truncate(filename, 0);

	blobmsg_parse(&policy, 1, &attr, blob_data(b.head), blob_len(b.head));
	if (!attr)
		return;

	if (!blobmsg_check_attr_list(attr, BLOBMSG_TYPE_ARRAY))
		return;

	blobmsg_for_each_attr(cur, attr, rem)
		cwmp_ubus_command(cur);
}

int main(int argc, char **argv)
{
	int ch;

	uci_ctx = uci_alloc_context();

	while ((ch = getopt(argc, argv, "c:dE:s:")) != -1) {
		switch(ch) {
		case 'c':
			config_path = optarg;
			break;
		case 'E':
			cache_file = optarg;
			break;
		case 'd':
			debug_level++;
			break;
		case 's':
			session_path = optarg;
			break;
		default:
			return usage(argv[0]);
		}
	}

	uci_set_confdir(uci_ctx, config_path);

	if (cwmp_load_config() < 0)
		return 1;

	uloop_init();

	if (cwmp_ubus_register()) {
		fprintf(stderr, "Failed to register ubus object\n");
		return 1;
	}

	cwmp_load_cache(cache_file);
	cwmp_download_check_pending(true);
	cwmp_load_startup(CWMP_STARTUP_FILE);

	uloop_timeout_cancel(&save_cache);
	cwmp_schedule_session(1);
	cwmp_update_session_timer();
	uloop_run();
	uloop_done();

	return 0;
}
