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
#include <time.h>

#include <libubox/uclient.h>
#include <libubox/uclient-utils.h>
#include <libubus.h>

#include "state.h"
#include "strncpyt.h"

static struct ubus_context *ctx;
static struct blob_buf b;
static char auth_md5[33];
extern int debug_level;

static const char * const auth_realm = "ucwmp";

enum {
	CONN_REQ_USERNAME,
	CONN_REQ_REALM,
	CONN_REQ_NONCE,
	CONN_REQ_URI,
	CONN_REQ_RESPONSE,
	CONN_REQ_CNONCE,
	CONN_REQ_NC,
	__CONN_REQ_MAX,
};

static const struct blobmsg_policy conn_req_policy[__CONN_REQ_MAX] = {
	[CONN_REQ_USERNAME] = { "username", BLOBMSG_TYPE_STRING },
	[CONN_REQ_REALM] = { "realm", BLOBMSG_TYPE_STRING },
	[CONN_REQ_NONCE] = { "nonce", BLOBMSG_TYPE_STRING },
	[CONN_REQ_URI] = { "uri", BLOBMSG_TYPE_STRING },
	[CONN_REQ_RESPONSE] = { "response", BLOBMSG_TYPE_STRING },
	[CONN_REQ_CNONCE] = { "cnonce", BLOBMSG_TYPE_STRING },
	[CONN_REQ_NC] = { "nc", BLOBMSG_TYPE_STRING },
};

enum {
	CFG_ACS_URL,
	CFG_ACS_USR,
	CFG_ACS_PWD,
	CFG_ACS_PERIODIC_ENABLE,
	CFG_ACS_PERIODIC_INTERVAL,

	CFG_CPE_USR,
	CFG_CPE_PWD,

	CFG_CWMP_DEBUG,
	__CFG_MAX
};

static const struct blobmsg_policy cfg_policy[__CFG_MAX] = {
	[CFG_ACS_URL] = { "url", BLOBMSG_TYPE_STRING },
	[CFG_ACS_USR] = { "username", BLOBMSG_TYPE_STRING },
	[CFG_ACS_PWD] = { "password", BLOBMSG_TYPE_STRING },
	[CFG_ACS_PERIODIC_ENABLE] = { "periodic_inform_enabled", BLOBMSG_TYPE_INT8 },
	[CFG_ACS_PERIODIC_INTERVAL] = { "periodic_inform_interval", BLOBMSG_TYPE_INT32 },

	[CFG_CPE_USR] = { "userid", BLOBMSG_TYPE_STRING },
	[CFG_CPE_PWD] = { "passwd", BLOBMSG_TYPE_STRING },

	[CFG_CWMP_DEBUG] = { "debug", BLOBMSG_TYPE_INT32 }
};

static const struct blobmsg_policy event_policy[] = {
	{ .name = "event", .type = BLOBMSG_TYPE_STRING },
	{ .name = "commandkey", .type = BLOBMSG_TYPE_STRING },
	{ .name = "data", .type = BLOBMSG_TYPE_TABLE },
};

static const struct blobmsg_policy reboot_policy[] = {
	{ .name = "commandkey", .type = BLOBMSG_TYPE_STRING },
};

static void conn_req_challenge(void)
{
	time_t cur = time(NULL);
	char nonce[9];

	snprintf(nonce, sizeof(nonce), "%08x", (uint32_t) cur);
	blobmsg_add_string(&b, "nonce", nonce);
	blobmsg_add_string(&b, "realm", auth_realm);
}

static bool conn_req_check_digest(struct blob_attr **tb)
{
	struct http_digest_data data = {
		.uri = blobmsg_data(tb[CONN_REQ_URI]),
		.method = "GET",
		.auth_hash = auth_md5,
		.qop = "auth",
		.nc = blobmsg_data(tb[CONN_REQ_NC]),
		.nonce = blobmsg_data(tb[CONN_REQ_NONCE]),
		.cnonce = blobmsg_data(tb[CONN_REQ_CNONCE]),
	};
	char md5[33];

	http_digest_calculate_response(md5, &data);

	return !strcmp(blobmsg_data(tb[CONN_REQ_RESPONSE]), md5);
}

static bool conn_req_validate(struct blob_attr **tb)
{
	const char *password = "";
	int i;

	if (!config.cpe.usr[0])
		return true;

	if (config.cpe.pwd[0])
		password = config.cpe.pwd;

	http_digest_calculate_auth_hash(auth_md5, config.cpe.usr,
					auth_realm, password);

	for (i = 0; i < __CONN_REQ_MAX; i++) {
		if (!tb[i])
			return false;
	}

	return conn_req_check_digest(tb);
}

static int
cwmp_connection_request(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__CONN_REQ_MAX];
	bool ok;

	blob_buf_init(&b, 0);

	blobmsg_parse(conn_req_policy, __CONN_REQ_MAX, tb, blobmsg_data(msg), blobmsg_data_len(msg));

	ok = conn_req_validate(tb);
	conn_req_challenge();
	blobmsg_add_u8(&b, "ok", ok);

	if (ok)
		cwmp_flag_event("6 CONNECTION REQUEST", NULL, NULL);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
cwmp_event_sent(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	cwmp_clear_pending_events();
	return 0;
}

static int
cwmp_event_add(struct ubus_context *ctx, struct ubus_object *obj,
	       struct ubus_request_data *req, const char *method,
	       struct blob_attr *msg)
{
	struct blob_attr *tb[3];
	const char *id, *ckey = NULL;

	blobmsg_parse(event_policy, ARRAY_SIZE(event_policy), tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (!tb[0])
		return UBUS_STATUS_INVALID_ARGUMENT;

	id = blobmsg_data(tb[0]);
	if (tb[1])
		ckey = blobmsg_data(tb[1]);

	cwmp_flag_event(id, ckey, tb[2]);
	return 0;
}

static int
cwmp_session_completed(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{
	session_success = true;
	return 0;
}

static int
cwmp_download_req(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{

	cwmp_download_add(msg, false);

	return 0;
}

static int
cwmp_download_done_req(struct ubus_context *ctx, struct ubus_object *obj,
		       struct ubus_request_data *req, const char *method,
		       struct blob_attr *msg)
{

	cwmp_download_done(msg);

	return 0;
}

static int
cwmp_factory_reset(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	pending_cmd = CMD_FACTORY_RESET;
	return 0;
}

static int
cwmp_reboot(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct blob_attr *tb[ARRAY_SIZE(reboot_policy)];
	const char *cmd_key = NULL;

	blobmsg_parse(reboot_policy, ARRAY_SIZE(reboot_policy),
			tb, blobmsg_data(msg), blobmsg_data_len(msg));
	if (tb[0])
		cmd_key = blobmsg_get_string(tb[0]);

	cwmp_flag_event("M Reboot", cmd_key, NULL);
	pending_cmd = CMD_REBOOT;
	return 0;
}

static int
cwmp_set_config(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct blob_attr *tb[__CFG_MAX];
	struct blob_attr *cur;
	bool acs_changed = false;

	blobmsg_parse(cfg_policy, __CFG_MAX, tb,
			blobmsg_data(msg), blobmsg_data_len(msg));

	if ((cur = tb[CFG_ACS_URL])) {
		const char *url = blobmsg_get_string(cur);

		if (strcmp(url, config.acs.url)) {
			strncpyt(config.acs.url, blobmsg_get_string(cur),
				sizeof(config.acs.url));
			acs_changed = true;
		}
	}

	if ((cur = tb[CFG_ACS_USR]))
		strncpyt(config.acs.usr, blobmsg_get_string(cur),
			sizeof(config.acs.usr));

	if ((cur = tb[CFG_ACS_PWD]))
		strncpyt(config.acs.pwd, blobmsg_get_string(cur),
			sizeof(config.acs.pwd));

	if ((cur = tb[CFG_ACS_PERIODIC_ENABLE]))
		config.acs.periodic_enabled = blobmsg_get_u8(cur);

	if ((cur = tb[CFG_ACS_PERIODIC_INTERVAL]))
		config.acs.periodic_interval = blobmsg_get_u32(cur);

	if ((cur = tb[CFG_CPE_USR]))
		strncpyt(config.cpe.usr, blobmsg_get_string(cur),
			sizeof(config.cpe.usr));

	if ((cur = tb[CFG_CPE_PWD]))
		strncpyt(config.cpe.pwd, blobmsg_get_string(cur),
			sizeof(config.cpe.pwd));

	if ((cur = tb[CFG_CWMP_DEBUG]))
		debug_level = blobmsg_get_u32(cur);

	cwmp_reload(acs_changed);
	return 0;
}

static struct ubus_method cwmp_methods[] = {
	UBUS_METHOD_NOARG("connection_request", cwmp_connection_request),
	UBUS_METHOD_NOARG("event_sent", cwmp_event_sent),
	UBUS_METHOD("event_add", cwmp_event_add, event_policy),

	UBUS_METHOD("download_add", cwmp_download_req, transfer_policy),
	UBUS_METHOD_MASK("download_done", cwmp_download_done_req, transfer_policy,
			 (1 << CWMP_DL_URL)),

	UBUS_METHOD_NOARG("factory_reset", cwmp_factory_reset),
	UBUS_METHOD("reboot", cwmp_reboot, reboot_policy),
	UBUS_METHOD_NOARG("set_config", cwmp_set_config),

	UBUS_METHOD_NOARG("session_completed", cwmp_session_completed),
};

static struct ubus_object_type cwmp_object_type =
	UBUS_OBJECT_TYPE("cwmp", cwmp_methods);

static struct ubus_object cwmp_object = {
	.name = "cwmp",
	.type = &cwmp_object_type,
	.methods = cwmp_methods,
	.n_methods = ARRAY_SIZE(cwmp_methods),
};

void cwmp_ubus_command(struct blob_attr *data)
{
	struct blobmsg_policy policy[2] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[2];
	const char *name;

	blobmsg_parse_array(policy, ARRAY_SIZE(policy), tb, blobmsg_data(data), blobmsg_data_len(data));
	if (!tb[0] || !tb[1])
		return;

	name = blobmsg_data(tb[0]);

	if (!strcmp(name, "download_done"))
		cwmp_download_done_req(ctx, &cwmp_object, NULL, NULL, tb[1]);
}

int cwmp_ubus_register(void)
{
	ctx = ubus_connect(NULL);
	if (!ctx)
		return -1;

	if (ubus_add_object(ctx, &cwmp_object))
		return -1;

	ubus_add_uloop(ctx);
	return 0;
}
