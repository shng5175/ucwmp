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
#include <string.h>
#include <time.h>

#include <libubox/utils.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "soap.h"
#include "rpc.h"
#include "backend.h"

struct blob_buf events = {};

static LIST_HEAD(event_msgs);

struct event_rpc {
	struct list_head list;
	const char *command_key;
	struct blob_attr *data;
};

static node_t *cwmp_open_array(node_t *node, const char *name)
{
	return roxml_add_node(node, 0, ROXML_ELM_NODE, (char *) name, NULL);
}

static void cwmp_close_array(node_t *node, int n_values, const char *type)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "%s[%u]", type, n_values);
	roxml_add_node(node, 0, ROXML_ATTR_NODE, "soap-enc:arrayType", buf);
}

void cwmp_add_parameter_value_struct(node_t *node, const char *name,
				const char *value, const char *type)
{
	node_t *cur;

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "ParameterValueStruct", NULL);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Name", (char *) name);
	cur = roxml_add_node(node, 0, ROXML_ELM_NODE, "Value", (char *)value);
	roxml_add_node(cur, 0, ROXML_ATTR_NODE, "xsi:type", (char *) type);
}

static void add_parameter_value(struct cwmp_iterator *it, union cwmp_any *a)
{
	const struct b_cwmp_param *p = &a->param;

	if (p->path)
		cwmp_add_parameter_value_struct(it->node, p->path, p->value, p->type);
	else
		cwmp_add_parameter_value_struct(it->node, it->path, p->value, p->type);
}

static void set_parameter_attrib(struct cwmp_iterator *it, union cwmp_any *a)
{
}

static void add_parameter_attrib(struct cwmp_iterator *it, union cwmp_any *a)
{
	const struct b_cwmp_param *p = &a->param;
	const char *path = p->path ? p->path : it->path;
	node_t *node;

	node = roxml_add_node(it->node, 0, ROXML_ELM_NODE, "ParameterAttributeStruct", NULL);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Name", (char *)path);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Notification", (char *)p->value);

	/* TODO: implement access list */
#if 0
	node = cwmp_open_array(node, "AccessList");
	if (attr->acl_subscriber)
		roxml_add_node(it->node, 0, ROXML_ELM_NODE, "string", "Subscriber");
	cwmp_close_array(node, attr->acl_subscriber, "string");
#endif
}

static bool cwmp_complete_path(char *path)
{
	char buf[CWMP_PATH_LEN - 32];
	const unsigned len = strlen(path);
	bool partial = false;

	if (len == 0) {
		sprintf(path, "%s.", CWMP_ROOT_OBJECT);
		partial = true;
	} else if (path[0] == '.') {
		memcpy(buf, path, len + 1);
		if (len + sizeof(CWMP_ROOT_OBJECT) < CWMP_PATH_LEN)
			sprintf(path, "%s%s", CWMP_ROOT_OBJECT, buf);
		else
			path[0] = 0;
	} else if (path[len - 1] == '.') {
		partial = true;
	}
	return partial;
}

static int cwmp_add_parameter_value(node_t *node, const char *name)
{
	struct cwmp_iterator it;

	cwmp_iterator_init(&it);
	it.cb = add_parameter_value;
	it.node = node;

	strncpy(it.path, name, sizeof(it.path));
	cwmp_complete_path(it.path);
	return backend.get_parameter_value(&it);
}

static int cwmp_add_parameter_attrib(node_t *node, const char *name)
{
	struct cwmp_iterator it;

	cwmp_iterator_init(&it);
	it.cb = add_parameter_attrib;
	it.node = node;

	strncpy(it.path, name, sizeof(it.path));
	cwmp_complete_path(it.path);
	return backend.get_parameter_attribute(&it);
}

static int cwmp_handle_get_parameter_values(struct rpc_data *data)
{
	node_t *node, *cur_node;
	char *cur = NULL;
	int n_values = 0;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE,
			"cwmp:GetParameterValuesResponse", NULL);
	node = cwmp_open_array(node, "ParameterList");

	cur_node = soap_array_start(data->in, "ParameterNames", NULL);
	if (!cur_node)
		return CWMP_ERROR_INVALID_PARAM;

	backend.get_parameter_values_init();

	while (soap_array_iterate_contents(&cur_node, "string", &cur))
		n_values += cwmp_add_parameter_value(node, cur);

	if (backend.get_parameter_values)
		n_values = backend.get_parameter_values(node, add_parameter_value);

	cwmp_close_array(node, n_values, "cwmp:ParameterValueStruct");
	return 0;
}

static int cwmp_handle_set_parameter_values(struct rpc_data *data)
{
	char key[32] = { 0, 0 };
	char *name = NULL, *value = NULL, *type = NULL;
	node_t *node, *cur_node;
	struct {
		char *param;
		int code;
	} *fault;
	int n_fault = 0, len;
	int error = 0;
	int i;

	cur_node = soap_array_start(data->in, "ParameterList", &len);
	if (!cur_node)
		return CWMP_ERROR_INVALID_PARAM;

	__soap_get_field(data->in, "ParameterKey", key, sizeof(key));

	fault = alloca(len * sizeof(*fault));
	while (soap_array_iterate(&cur_node, "ParameterValueStruct", &node)) {
		bool abort = false;
		int error;

		name = soap_get_field(node, "Name");
		node = roxml_get_chld(node, "Value", 0);
		if (node) {
			value = roxml_get_content(node, NULL, 0, NULL);
			node = roxml_get_attr(node, "type", 0);
			if (node)
				type = roxml_get_content(node, NULL, 0, NULL);
		}

		if (!name || !value) {
			abort = true;
		} else {
			error = backend.set_parameter_value(name, value, key);
			if (error) {
				fault[n_fault].param = name;
				fault[n_fault].code = error;
				n_fault++;
				name = NULL;
			}
		}

		roxml_release(name);
		roxml_release(value);
		roxml_release(type);
		name = value = type = NULL;

		if (abort) {
			error = CWMP_ERROR_INVALID_PARAM;
			break;
		}
	}

	if (!n_fault && !error)
		backend.commit();

	if (error)
		goto out;

	if (!n_fault) {
		node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:SetParameterValuesResponse", NULL);
		node = roxml_add_node(node, 0, ROXML_ELM_NODE, "Status", "0");
		goto out;
	}

	node = soap_add_fault(data->out, CWMP_ERROR_INVALID_ARGUMENTS);
	for (i = 0; i < n_fault; i++) {
		node_t *f = roxml_add_node(node, 0, ROXML_ELM_NODE, "SetParameterValuesFault", NULL);
		roxml_add_node(f, 0, ROXML_ELM_NODE, "ParameterName", fault[i].param);
		soap_add_fault_struct(f, fault[i].code);
	}

out:
	for (i = 0; i < n_fault; i++)
		roxml_release(fault[i].param);

	return error;
}

static void cwmp_add_object_path(node_t *node, char *path, bool writable)
{
	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "ParameterInfoStruct", NULL);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Name", path);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Writable", writable ? "1" : "0");
}

static void add_parameter_name(struct cwmp_iterator *it, union cwmp_any *a)
{
	cwmp_add_object_path(it->node, (char *)a->param.path,
				a->param.writeable);
}

static int cwmp_handle_get_parameter_names(struct rpc_data *data)
{
	struct cwmp_iterator it;
	node_t *node;
	int n_params;
	bool next_level = false;

	cwmp_iterator_init(&it);
	it.cb = add_parameter_name;

	node = data->in;
	if (soap_get_boolean_field(node, "NextLevel", &next_level))
		return CWMP_ERROR_INVALID_ARGUMENTS;

	if (!__soap_get_field(node, "ParameterPath", it.path, sizeof(it.path)))
		return CWMP_ERROR_INVALID_ARGUMENTS;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE,
				"cwmp:GetParameterNamesResponse", NULL);
	it.node = cwmp_open_array(node, "ParameterList");
	n_params = backend.get_parameter_names(&it, next_level);
	cwmp_close_array(it.node, n_params, "cwmp:ParameterInfoStruct");

	if (it.error) {
		roxml_del_node(node);
		return it.error;
	}
	return 0;
}

static int cwmp_handle_get_parameter_attributes(struct rpc_data *data)
{
	node_t *node, *cur_node;
	char *cur = NULL;
	int ret = 0;
	int n = 0;

	cur_node = soap_array_start(data->in, "ParameterNames", NULL);
	if (!cur_node)
		return CWMP_ERROR_INVALID_PARAM;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:GetParameterAttributesResponse", NULL);
	node = cwmp_open_array(node, "ParameterList");

	backend.get_parameter_attributes_init();

	while (soap_array_iterate_contents(&cur_node, "string", &cur))
		n += cwmp_add_parameter_attrib(node, cur);

	if (backend.get_parameter_attributes)
		n = backend.get_parameter_attributes(node, add_parameter_attrib);

	cwmp_close_array(node, n, "cwmp:ParameterAttributeStruct");

	return ret;
}

static int cwmp_set_param_attr(node_t *node)
{
	char path[CWMP_PATH_LEN];
	char notif_change[2] = {};
	char notif_value[2] = {};
	int rc;

	rc = !__soap_get_field(node, "Name", path, sizeof(path));
	rc |= !__soap_get_field(node, "Notification",
				notif_value, sizeof(notif_value));
	if (rc)
		return CWMP_ERROR_INVALID_PARAM;

	__soap_get_field(node, "NotificationChange",
				notif_change, sizeof(notif_change));

	backend.set_parameter_attribute(path, notif_change, notif_value);

	/* TODO: implement AccessList
	 */
#if 0
	if (!soap_get_boolean_field(node, "AccessListChange", &val) && val) {
		char *str;
		node_t *cur;

		attr->acl_subscriber = false;

		cur = soap_array_start(node, "AccessList", NULL);
		while (soap_array_iterate_contents(&cur, "string", &str)) {
			if (!strcmp(str, "Subscriber"))
				attr->acl_subscriber = true;
		}
	}
#endif

	return 0;
}

static int cwmp_handle_set_parameter_attributes(struct rpc_data *data)
{
	node_t *node, *cur_node;
	int fault;

	cur_node = soap_array_start(data->in, "ParameterList", NULL);
	if (!cur_node)
		return CWMP_ERROR_INVALID_PARAM;

	backend.set_parameter_attributes_init();

	while (soap_array_iterate(&cur_node, "SetParameterAttributesStruct", &node)) {
		fault = cwmp_set_param_attr(node);
		if (fault)
			goto out;
	}

	if (backend.set_parameter_attributes)
		fault = backend.set_parameter_attributes(node, set_parameter_attrib);

out:
	/* SetParameterValuesResponse is always empty*/
	roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:SetParameterAttributesResponse", NULL);
	return fault;
}

static void add_object_response(struct cwmp_iterator *it, union cwmp_any *a)
{
	const struct b_cwmp_add_object *obj = &a->add_obj;
	node_t *node = it->node;
	char status[32];

	roxml_add_node(node, 0, ROXML_ELM_NODE,
			"InstanceNumber", (char *)obj->instance_num);
	sprintf(status, "%d", obj->status);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Status", status);
}

static int cwmp_handle_add_object(struct rpc_data *data)
{
	struct cwmp_iterator it;
	node_t *node = data->in;
	char key[32] = { 0, 0 };

	cwmp_iterator_init(&it);

	if (!__soap_get_field(node, "ObjectName", it.path, sizeof(it.path)))
		return CWMP_ERROR_INVALID_ARGUMENTS;

	__soap_get_field(node, "ParameterKey", key, sizeof(key));

	cwmp_complete_path(it.path);
	it.node = roxml_add_node(data->out, 0, ROXML_ELM_NODE,
				"cwmp:AddObjectResponse", NULL);
	it.cb = add_object_response;
	return backend.add_object(&it, key);
}

static int cwmp_handle_delete_object(struct rpc_data *data)
{
	char path[CWMP_PATH_LEN] = { 0, 0 };
	char key[32] = { 0, 0 };
	char status[32];
	node_t *node = data->in;
	int status_code;

	__soap_get_field(node, "ObjectName", path, sizeof(path));
	__soap_get_field(node, "ParameterKey", key, sizeof(key));

	cwmp_complete_path(path);
	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE,
				"cwmp:DeleteObjectResponse", NULL);
	status_code = backend.del_object(path, key);
	if (status_code <= 1) {
		sprintf(status, "%d", status_code);
		roxml_add_node(node, 0, ROXML_ELM_NODE, "Status", status);
	} else {
		soap_add_fault(node, status_code);
	}
	return 0;
}

static int cwmp_handle_factory_reset(struct rpc_data *data)
{
	cwmp_invoke_noarg("factory_reset");
	roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:FactoryResetResponse", NULL);
	return 0;
}

static int cwmp_handle_reboot(struct rpc_data *data)
{
	struct blob_buf b = {};
	char *str;
	const unsigned maxlen = CWMP_COMMAND_KEY_MAXLEN;
	int ret;

	blob_buf_init(&b, 0);
	str = blobmsg_alloc_string_buffer(&b, "commandkey", maxlen);
	__soap_get_field(data->in, "CommandKey", str, maxlen);
	blobmsg_add_string_buffer(&b);

	ret = cwmp_invoke("reboot", b.head);
	blob_buf_free(&b);

	if (ret == 0)
		roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:RebootResponse", NULL);

	return ret;
}

static int cwmp_handle_download(struct rpc_data *data)
{
	static const struct {
		const char *soap_key;
		const char *ubus_key;
	} fields[] = {
		{ "FileType", "type" },
		{ "URL", "url" },
		{ "TargetFileName", "filename" },
		{ "Username", "username" },
		{ "Password", "password" },
		{ "CommandKey", "command_key" },
	};
	static struct blob_buf b;
	struct timeval tv;
	node_t *node;
	int i, ret;
	int delay;

	blob_buf_init(&b, 0);

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		char *str;
		int maxlen = 256;

		str = blobmsg_alloc_string_buffer(&b, fields[i].ubus_key, maxlen);
		if (!__soap_get_field(data->in, fields[i].soap_key, str, maxlen))
			continue;

		blobmsg_add_string_buffer(&b);
	}

	if (soap_get_int_field(data->in, "DelaySeconds", &delay))
		delay = 0;

	if (delay < 0)
		delay = 0;

	gettimeofday(&tv, NULL);
	blobmsg_add_u32(&b, "start", tv.tv_sec + delay);

	ret = cwmp_invoke("download_add", b.head);
	blob_buf_free(&b);

	if (ret)
		return ret;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:DownloadResponse", NULL);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "Status", "0");
	soap_add_time(node, "StartTime", NULL);
	soap_add_time(node, "CompleteTime", NULL);

	return ret;
}

static int cwmp_handle_get_rpc_methods(struct rpc_data *data);

static const struct rpc_method rpc_methods[] = {
	{ "GetRPCMethods", cwmp_handle_get_rpc_methods },
	{ "GetParameterValues", cwmp_handle_get_parameter_values },
	{ "SetParameterValues", cwmp_handle_set_parameter_values },
	{ "GetParameterNames", cwmp_handle_get_parameter_names },
	{ "GetParameterAttributes", cwmp_handle_get_parameter_attributes },
	{ "SetParameterAttributes", cwmp_handle_set_parameter_attributes },
	{ "AddObject", cwmp_handle_add_object },
	{ "DeleteObject", cwmp_handle_delete_object },
	{ "Reboot", cwmp_handle_reboot },
	{ "Download", cwmp_handle_download },
	{ "FactoryReset", cwmp_handle_factory_reset },
};

static int cwmp_handle_get_rpc_methods(struct rpc_data *data)
{
	node_t *node;
	int i;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:GetRPCMethodsResponse", NULL);

	node = cwmp_open_array(node, "MethodList");
	for (i = 0; i < ARRAY_SIZE(rpc_methods); i++)
		roxml_add_node(node, 0, ROXML_ELM_NODE, "string", (char *) rpc_methods[i].name);
	cwmp_close_array(node, ARRAY_SIZE(rpc_methods), "xsd:string");

	return 0;
}

static int cwmp_inform_response(struct rpc_data *data)
{
	return 0;
}

static int cwmp_ignore_response(struct rpc_data *data)
{
	return 0;
}

static const struct rpc_method response_types[] = {
	{ "InformResponse", cwmp_inform_response },
	{ "TransferCompleteResponse", cwmp_ignore_response },
};

int cwmp_session_response(struct rpc_data *data)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(rpc_methods); i++) {
		if (strcmp(rpc_methods[i].name, data->method) != 0)
			continue;

		data->response = SOAP_RESPONSE_DATA;
		return rpc_methods[i].handler(data);
	}

	for (i = 0; i < ARRAY_SIZE(response_types); i++) {
		if (strcmp(response_types[i].name, data->method) != 0)
			continue;

		return response_types[i].handler(data);
	}

	return CWMP_ERROR_INVALID_METHOD;
}

static void cwmp_add_inform_parameters(node_t *node)
{
	static const char *devinfo_params[] = {
		"SpecVersion",
		"HardwareVersion",
		"SoftwareVersion",
		"ProvisioningCode",
	};
	static const char *mgmt_params[] = {
		"ConnectionRequestURL",
		"ParameterKey",
	};
	char path[CWMP_PATH_LEN];
	char *cur, *cur1;
	int i, n = 0;

	node = cwmp_open_array(node, "ParameterList");

	cur = path + sprintf(path, "%s.", CWMP_ROOT_OBJECT);

	backend.get_parameter_values_init();
	cur1 = cur + sprintf(cur, "DeviceInfo.");
	for (i = 0; i < ARRAY_SIZE(devinfo_params); i++) {
		strcpy(cur1, devinfo_params[i]);
		n += cwmp_add_parameter_value(node, path);
	}

	cur1 = cur + sprintf(cur, "ManagementServer.");
	for (i = 0; i < ARRAY_SIZE(mgmt_params); i++) {
		strcpy(cur1, mgmt_params[i]);
		n += cwmp_add_parameter_value(node, path);
	}

	if (backend.get_parameter_values)
		n = backend.get_parameter_values(node, add_parameter_value);

#if 0
	n += cwmp_attr_cache_add_changed(node);
	cwmp_close_array(node, n, "ParameterValueStruct");
#endif
}

static int
cwmp_add_event(node_t *node, const char *code, const char *key,
	       struct blob_attr *data)
{
	struct xml_kv ev_kv[2] = {
		{ "EventCode", code },
		{ "CommandKey", key },
	};
	struct event_rpc *rpc;

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "EventStruct", NULL);
	xml_add_multi(node, ROXML_ELM_NODE, ARRAY_SIZE(ev_kv), ev_kv, NULL);
	if (data) {
		rpc = calloc(1, sizeof(*rpc));
		rpc->data = data;
		rpc->command_key = key;
		list_add(&rpc->list, &event_msgs);
	}
	return 1;
}

static int cwmp_add_event_blob(node_t *node, struct blob_attr *ev)
{
	static const struct blobmsg_policy ev_policy[3] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *ev_attr[3];
	const char *val = "";

	if (blobmsg_type(ev) != BLOBMSG_TYPE_ARRAY)
		return 0;

	blobmsg_parse_array(ev_policy, ARRAY_SIZE(ev_policy), ev_attr,
			    blobmsg_data(ev), blobmsg_data_len(ev));
	if (!ev_attr[0])
		return 0;

	if (ev_attr[1])
		val = blobmsg_data(ev_attr[1]);

	return cwmp_add_event(node, blobmsg_data(ev_attr[0]), val, ev_attr[2]);
}

static void cwmp_add_inform_events(node_t *node)
{
	struct blob_attr *ev = NULL;
	int n = 0;

	node = cwmp_open_array(node, "Event");

	if (events.head) {
		struct blob_attr *cur;
		int rem;

		ev = blob_data(events.head);
		blobmsg_for_each_attr(cur, ev, rem)
			n += cwmp_add_event_blob(node, cur);
	}

	/* TODO: add "4 VALUE CHANGED" events */

	cwmp_close_array(node, n, "EventStruct");
}

static const char * get_name_offset(const char *path)
{
	unsigned len = strlen(path);

	if (len == 0 || path[len - 1] == '.')
		return "";

	while (--len && path[len] != '.')
		;

	return &path[len + 1];
}

static void add_value(struct cwmp_iterator *it, union cwmp_any *a)
{
	const struct b_cwmp_param *p = &a->param;
	const char *name;

	if (p->path)
		name = get_name_offset(p->path);
	else
		name = p->name;

	roxml_add_node(it->node, 0, ROXML_ELM_NODE,
			(char *)name, (char *)p->value);
}

static void add_value_oui(struct cwmp_iterator *it, union cwmp_any *a)
{
	const struct b_cwmp_param *p = &a->param;

	roxml_add_node(it->node, 0, ROXML_ELM_NODE,
			(char *)"OUI", (char *)p->value);
}

static void cwmp_add_oui(node_t *node)
{
	struct cwmp_iterator it;

	cwmp_iterator_init(&it);
	it.node = node;
	it.cb = add_value_oui;

	sprintf(it.path, "%s.DeviceInfo.ManufacturerOUI", CWMP_ROOT_OBJECT);

	backend.get_parameter_values_init();
	backend.get_parameter_value(&it);

	if (backend.get_parameter_values)
		backend.get_parameter_values(node, add_value_oui);
}

static void cwmp_add_device_id(node_t *node)
{
	struct cwmp_iterator it;
	static const char *devid_params[] = {
		"Manufacturer",
		"ManufacturerOUI",
		"ProductClass",
		"SerialNumber"
	};
	char *cur;
	unsigned i;

	node = roxml_add_node(node, 0, ROXML_ELM_NODE, "DeviceId", NULL);

	cwmp_iterator_init(&it);
	it.node = node;
	it.cb = add_value;

	backend.get_parameter_values_init();

	cur = it.path + sprintf(it.path, "%s.DeviceInfo.", CWMP_ROOT_OBJECT);
	for (i = 0; i < ARRAY_SIZE(devid_params); i++) {
		strcpy(cur, devid_params[i]);
		backend.get_parameter_value(&it);
	}

	if (backend.get_parameter_values)
		backend.get_parameter_values(node, add_value);

	cwmp_add_oui(node);
}

int cwmp_session_init(struct rpc_data *data)
{
	time_t now = time(NULL);
	node_t *node;

	node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:Inform", NULL);

	cwmp_add_device_id(node);
	cwmp_add_inform_events(node);
	roxml_add_node(node, 0, ROXML_ELM_NODE, "MaxEnvelopes", "1");
	soap_add_time(node, "CurrentTime", localtime(&now));
	roxml_add_node(node, 0, ROXML_ELM_NODE, "RetryCount", "0");
	cwmp_add_inform_parameters(node);

	return 0;
}

static bool cwmp_add_event_msg(struct rpc_data *data, struct event_rpc *rpc)
{
	enum {
		EVMSG_TYPE,
		EVMSG_ERROR,
		__EVMSG_MAX
	};
	static const struct blobmsg_policy policy[__EVMSG_MAX] = {
		[EVMSG_TYPE] = { "type", BLOBMSG_TYPE_STRING },
		[EVMSG_ERROR] = { "error", BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[__EVMSG_MAX];
	const char *type;
	int error = 0;
	node_t *node;

	blobmsg_parse(policy, __EVMSG_MAX, tb, blobmsg_data(rpc->data), blobmsg_data_len(rpc->data));

	if (!tb[EVMSG_TYPE])
		return false;

	type = blobmsg_data(tb[EVMSG_TYPE]);
	if (tb[EVMSG_ERROR])
		error = blobmsg_get_u32(tb[EVMSG_ERROR]);

	if (!strcmp(type, "TransferComplete")) {
		node = roxml_add_node(data->out, 0, ROXML_ELM_NODE, "cwmp:TransferComplete", NULL);
		soap_add_fault_struct(node, error);
		soap_add_time(node, "StartTime", NULL);
		soap_add_time(node, "CompleteTime", NULL);
	} else {
		return false;
	}

	roxml_add_node(node, 0, ROXML_ELM_NODE, "CommandKey", (char *) rpc->command_key);
	data->response = SOAP_RESPONSE_DATA;

	return true;
}

void cwmp_session_continue(struct rpc_data *data)
{
	struct event_rpc *rpc, *tmp;

	list_for_each_entry_safe(rpc, tmp, &event_msgs, list) {
		bool ret;

		ret = cwmp_add_event_msg(data, rpc);
		list_del(&rpc->list);
		free(rpc);

		if (ret)
			return;
	}

	if (data->empty_message) {
		cwmp_invoke_noarg("session_completed");
		uloop_end();
		return;
	}

	data->response = SOAP_RESPONSE_EMPTY;
}
