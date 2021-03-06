#include "backend.h"
#include "ubus.h"
#include "blob_helpers.h"

#include <string.h>
#include <inttypes.h>

#define USP_UBUS "usp.raw"

static struct uspd_ctx {
	struct ubus_context *ubus_ctx;
	unsigned uspd_id;
	int prepared;
	struct blob_buf buf;
	void *array;
} uspd;

struct uspd_get_req {
	struct cwmp_iterator *it;
	bool names_only;
	unsigned n_values;
};

struct uspd_set_req {
	const char *path;
	const char *value;
	int error;
};

struct uspd_set_attrib_req {
	node_t *node;
	cwmp_iterator_cb cb;
	unsigned n_values;
	int fault;
};

struct uspd_add_req {
	struct cwmp_iterator *it;
	int error;
};

struct uspd_del_req {
	const char *path;
	const char *key;
	int error;
};

static void usp_init(struct ubus_context *ubus)
{
	memset(&uspd, 0, sizeof(uspd));
	uspd.ubus_ctx = ubus;
}

static void usp_deinit()
{
	blob_buf_free(&uspd.buf);
}

static int uspd_lookup(struct uspd_ctx *ctx)
{
	int err;

	err = ubus_lookup_id(ctx->ubus_ctx, USP_UBUS, &ctx->uspd_id);
	if (err)
		err_ubus(err, "ubus_lookup %s failed", USP_UBUS);

	return !err;
}

static int uspd_ctx_prepare(struct uspd_ctx *ctx)
{
	if (!ctx->prepared)
		ctx->prepared = uspd_lookup(ctx);
	return ctx->prepared;
}

static void uspd_set_req_init(struct uspd_set_req *r,
				const char *path,
				const char *value)
{
	r->path = path;
	r->value = value;
	r->error = CWMP_ERROR_INTERNAL_ERROR;
}

static void uspd_set_attrib_req_init(struct uspd_set_attrib_req *r,
				node_t *node,
				cwmp_iterator_cb cb)
{
	r->node = node;
	r->cb = cb;
	r->n_values = 0;
	r->fault = 0;
}

static void uspd_get_req_init(struct uspd_get_req *r,
				struct cwmp_iterator *it,
				int names_only)
{
	r->it = it;
	r->names_only = names_only;
	r->n_values = 0;
}

static void uspd_add_req_init(struct uspd_add_req *r,
				struct cwmp_iterator *it)
{
	r->it = it;
	r->error = CWMP_ERROR_INTERNAL_ERROR;
}

static void uspd_del_req_init(struct uspd_del_req *r,
				const char *path,
				const char *key)
{
	r->path = path;
	r->key = key;
	r->error = CWMP_ERROR_INTERNAL_ERROR;
}

static struct blob_attr * get_parameters(struct blob_attr *msg)
{
	struct blob_attr *params = NULL;
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (blobmsg_type(cur) == BLOBMSG_TYPE_ARRAY) {
			params = cur;
			break;
		}
	}
	return params;
}

static struct blob_attr * get_parameters_first_entry(struct blob_attr *msg)
{
	struct blob_attr *params = get_parameters(msg);

	return params ? blobmsg_data(params) : NULL;
}

static void get_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum {
		P_VAL,
		P_TYPE,
		P_PARAM,
		__P_MAX
	};
	enum {
		P_FAULT_PATH,
		P_FAULT_FAULT,
		__P_FAULT_MAX
	};
	static const struct blobmsg_policy p[__P_MAX] = {
		{ "value", BLOBMSG_TYPE_UNSPEC },
		{ "type", BLOBMSG_TYPE_STRING },
		{ "parameter", BLOBMSG_TYPE_STRING }
	};
	static const struct blobmsg_policy p_fault[__P_FAULT_MAX] = {
		{ "path", BLOBMSG_TYPE_STRING },
		{ "fault", BLOBMSG_TYPE_INT32 }
	};
	char buf[32];
	struct uspd_get_req *r = req->priv;
	struct blob_attr *cur;
	struct blob_attr *params;
	int rem;

	params = get_parameters(msg);
	if (params == NULL)
		return;

	blobmsg_for_each_attr(cur, params, rem) {
		struct blob_attr *tb[__P_MAX];
		struct blob_attr *param;
		struct blob_attr *value;

		blobmsg_parse(p, __P_MAX, tb, blobmsg_data(cur), blobmsg_len(cur));
		param = tb[P_PARAM];
		value = tb[P_VAL];

		if ((value && param) || (r->names_only && param)) {
			union cwmp_any u;

			u.param.path = blobmsg_get_string(param);

			if (tb[P_TYPE])
				u.param.type = blobmsg_get_string(tb[P_TYPE]);
			if (u.param.type == NULL)
				u.param.type = "xsd:string";

			if (value != NULL)
				u.param.value = blob_any_to_string(value, buf, sizeof(buf));
			else
				u.param.value = "";

			r->it->cb(r->it, &u);
			r->n_values += 1;

			cwmp_debug(1, "usp", "parameter '%s' get %s '%s'\n",
					u.param.path,
					r->names_only ? "name" : "value",
					u.param.value);
		} else {
			struct blob_attr *tb_fault[__P_FAULT_MAX];
			struct blob_attr *tb_cur;
			const char *path = "";
			int fault = 0;

			blobmsg_parse(p_fault, __P_FAULT_MAX, tb_fault,
					blobmsg_data(cur), blobmsg_len(cur));

			if ((tb_cur = tb_fault[P_FAULT_PATH]))
				path = blobmsg_get_string(tb_cur);

			if ((tb_cur = tb_fault[P_FAULT_FAULT]))
				fault = blobmsg_get_u32(tb_cur);

			cwmp_debug(1, "usp",
				"parameter '%s' get value error '%d'\n",
				path, fault);

			if (fault)
				r->it->error = fault;
			else
				r->it->error = CWMP_ERROR_INTERNAL_ERROR;
		}
	}
}

static void set_attrib_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum {
		P_PATH,
		P_FAULT,
		__P_MAX
	};
	static const struct blobmsg_policy p[__P_MAX] = {
		{ "path", BLOBMSG_TYPE_STRING },
		{ "fault", BLOBMSG_TYPE_INT32 }
	};
	struct uspd_set_attrib_req *r = req->priv;
	struct blob_attr *cur;
	struct blob_attr *params;
	int rem;

	params = get_parameters(msg);
	if (params == NULL)
		return;

	blobmsg_for_each_attr(cur, params, rem) {
		struct blob_attr *tb[__P_MAX];
		union cwmp_any a;

		blobmsg_parse(p, __P_MAX, tb,
				blobmsg_data(cur), blobmsg_len(cur));

		if (tb[P_PATH])
			a.param.path = blobmsg_get_string(tb[P_PATH]);
		else
			a.param.path = "";

		if (tb[P_FAULT])
			a.param.fault = blobmsg_get_u32(tb[P_FAULT]);
		else
			a.param.fault = 0;

		cwmp_debug(1, "usp", "set parameter '%s' fault %d\n",
			  a.param.path, a.param.fault);

		r->cb(NULL, &a);
		r->n_values += 1;

		/* attributes only */
		if (a.param.fault) {
			r->fault = a.param.fault;
			break;
		}
	}
}

static void set_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum {
		P_STATUS,
		P_FAULT,
		__P_MAX
	};
	static const struct blobmsg_policy p[] = {
		{ "status", BLOBMSG_TYPE_INT8 },
		{ "fault", BLOBMSG_TYPE_INT32 }
	};
	struct uspd_set_req *r = req->priv;
	struct blob_attr *cur;
	struct blob_attr *params;
	int rem;
	int param_cnt = 0;

	params = get_parameters(msg);
	if (params == NULL)
		return;

	blobmsg_for_each_attr(cur, params, rem) {
		struct blob_attr *tb[__P_MAX];

		blobmsg_parse(p, __P_MAX, tb,
				blobmsg_data(cur), blobmsg_len(cur));

		if (tb[P_STATUS]) {
			bool status_ok = blobmsg_get_u8(tb[P_STATUS]);

			if (status_ok)
				r->error = 0;

			if (tb[P_FAULT])
				r->error = blobmsg_get_u32(tb[P_FAULT]);
		} else {
			err("missing 'status' field in response for set, %s = %s\n",
				r->path, r->value);
		}

		cwmp_debug(1, "usp", "parameter '%s' set value '%s' error '%d'\n",
			  r->path, r->value, r->error);

		/* No multi set parameter support yet */
		param_cnt++;
		break;
	}

	/* uspd returns emtpy repsonse on non existent path */
	if (param_cnt == 0)
		r->error = CWMP_ERROR_INVALID_PARAM;
}

static void usp_get_parameter_values_init()
{
	blob_buf_init(&uspd.buf, 0);
	uspd.array = blobmsg_open_array(&uspd.buf, "paths");
}

static int usp_get_parameter(node_t *node, cwmp_iterator_cb cb, const char *method)
{
	struct uspd_get_req req;
	struct cwmp_iterator it = { .cb = cb, .node = node };
	int err;

	blobmsg_close_array(&uspd.buf, uspd.array);

	if (!uspd_ctx_prepare(&uspd))
		return 0;

	uspd_get_req_init(&req, &it, false);

	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, method,
			uspd.buf.head, get_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " %s", method);
		uspd.prepared = 0;
	}
	return req.n_values;
}

static int usp_get_parameter_attributes(node_t *node, cwmp_iterator_cb cb)
{
	return usp_get_parameter(node, cb, "get_safe_attributes");
}

static int usp_get_parameter_values(node_t *node, cwmp_iterator_cb cb)
{
	return usp_get_parameter(node, cb, "get_safe_values");
}

static int usp_set_parameter_attributes(node_t *node, cwmp_iterator_cb cb)
{
	struct uspd_set_attrib_req req;
	int err;

	blobmsg_close_array(&uspd.buf, uspd.array);

	if (!uspd_ctx_prepare(&uspd))
		return 0;

	uspd_set_attrib_req_init(&req, node, cb);

	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "set_safe_attributes",
			uspd.buf.head, set_attrib_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " set_safe_attributes");
		uspd.prepared = 0;
	}
	return req.fault;
}

static int usp_set_parameter_attribute(const char *path, const char *notif_change, const char *notif_value)
{
	void *t = blobmsg_open_table(&uspd.buf, NULL);

	blobmsg_add_string(&uspd.buf, "path", path);
	blobmsg_add_string(&uspd.buf, "notify-type", notif_value);
	blobmsg_add_string(&uspd.buf, "notify", notif_change);
	blobmsg_close_table(&uspd.buf, t);

	return 0;
}

static int usp_get_parameter_value(struct cwmp_iterator *it)
{
	blobmsg_add_string(&uspd.buf, NULL, it->path);
	return 0;
}

static int usp_get_parameter_names(struct cwmp_iterator *it, bool next_level)
{
	struct uspd_get_req req;
	void *a;
	int err;

	if (!uspd_ctx_prepare(&uspd))
		return 0;

	uspd_get_req_init(&req, it, true);

	blob_buf_init(&uspd.buf, 0);
	a = blobmsg_open_array(&uspd.buf, "paths");
	blobmsg_add_string(&uspd.buf, NULL, it->path);
	blobmsg_close_array(&uspd.buf, a);
	blobmsg_add_string(&uspd.buf, "proto", "cwmp");
	blobmsg_add_u8(&uspd.buf, "next-level", next_level);

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "get_safe_names",
			uspd.buf.head, get_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " get path=%s", it->path);
		if (err == UBUS_STATUS_INVALID_ARGUMENT)
			/* uspd responds with -EINVAL when the path fails basic checks
			 */
			it->error = CWMP_ERROR_INVALID_PARAM;
		else
			it->error = CWMP_ERROR_INTERNAL_ERROR;

		uspd.prepared = 0;
	}
	return req.n_values;
}

static int usp_set_parameter_value(const char *path, const char *value, const char *key)
{
	struct uspd_set_req req;
	int err;

	if (!uspd_ctx_prepare(&uspd))
		return CWMP_ERROR_INTERNAL_ERROR;

	uspd_set_req_init(&req, path, value);

	cwmp_debug(1, "usp", "Object '%s' set value '%s'\n",
		   path, value);

	blob_buf_init(&uspd.buf, 0);
	blobmsg_add_string(&uspd.buf, "path", path);
	blobmsg_add_string(&uspd.buf, "value", value);
	blobmsg_add_string(&uspd.buf, "key", key);
	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "set",
			uspd.buf.head, set_cb, &req, 2000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " set path=%s,value=%s",
			path, value);
		uspd.prepared = 0;
	}
	return req.error;
}

static int usp_commit()
{
	return 0;
}

static void add_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum {
		P_ADD_STATUS,
		P_ADD_INSTANCE,
		P_ADD_FAULT,
		__P_ADD_MAX
	};
	static const struct blobmsg_policy p[__P_ADD_MAX] = {
		{ "status", BLOBMSG_TYPE_INT8 },
		{ "instance", BLOBMSG_TYPE_STRING },
		{ "fault", BLOBMSG_TYPE_INT32 },
	};
	struct uspd_add_req *r = req->priv;
	struct blob_attr *tb[__P_ADD_MAX];
	struct blob_attr *cur;
	union cwmp_any u = {};

	blobmsg_parse(p, __P_ADD_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[P_ADD_STATUS]))
		u.add_obj.status = !blobmsg_get_u8(cur);

	if ((cur = tb[P_ADD_FAULT]))
		u.add_obj.status = blobmsg_get_u32(cur);

	if ((cur = tb[P_ADD_INSTANCE]))
		u.add_obj.instance_num = blobmsg_get_string(cur);

	r->error = u.add_obj.status;
	r->it->cb(r->it, &u);

	cwmp_debug(1, "usp", "Add Obejct '%s' instance '%s' status '%d'\n",
		  r->it->path, u.add_obj.instance_num, u.add_obj.status);
}

static int usp_add_object(struct cwmp_iterator *it, const char *key)
{
	struct uspd_add_req req;
	const char *path = it->path;
	int err;

	if (!uspd_ctx_prepare(&uspd))
		return CWMP_ERROR_INTERNAL_ERROR;

	cwmp_debug(1, "usp", "Add Object '%s' with key '%s'\n", path, key);

	blob_buf_init(&uspd.buf, 0);
	blobmsg_add_string(&uspd.buf, "path", path);
	blobmsg_add_string(&uspd.buf, "key", key);
	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	uspd_add_req_init(&req, it);

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "add_object",
			uspd.buf.head, add_cb, &req, 2000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS "add_object path=%s,key=%s",
			path, key);
		uspd.prepared = 0;
	}
	return req.error;
}

static void del_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	enum {
		P_DEL_STATUS,
		P_DEL_FAULT,
		__P_DEL_MAX
	};
	static const struct blobmsg_policy p[__P_DEL_MAX] = {
		{ "status", BLOBMSG_TYPE_INT8 },
		{ "fault", BLOBMSG_TYPE_INT32 },
	};
	struct uspd_del_req *r = req->priv;
	struct blob_attr *tb[__P_DEL_MAX];
	struct blob_attr *cur;
	int err = CWMP_ERROR_INVALID_PARAM;

	msg = get_parameters_first_entry(msg);
	if (msg == NULL)
		goto out;

	blobmsg_parse(p, __P_DEL_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[P_DEL_STATUS]))
		err = !blobmsg_get_u8(cur);

	/* fault overwrites status
	 */
	if ((cur = tb[P_DEL_FAULT]))
		err = blobmsg_get_u32(cur);

out:
	r->error = err;

	cwmp_debug(1, "usp", "Del Obejct '%s' key '%s' status '%d'\n",
			r->path, r->key, err);
}

static int usp_del_object(const char *path, const char *key)
{
	struct uspd_del_req req;
	int err;

	if (!uspd_ctx_prepare(&uspd))
		return CWMP_ERROR_INTERNAL_ERROR;

	cwmp_debug(1, "usp", "Del Object '%s' with key '%s'\n", path, key);

	blob_buf_init(&uspd.buf, 0);
	blobmsg_add_string(&uspd.buf, "path", path);
	blobmsg_add_string(&uspd.buf, "key", key);
	blobmsg_add_string(&uspd.buf, "proto", "cwmp");

	uspd_del_req_init(&req, path, key);

	err = ubus_invoke(uspd.ubus_ctx, uspd.uspd_id, "del_object",
			uspd.buf.head, del_cb, &req, 2000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS "add_object path=%s,key=%s",
			path, key);
		uspd.prepared = 0;
	}
	return req.error;
}

const struct backend backend = {
	.init = usp_init,
	.deinit = usp_deinit,

	.get_parameter_names = usp_get_parameter_names,

	.get_parameter_values_init = usp_get_parameter_values_init,
	.get_parameter_value = usp_get_parameter_value,
	.set_parameter_value = usp_set_parameter_value,
	.get_parameter_values = usp_get_parameter_values,

	.get_parameter_attributes_init = usp_get_parameter_values_init,
	.get_parameter_attribute = usp_get_parameter_value,
	.get_parameter_attributes = usp_get_parameter_attributes,

	.set_parameter_attributes_init = usp_get_parameter_values_init,
	.set_parameter_attribute = usp_set_parameter_attribute,
	.set_parameter_attributes = usp_set_parameter_attributes,

	.add_object = usp_add_object,
	.del_object = usp_del_object,

	.commit = usp_commit,
};
