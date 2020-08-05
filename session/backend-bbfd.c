#include "backend.h"
#include "ubus.h"
#include "blob_helpers.h"

#include <string.h>
#include <inttypes.h>

#define USP_UBUS "bbfd.raw"

static struct bbfdd_ctx {
	struct ubus_context *ubus_ctx;
	unsigned bbfdd_id;
	int prepared;
	struct blob_buf buf;
	void *array;
} bbfdd;

struct bbfdd_get_req {
	struct cwmp_iterator *it;
	bool names_only;
	unsigned n_values;
};

struct bbfdd_set_req {
	const char *path;
	const char *value;
	int error;
};

struct bbfdd_set_attrib_req {
	node_t *node;
	cwmp_iterator_cb cb;
	unsigned n_values;
	int fault;
};

struct bbfdd_add_req {
	struct cwmp_iterator *it;
	int error;
};

struct bbfdd_del_req {
	const char *path;
	const char *key;
	int error;
};

static void bbfd_init(struct ubus_context *ubus)
{
	memset(&bbfdd, 0, sizeof(bbfdd));
	bbfdd.ubus_ctx = ubus;
}

static void bbfd_deinit()
{
	blob_buf_free(&bbfdd.buf);
}

static int bbfdd_lookup(struct bbfdd_ctx *ctx)
{
	int err;

	err = ubus_lookup_id(ctx->ubus_ctx, USP_UBUS, &ctx->bbfdd_id);
	if (err)
		err_ubus(err, "ubus_lookup %s failed", USP_UBUS);

	return !err;
}

static int bbfdd_ctx_prepare(struct bbfdd_ctx *ctx)
{
	if (!ctx->prepared)
		ctx->prepared = bbfdd_lookup(ctx);
	return ctx->prepared;
}

static void bbfdd_set_req_init(struct bbfdd_set_req *r,
				const char *path,
				const char *value)
{
	r->path = path;
	r->value = value;
	r->error = CWMP_ERROR_INTERNAL_ERROR;
}

static void bbfdd_set_attrib_req_init(struct bbfdd_set_attrib_req *r,
				node_t *node,
				cwmp_iterator_cb cb)
{
	r->node = node;
	r->cb = cb;
	r->n_values = 0;
	r->fault = 0;
}

static void bbfdd_get_req_init(struct bbfdd_get_req *r,
				struct cwmp_iterator *it,
				int names_only)
{
	r->it = it;
	r->names_only = names_only;
	r->n_values = 0;
}

static void bbfdd_add_req_init(struct bbfdd_add_req *r,
				struct cwmp_iterator *it)
{
	r->it = it;
	r->error = CWMP_ERROR_INTERNAL_ERROR;
}

static void bbfdd_del_req_init(struct bbfdd_del_req *r,
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
	struct bbfdd_get_req *r = req->priv;
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

			cwmp_debug(1, "bbfd", "parameter '%s' get %s '%s'\n",
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

			cwmp_debug(1, "bbfd",
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
	struct bbfdd_set_attrib_req *r = req->priv;
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

		cwmp_debug(1, "bbfd", "set parameter '%s' fault %d\n",
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
	struct bbfdd_set_req *r = req->priv;
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

		cwmp_debug(1, "bbfd", "parameter '%s' set value '%s' error '%d'\n",
			  r->path, r->value, r->error);

		/* No multi set parameter support yet */
		param_cnt++;
		break;
	}

	/* bbfdd returns emtpy repsonse on non existent path */
	if (param_cnt == 0)
		r->error = CWMP_ERROR_INVALID_PARAM;
}

static void bbfd_get_parameter_values_init()
{
	blob_buf_init(&bbfdd.buf, 0);
	bbfdd.array = blobmsg_open_array(&bbfdd.buf, "paths");
}

static int bbfd_get_parameter(node_t *node, cwmp_iterator_cb cb, const char *method)
{
	struct bbfdd_get_req req;
	struct cwmp_iterator it = { .cb = cb, .node = node };
	int err;

	blobmsg_close_array(&bbfdd.buf, bbfdd.array);

	if (!bbfdd_ctx_prepare(&bbfdd))
		return 0;

	bbfdd_get_req_init(&req, &it, false);

	blobmsg_add_string(&bbfdd.buf, "proto", "cwmp");

	err = ubus_invoke(bbfdd.ubus_ctx, bbfdd.bbfdd_id, method,
			bbfdd.buf.head, get_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " %s", method);
		bbfdd.prepared = 0;
	}
	return req.n_values;
}

static int bbfd_get_parameter_attributes(node_t *node, cwmp_iterator_cb cb)
{
	return bbfd_get_parameter(node, cb, "get_attributes");
}

static int bbfd_get_parameter_values(node_t *node, cwmp_iterator_cb cb)
{
	return bbfd_get_parameter(node, cb, "get_values");
}

static int bbfd_set_parameter_attributes(node_t *node, cwmp_iterator_cb cb)
{
	struct bbfdd_set_attrib_req req;
	int err;

	blobmsg_close_array(&bbfdd.buf, bbfdd.array);

	if (!bbfdd_ctx_prepare(&bbfdd))
		return 0;

	bbfdd_set_attrib_req_init(&req, node, cb);

	blobmsg_add_string(&bbfdd.buf, "proto", "cwmp");

	err = ubus_invoke(bbfdd.ubus_ctx, bbfdd.bbfdd_id, "set_safe_attributes",
			bbfdd.buf.head, set_attrib_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " set_safe_attributes");
		bbfdd.prepared = 0;
	}
	return req.fault;
}

static int bbfd_set_parameter_attribute(const char *path, const char *notif_change, const char *notif_value)
{
	void *t = blobmsg_open_table(&bbfdd.buf, NULL);

	blobmsg_add_string(&bbfdd.buf, "path", path);
	blobmsg_add_string(&bbfdd.buf, "notify-type", notif_value);
	blobmsg_add_string(&bbfdd.buf, "notify", notif_change);
	blobmsg_close_table(&bbfdd.buf, t);

	return 0;
}

static int bbfd_get_parameter_value(struct cwmp_iterator *it)
{
	blobmsg_add_string(&bbfdd.buf, NULL, it->path);
	return 0;
}

static int bbfd_get_parameter_names(struct cwmp_iterator *it, bool next_level)
{
	struct bbfdd_get_req req;
	void *a;
	int err;

	if (!bbfdd_ctx_prepare(&bbfdd))
		return 0;

	bbfdd_get_req_init(&req, it, true);

	blob_buf_init(&bbfdd.buf, 0);
	a = blobmsg_open_array(&bbfdd.buf, "paths");
	blobmsg_add_string(&bbfdd.buf, NULL, it->path);
	blobmsg_close_array(&bbfdd.buf, a);
	blobmsg_add_string(&bbfdd.buf, "proto", "cwmp");
	blobmsg_add_u8(&bbfdd.buf, "next-level", next_level);

	err = ubus_invoke(bbfdd.ubus_ctx, bbfdd.bbfdd_id, "get_names",
			bbfdd.buf.head, get_cb, &req, 10000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " get path=%s", it->path);
		if (err == UBUS_STATUS_INVALID_ARGUMENT)
			/* bbfdd responds with -EINVAL when the path fails basic checks
			 */
			it->error = CWMP_ERROR_INVALID_PARAM;
		else
			it->error = CWMP_ERROR_INTERNAL_ERROR;

		bbfdd.prepared = 0;
	}
	return req.n_values;
}

static int bbfd_set_parameter_value(const char *path, const char *value, const char *key)
{
	struct bbfdd_set_req req;
	int err;

	if (!bbfdd_ctx_prepare(&bbfdd))
		return CWMP_ERROR_INTERNAL_ERROR;

	bbfdd_set_req_init(&req, path, value);

	cwmp_debug(1, "bbfd", "Object '%s' set value '%s'\n",
		   path, value);

	blob_buf_init(&bbfdd.buf, 0);
	blobmsg_add_string(&bbfdd.buf, "path", path);
	blobmsg_add_string(&bbfdd.buf, "value", value);
	blobmsg_add_string(&bbfdd.buf, "key", key);
	blobmsg_add_string(&bbfdd.buf, "proto", "cwmp");

	err = ubus_invoke(bbfdd.ubus_ctx, bbfdd.bbfdd_id, "set",
			bbfdd.buf.head, set_cb, &req, 2000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS " set path=%s,value=%s",
			path, value);
		bbfdd.prepared = 0;
	}
	return req.error;
}

static int bbfd_commit()
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
	struct bbfdd_add_req *r = req->priv;
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

	cwmp_debug(1, "bbfd", "Add Obejct '%s' instance '%s' status '%d'\n",
		  r->it->path, u.add_obj.instance_num, u.add_obj.status);
}

static int bbfd_add_object(struct cwmp_iterator *it, const char *key)
{
	struct bbfdd_add_req req;
	const char *path = it->path;
	int err;

	if (!bbfdd_ctx_prepare(&bbfdd))
		return CWMP_ERROR_INTERNAL_ERROR;

	cwmp_debug(1, "bbfd", "Add Object '%s' with key '%s'\n", path, key);

	blob_buf_init(&bbfdd.buf, 0);
	blobmsg_add_string(&bbfdd.buf, "path", path);
	blobmsg_add_string(&bbfdd.buf, "key", key);
	blobmsg_add_string(&bbfdd.buf, "proto", "cwmp");

	bbfdd_add_req_init(&req, it);

	err = ubus_invoke(bbfdd.ubus_ctx, bbfdd.bbfdd_id, "add_object",
			bbfdd.buf.head, add_cb, &req, 2000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS "add_object path=%s,key=%s",
			path, key);
		bbfdd.prepared = 0;
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
	struct bbfdd_del_req *r = req->priv;
	struct blob_attr *tb[__P_DEL_MAX];
	struct blob_attr *cur;
	int err = CWMP_ERROR_INVALID_PARAM;

	blobmsg_parse(p, __P_DEL_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[P_DEL_STATUS]))
		err = !blobmsg_get_u8(cur);

	/* fault overwrites status
	 */
	if ((cur = tb[P_DEL_FAULT]))
		err = blobmsg_get_u32(cur);

	r->error = err;

	cwmp_debug(1, "bbfd", "Del Obejct '%s' key '%s' status '%d'\n",
			r->path, r->key, err);
}

static int bbfd_del_object(const char *path, const char *key)
{
	struct bbfdd_del_req req;
	int err;

	if (!bbfdd_ctx_prepare(&bbfdd))
		return CWMP_ERROR_INTERNAL_ERROR;

	cwmp_debug(1, "bbfd", "Del Object '%s' with key '%s'\n", path, key);

	blob_buf_init(&bbfdd.buf, 0);
	blobmsg_add_string(&bbfdd.buf, "path", path);
	blobmsg_add_string(&bbfdd.buf, "key", key);
	blobmsg_add_string(&bbfdd.buf, "proto", "cwmp");

	bbfdd_del_req_init(&req, path, key);

	err = ubus_invoke(bbfdd.ubus_ctx, bbfdd.bbfdd_id, "del_object",
			bbfdd.buf.head, del_cb, &req, 2000);
	if (err) {
		err_ubus(err, "ubus_invoke " USP_UBUS "add_object path=%s,key=%s",
			path, key);
		bbfdd.prepared = 0;
	}
	return req.error;
}

const struct backend backend = {
	.init = bbfd_init,
	.deinit = bbfd_deinit,

	.get_parameter_names = bbfd_get_parameter_names,

	.get_parameter_values_init = bbfd_get_parameter_values_init,
	.get_parameter_value = bbfd_get_parameter_value,
	.set_parameter_value = bbfd_set_parameter_value,
	.get_parameter_values = bbfd_get_parameter_values,

	.get_parameter_attributes_init = bbfd_get_parameter_values_init,
	.get_parameter_attribute = bbfd_get_parameter_value,
	.get_parameter_attributes = bbfd_get_parameter_attributes,

	.set_parameter_attributes_init = bbfd_get_parameter_values_init,
	.set_parameter_attribute = bbfd_set_parameter_attribute,
	.set_parameter_attributes = bbfd_set_parameter_attributes,

	.add_object = bbfd_add_object,
	.del_object = bbfd_del_object,

	.commit = bbfd_commit,
};
