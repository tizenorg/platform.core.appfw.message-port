
// Message Port
// Copyright (c) 2015 Samsung Electronics Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the License);
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/**
 * @file	message-port.cpp
 * @brief	This is the implementation file for the MessagePort.
 */

#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <gio/gio.h>
#include <aul/aul.h>
#include <openssl/md5.h>
#include <bundle.h>
#include <pkgmgr-info.h>

#include "message-port.h"
#include "message-port-log.h"


#define MAX_PACKAGE_STR_SIZE 512
#define MESSAGEPORT_BUS_NAME_PREFIX "org.tizen.messageport._"
#define MESSAGEPORT_OBJECT_PATH "/org/tizen/messageport"
#define MESSAGEPORT_INTERFACE "org.tizen.messageport"



#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_LOGE(fmt, ##arg); \
		_LOGE("(%s) -> %s() return", #expr, __func__); \
		return val; \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_LOGE("(%s) -> %s() return", #expr, __func__); \
		return val; \
	} \
} while (0)

#define FREE_AND_NULL(ptr) do { \
	if (ptr) { \
		free((void *)ptr); \
		ptr = NULL; \
	} \
} while (0)

static bool _initialized = false;
static GDBusConnection *__gdbus_conn = NULL;
static char *__app_id;
static GHashTable *__local_port_info = NULL;
static GHashTable *__remote_port_info = NULL;;
static GHashTable *__sender_appid_hash = NULL;;
static GHashTable *__checked_app_list_hash = NULL;
static GHashTable *__trusted_app_list_hash = NULL;
static const int MAX_MESSAGE_SIZE = 16 * 1024;



enum __certificate_info_type {
	UNKNOWN = 0,
	CERTIFICATE_MATCH,
	CERTIFICATE_NOT_MATCH,
};

typedef struct message_port_local_port_info {
	messageport_message_cb callback;
	bool is_trusted;
	char *port_name;
	int local_id;
} message_port_local_port_info_s;

typedef struct message_port_remote_port_info {
	char *encoded_bus_name;
	char *sender_id;
	char *remote_app_id;
	int certificate_info;
	int watcher_id;
	GList *port_list;
} message_port_remote_app_info_s;

typedef struct port_list_info {
	char *port_name;
	bool is_trusted;
	bool exist;
} port_list_info_s;

static char *__get_encoded_bus_name(const char *bus_name, const char *prefix, int len)
{
	unsigned char c[MD5_DIGEST_LENGTH] = {0};
	char *md5_interface = NULL;
	char *temp;
	int index = 0;
	MD5_CTX mdContext;
	int interface_len = len + (MD5_DIGEST_LENGTH * 2) + 1;

	MD5_Init(&mdContext);
	MD5_Update(&mdContext, bus_name, strlen(bus_name));
	MD5_Final(c, &mdContext);

	md5_interface = (char *)calloc(interface_len , sizeof(char));
	if (md5_interface == NULL) {
		_LOGI("Malloc failed!!");
		return 0;
	}

	snprintf(md5_interface, interface_len, "%s", prefix);
	temp = md5_interface;
	temp += len;

	for (index = 0; index < MD5_DIGEST_LENGTH; index++) {
		snprintf(temp, 3, "%02x", c[index]);
		temp += 2;
	}

	return md5_interface;
}

static char *__get_bus_name(const char *remote_app_id)
{
	char *bus_name = NULL;

	bus_name = __get_encoded_bus_name(remote_app_id, MESSAGEPORT_BUS_NAME_PREFIX, strlen(MESSAGEPORT_BUS_NAME_PREFIX));
	if (!bus_name) {
		_LOGE("fail to get bus name");
	}
	return bus_name;
}

int __get_next_id(void)
{
	static int count = 0;

	++count;
	return count;
}

static int __remote_port_compare_cb(gconstpointer a, gconstpointer b)
{
	port_list_info_s *key1 = (port_list_info_s *)a;
	port_list_info_s *key2 = (port_list_info_s *)b;

	if (key1->is_trusted == key2->is_trusted) {
		return strcmp(key1->port_name, key2->port_name);
	}

	return 1;
}


static bool __is_preloaded(const char *local_appid, const char *remote_appid)
{
	_LOGI("IsPreloaded");

	bool preload_local = false;
	bool preload_remote = false;

	pkgmgrinfo_appinfo_h handle = NULL;
	int ret = pkgmgrinfo_appinfo_get_usr_appinfo(local_appid, getuid(), &handle);
	if (ret != PMINFO_R_OK)	{
		_LOGE("Failed to get the appinfo. %d", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return false;
	}
	ret = pkgmgrinfo_appinfo_is_preload(handle, &preload_local);
	if (ret != PMINFO_R_OK) {
		_LOGE("Failed to check the preloaded application. %d", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return false;
	}
	ret = pkgmgrinfo_appinfo_get_usr_appinfo(remote_appid, getuid(), &handle);
	if (ret != PMINFO_R_OK) {
		_LOGE("Failed to get the appinfo. %d", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return false;
	}
	ret = pkgmgrinfo_appinfo_is_preload(handle, &preload_remote);
	if (ret != PMINFO_R_OK) {
		_LOGE("Failed to check the preloaded application. %d", ret);
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return false;
	}

	if (preload_local && preload_remote) {
		pkgmgrinfo_appinfo_destroy_appinfo(handle);
		return true;
	}
	pkgmgrinfo_appinfo_destroy_appinfo(handle);
	return false;
}

static int __check_certificate(const char *local_appid, const char *remote_appid)
{
	_LOGI("CheckCertificate");

	pkgmgrinfo_cert_compare_result_type_e res;
	int ret = pkgmgrinfo_pkginfo_compare_usr_app_cert_info(local_appid,
			remote_appid, getuid(), &res);
	if (ret < 0) {
		_LOGE(":CheckCertificate() Failed");
		return MESSAGEPORT_ERROR_IO_ERROR;
	}
	if (res != PMINFO_CERT_COMPARE_MATCH) {
		_LOGE("CheckCertificate() Failed : MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH");
		return MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH;
	}

	return MESSAGEPORT_ERROR_NONE;
}

static void on_name_appeared (GDBusConnection *connection,
		const gchar     *name,
		const gchar     *name_owner,
		gpointer         user_data)
{
	_LOGI("name appeared : %s %s", __app_id, name);
}

static void on_name_vanished (GDBusConnection *connection,
		const gchar     *name,
		gpointer         user_data)
{
	_LOGI("name vanished : %s", name);
	message_port_remote_app_info_s *remote_app_info = (message_port_remote_app_info_s *)user_data;
	g_bus_unwatch_name(remote_app_info->watcher_id);
	g_hash_table_remove(__remote_port_info, remote_app_info->remote_app_id);
}

static void __hash_destory_list_value(gpointer data)
{
	GList *list = (GList *)data;
	g_list_foreach(list, (GFunc)g_free, NULL);
	g_list_free(list);
	list = NULL;
}

static void __set_checked_app_list(message_port_local_port_info_s *mi, char *remote_appid) {

	GList *app_list = (GList *)g_hash_table_lookup(__checked_app_list_hash, mi->port_name);
	if (app_list == NULL) {
		app_list = g_list_append(app_list, strdup(remote_appid));
		_LOGI("set checked_app_list appid: %s", remote_appid);
		g_hash_table_insert(__checked_app_list_hash, mi->port_name, app_list);
	} else {
		GList *app = g_list_find(app_list, (gpointer)remote_appid);
		if (app == NULL) {
			app_list = g_list_append(app_list, strdup(remote_appid));
			_LOGI("set checked_app_list appid: %s", remote_appid);
		}
	}
}

static int __get_local_port_info(int id, message_port_local_port_info_s **info)
{
	message_port_local_port_info_s *mi = (message_port_local_port_info_s *)g_hash_table_lookup(__local_port_info, GINT_TO_POINTER(id));

	if (mi == NULL) {
		return MESSAGEPORT_ERROR_INVALID_PARAMETER;
	}
	*info = mi;

	return MESSAGEPORT_ERROR_NONE;
}

static port_list_info_s *__set_remote_port_info(const char *remote_app_id, const char *remote_port, bool is_trusted)
{
	int ret_val = MESSAGEPORT_ERROR_NONE;
	port_list_info_s *port_info = (port_list_info_s *)calloc(1, sizeof(port_list_info_s));

	if (!port_info) {
		ret_val = MESSAGEPORT_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	port_info->port_name = strdup(remote_port);
	if (!port_info->port_name) {
		ret_val = MESSAGEPORT_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	port_info->is_trusted = is_trusted;

	out:
	if (ret_val != MESSAGEPORT_ERROR_NONE) {
		if (port_info) {
			FREE_AND_NULL(port_info->port_name);
			free(port_info);
		}
		return NULL;
	}
	return port_info;
}

static message_port_remote_app_info_s *__set_remote_app_info(const char *remote_app_id, const char *remote_port, bool is_trusted)
{
	port_list_info_s *port_info = NULL;
	message_port_remote_app_info_s *remote_app_info = NULL;
	int ret_val = MESSAGEPORT_ERROR_NONE;

	remote_app_info = (message_port_remote_app_info_s *)calloc(1, sizeof(message_port_remote_app_info_s));
	if (!remote_app_info) {
		ret_val = MESSAGEPORT_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	remote_app_info->encoded_bus_name = __get_bus_name(remote_app_id);
	if (remote_app_info->encoded_bus_name == NULL) {
		ret_val = MESSAGEPORT_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	remote_app_info->remote_app_id = strdup(remote_app_id);
	if (remote_app_info->remote_app_id == NULL) {
		ret_val = MESSAGEPORT_ERROR_OUT_OF_MEMORY;;
		goto out;
	}

	remote_app_info->watcher_id = g_bus_watch_name(G_BUS_TYPE_SESSION,
		remote_app_info->encoded_bus_name,
		G_BUS_NAME_WATCHER_FLAGS_NONE,
		on_name_appeared,
		on_name_vanished,
		remote_app_info,
		NULL);

	port_info = __set_remote_port_info(remote_app_id, remote_port, is_trusted);
	if (port_info == NULL) {
		ret_val = MESSAGEPORT_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	remote_app_info->port_list = g_list_append(remote_app_info->port_list, port_info);

	out:
	if (ret_val != MESSAGEPORT_ERROR_NONE) {
		if (remote_app_info) {
			FREE_AND_NULL(remote_app_info->encoded_bus_name);
			FREE_AND_NULL(remote_app_info->remote_app_id);
			FREE_AND_NULL(remote_app_info);
		}
		return NULL;
	}
	return remote_app_info;
}

static int __get_remote_port_info(const char *remote_app_id, const char *remote_port, bool is_trusted,
		message_port_remote_app_info_s **mri, port_list_info_s **pli)
{
	message_port_remote_app_info_s *remote_app_info = NULL;
	port_list_info_s port_info;
	GList *cb_list = NULL;

	remote_app_info = (message_port_remote_app_info_s *)g_hash_table_lookup(__remote_port_info, remote_app_id);

	if (remote_app_info == NULL) {
		remote_app_info = __set_remote_app_info(remote_app_id, remote_port, is_trusted);
		retvm_if(!remote_app_info, MESSAGEPORT_ERROR_OUT_OF_MEMORY, "fail to create message_port_remote_app_info_s");
		g_hash_table_insert(__remote_port_info, remote_app_info->remote_app_id, remote_app_info);

	}
	*mri = remote_app_info;

	port_info.port_name = strdup(remote_port);
	port_info.is_trusted = is_trusted;
	cb_list = g_list_find_custom(remote_app_info->port_list, &port_info,
					(GCompareFunc)__remote_port_compare_cb);
	if (port_info.port_name)
		free(port_info.port_name);
	if (cb_list == NULL) {
		port_list_info_s *tmp = __set_remote_port_info(remote_app_id, remote_port, is_trusted);
		retvm_if(!tmp, MESSAGEPORT_ERROR_OUT_OF_MEMORY, "fail to create port_list_info_s");
		remote_app_info->port_list = g_list_append(remote_app_info->port_list, tmp);
		*pli = tmp;
	} else {
		*pli = (port_list_info_s *)cb_list->data;
	}
	return MESSAGEPORT_ERROR_NONE;
}

static bool __is_local_port_registed(const char *local_port, bool trusted, int *local_id, message_port_local_port_info_s **lpi)
{
	GHashTableIter iter;
	gpointer key, value;

	g_hash_table_iter_init(&iter, __local_port_info);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		message_port_local_port_info_s *mi = (message_port_local_port_info_s *)value;

		if ((mi->is_trusted == trusted) && strcmp(mi->port_name, local_port) == 0) {
			*local_id = mi->local_id;
			if (lpi != NULL) {
				*lpi = mi;
			}
			return true;
		}
	}
	return false;
}

static int __get_sender_pid(GDBusConnection *conn, const char *sender_name)
{
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GError *err = NULL;
	GVariant *body;
	int pid = 0;

	msg = g_dbus_message_new_method_call("org.freedesktop.DBus", "/org/freedesktop/DBus",
			"org.freedesktop.DBus", "GetConnectionUnixProcessID");
	if (!msg) {
		_LOGE("Can't allocate new method call");
		goto out;
	}

	g_dbus_message_set_body (msg, g_variant_new ("(s)", sender_name));
	reply = g_dbus_connection_send_message_with_reply_sync(conn, msg,
							G_DBUS_SEND_MESSAGE_FLAGS_NONE, 500, NULL, NULL, &err);

	if (!reply) {
		if (err != NULL) {
			_LOGE("Failed to get pid [%s]", err->message);
			g_error_free(err);
		}
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	g_variant_get(body, "(u)", &pid);

out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return pid;
}


static bool send_message(GVariant *parameters)
{
	char *local_port = NULL;
	char *local_appid = NULL;
	char *remote_appid = NULL;
	char *remote_port = NULL;
	gboolean local_trusted = false;
	gboolean remote_trusted = false;
	gboolean bi_dir = false;
	int len = 0;

	bundle *data = NULL;
	bundle_raw *raw = NULL;
	message_port_local_port_info_s *mi;
	int local_reg_id = 0;

	g_variant_get(parameters, "(ssbbssbus)", &local_appid, &local_port, &local_trusted, &bi_dir,
			&remote_appid, &remote_port, &remote_trusted, &len, &raw);

	if (!remote_port) {
		_LOGE("Invalid argument : remote_port is NULL");
		goto out;
	}
	if (!remote_appid) {
		_LOGE("Invalid argument : remote_appid is NULL");
		goto out;
	}
	if (!__is_local_port_registed(remote_port, remote_trusted, &local_reg_id, &mi)) {
		_LOGE("Invalid argument : remote_port:(%s) trusted(%d)", remote_port, remote_trusted);
		goto out;
	}
	if (!local_appid) {
		_LOGE("Invalid argument : local_appid");
		goto out;
	}
	if (!local_port) {
		_LOGE("Invalid argument : local_port");
		goto out;
	}
	if (strcmp(remote_appid, __app_id) != 0) {
		_LOGE("Invalid argument : remote_appid (%s)", remote_appid);
		goto out;
	}
	if (strcmp(remote_port, mi->port_name) != 0) {
		_LOGE("Invalid argument : remote_port (%s)", remote_port);
		goto out;
	}
	if (!len) {
		_LOGE("Invalid argument : data_len");
		goto out;
	}
	if (remote_trusted) {
		if (g_hash_table_lookup(__trusted_app_list_hash, (gpointer)local_appid) == NULL) {
			if (!__is_preloaded(local_appid, remote_appid)) {
				// Check the certificate
				int ret = __check_certificate(local_appid, remote_appid);
				if (ret == MESSAGEPORT_ERROR_NONE) {
					g_hash_table_insert(__trusted_app_list_hash, local_appid, "TRUE");
				} else {
					_LOGE("The application (%s) is not signed with the same certificate",
							local_appid);
					goto out;
				}
			}
		}
	}

	data = bundle_decode(raw, len);
	bundle_free_encoded_rawdata(&raw);

	if (!data) {
		_LOGE("Invalid argument : message");
		goto out;
	}

	if (bi_dir) {
		mi->callback(mi->local_id, local_appid, local_port, local_trusted, data);
	} else {
		mi->callback(mi->local_id, local_appid, NULL, false, data);
	}
out:

	return true;
}

static int unregister_port(GVariant *parameters)
{
	int ret = MESSAGEPORT_ERROR_NONE;
	char *remote_appid = NULL;
	char *remote_port = NULL;
	bool is_trusted;
	port_list_info_s *port_info = NULL;
	message_port_remote_app_info_s *remote_app_info = NULL;

	g_variant_get(parameters, "(sbs)", &remote_appid, &is_trusted, &remote_port);

	if (!remote_appid) {
		_LOGE("Invalid argument : remote_appid");
		ret = MESSAGEPORT_ERROR_INVALID_PARAMETER;
		goto out;
	}
	if (!remote_port) {
		_LOGE("Invalid argument : remote_port");
		ret = MESSAGEPORT_ERROR_INVALID_PARAMETER;
		goto out;
	}

	ret = __get_remote_port_info(remote_appid, remote_port, is_trusted, &remote_app_info, &port_info);
	if (ret != MESSAGEPORT_ERROR_NONE) {
		goto out;
	}
	port_info->exist = false;


	out:
	if (remote_appid)
		g_free(remote_appid);
	if (remote_port)
		g_free(remote_port);

	return ret;
}
static int __check_remote_port(const char *remote_app_id, const char *remote_port, bool is_trusted, bool *exist)
{
	_LOGI("Check a remote port : [%s:%s]", remote_app_id, remote_port);

	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GError *err = NULL;
	GVariant *body;
	int ret_val = MESSAGEPORT_ERROR_NONE;
	char *bus_name = NULL;
	message_port_remote_app_info_s *remote_app_info = NULL;
	port_list_info_s *port_info = NULL;
	int local_reg_id = 0;
	message_port_local_port_info_s *mi = NULL;

	_LOGI("remote_app_id, app_id :[%s : %s] ", remote_app_id, __app_id);

	ret_val = __get_remote_port_info(remote_app_id, remote_port, is_trusted, &remote_app_info, &port_info);
	if (ret_val != MESSAGEPORT_ERROR_NONE) {
		return ret_val;
	}

	if (strcmp(remote_app_id, __app_id) == 0) {

		_LOGI("__is_local_port_registed ");
		if (!__is_local_port_registed(remote_port, is_trusted, &local_reg_id, &mi)) {
			*exist = false;
		} else {
			*exist = true;
		}
		_LOGI("__is_local_port_registed : %d ", *exist);
		return MESSAGEPORT_ERROR_NONE;
	}

	*exist = false;
	port_info->exist = false;
	bus_name = remote_app_info->encoded_bus_name;

	msg = g_dbus_message_new_method_call(bus_name, MESSAGEPORT_OBJECT_PATH,
			MESSAGEPORT_INTERFACE, "check_remote_port");
	_LOGI("bus_name, remote app id:[%s : %s] ", bus_name, remote_app_id);
	if (!msg) {
		_LOGI("Can't allocate new method call");
		return MESSAGEPORT_ERROR_OUT_OF_MEMORY;
	}

	g_dbus_message_set_body(msg, g_variant_new("(sbss)", __app_id, is_trusted, remote_app_id, remote_port));
	reply = g_dbus_connection_send_message_with_reply_sync(
			__gdbus_conn,
			msg,
			G_DBUS_SEND_MESSAGE_FLAGS_NONE,
			500,
			NULL,
			NULL,
			&err);

	if (err || (reply == NULL)) {
		if (err) {
			_LOGE("No reply. error = %s", err->message);
			g_error_free(err);
		}
		ret_val = MESSAGEPORT_ERROR_IO_ERROR;
	} else {
		if (g_dbus_message_to_gerror(reply, &err)) {
			_LOGE("error = %s", err->message);
			g_error_free(err);
			ret_val = MESSAGEPORT_ERROR_NONE;
			*exist = false;
		} else {
			body = g_dbus_message_get_body(reply);
			g_variant_get(body, "(i)", &ret_val);

			if (ret_val == MESSAGEPORT_ERROR_NONE) {
				*exist = true;
				port_info->exist = true;
			} else if (ret_val == MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH) {
				_SECURE_LOGI("The remote application (%s) is not signed with the same certificate", remote_app_id);
			}
		}
	}

	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return ret_val;
}

static int check_remote_port(GVariant *parameters)
{
	int ret = MESSAGEPORT_ERROR_NONE;
	char *remote_appid = NULL;
	char *remote_port = NULL;
	char *local_appid = NULL;
	bool is_trusted;
	int local_reg_id = 0;
	message_port_local_port_info_s *mi = NULL;

	g_variant_get(parameters, "(sbss)", &local_appid, &is_trusted, &remote_appid, &remote_port);

	if (!local_appid) {
		_LOGE("Invalid argument : local_appid");
		ret = MESSAGEPORT_ERROR_INVALID_PARAMETER;
		goto out;
	}
	if (!remote_appid) {
		_LOGE("Invalid argument : remote_appid");
		ret = MESSAGEPORT_ERROR_INVALID_PARAMETER;
		goto out;
	}
	if (!remote_port) {
		_LOGE("Invalid argument : remote_port");
		ret = MESSAGEPORT_ERROR_INVALID_PARAMETER;
		goto out;
	}
	if (strcmp(remote_appid, __app_id) != 0) {
		_LOGE("Invalid argument : remote_appid (%s)", remote_appid);
		ret =  MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
		goto out;
	}
	if (!__is_local_port_registed(remote_port, is_trusted, &local_reg_id, &mi)) {
		_LOGE("Invalid argument : remote_port:(%s) trusted(%d)", remote_port, is_trusted);
		ret = MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
		goto out;
	}
	if (is_trusted) {
		// Check the preloaded
		if (!__is_preloaded(local_appid, remote_appid)) {
			// Check the certificate
			ret = __check_certificate(local_appid, remote_appid);
			if (ret == MESSAGEPORT_ERROR_NONE) {
				g_hash_table_insert(__trusted_app_list_hash, local_appid, "TRUE");
			}
		}
	}

	__set_checked_app_list(mi, local_appid);

out :

	return ret;
}

static bool __check_sender_validation(GVariant *parameters, const char *sender, GDBusConnection *conn)
{
	int ret = 0;
	char buffer[MAX_PACKAGE_STR_SIZE] = {0, };
	char *local_appid = NULL;
	int pid = __get_sender_pid(conn, sender);

	ret = aul_app_get_appid_bypid(pid, buffer, sizeof(buffer));
	retvm_if(ret != AUL_R_OK, false, "Failed to get the sender ID: (%s) (%d)", sender, pid);

	g_variant_get_child(parameters, 0, "s", &local_appid);
	retvm_if(!local_appid, false, "remote_appid is NULL (%s) (%d)", sender, pid);

	if (strncmp(buffer, local_appid, MAX_PACKAGE_STR_SIZE) == 0) {
		g_hash_table_insert(__sender_appid_hash, strdup(sender), GINT_TO_POINTER(pid));
		g_free(local_appid);
	} else {
		g_free(local_appid);
		return false;
	}
	return true;
}

static void __dbus_method_call_handler(GDBusConnection *conn,
				const gchar *sender, const gchar *object_path,
				const gchar *iface_name, const gchar *method_name,
				GVariant *parameters, GDBusMethodInvocation *invocation,
				gpointer user_data)
{
	_LOGI("method_name: %s", method_name);
	 gpointer sender_pid = g_hash_table_lookup(__sender_appid_hash, sender);
	int ret = MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
	if (sender_pid == NULL) {
		if (!__check_sender_validation(parameters, sender, conn))
			return;
	}
	if (g_strcmp0(method_name, "send_message") == 0) {
		ret =send_message(parameters);
	} else if (g_strcmp0(method_name, "check_remote_port") == 0) {
		ret = check_remote_port(parameters);
			g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", ret));
	} else if (g_strcmp0(method_name, "unregister_port") == 0) {
		ret = unregister_port(parameters);
			g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", ret));
	}


}

static const GDBusInterfaceVTable interface_vtable = {
	__dbus_method_call_handler,
	NULL,
	NULL
};

static int __dbus_init(void)
{
	static gchar introspection[] =
		"<node>"
		"  <interface name='"
		MESSAGEPORT_INTERFACE
		"'>"
		"	 <method name='send_message'>"
		"	   <arg type='s' name='local_appid' direction='in'/>"
		"	   <arg type='s' name='local_port' direction='in'/>"
		"	   <arg type='b' name='local_trusted' direction='in'/>"
		"	   <arg type='b' name='bi_dir' direction='in'/>"
		"	   <arg type='s' name='remote_appid' direction='in'/>"
		"	   <arg type='s' name='remote_port' direction='in'/>"
		"	   <arg type='b' name='remote_trusted' direction='in'/>"
		"	   <arg type='u' name='data_len' direction='in'/>"
		"	   <arg type='s' name='data' direction='in'/>"
		"	 </method>"
		"	 <method name='check_remote_port'>"
		"	   <arg type='s' name='local_appid' direction='in'/>"
		"	   <arg type='b' name='is_trusted' direction='in'/>"
		"	   <arg type='s' name='remote_appid' direction='in'/>"
		"	   <arg type='s' name='remote_port' direction='in'/>"
		"	   <arg type='i' name='response' direction='out'/>"
		"	 </method>"
		"	 <method name='unregister_port'>"
		"	   <arg type='s' name='local_appid' direction='in'/>"
		"	   <arg type='b' name='is_trusted' direction='in'/>"
		"	   <arg type='s' name='remote_port' direction='in'/>"
		"	   <arg type='i' name='response' direction='out'/>"
		"	 </method>"
		"  </interface>"
		"</node>";

	int owner_id = 0;
	int registration_id = 0;
	char *bus_name = NULL;
	bool ret = false;
	GError *error = NULL;
	GDBusNodeInfo *introspection_data = NULL;

	bus_name = __get_bus_name(__app_id);
	retvm_if(!bus_name, false, "bus_name is NULL");

	__gdbus_conn = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &error);
	if (__gdbus_conn == NULL) {
		if (error != NULL) {
			_LOGE("Failed to get dbus [%s]", error->message);
			g_error_free(error);
		}
		goto out;
	}

	owner_id = g_bus_own_name_on_connection(__gdbus_conn, bus_name,
			G_BUS_NAME_OWNER_FLAGS_NONE, NULL, NULL, NULL, NULL);

	if (owner_id == 0) {
		_LOGE("Acquiring the own name is failed");
		goto out;
	}

	introspection_data = g_dbus_node_info_new_for_xml(introspection, NULL);
	if (!introspection_data) {
		_LOGE("g_dbus_node_info_new_for_xml() is failed.");
		goto out;
	}

	registration_id = g_dbus_connection_register_object(__gdbus_conn,
						MESSAGEPORT_OBJECT_PATH, introspection_data->interfaces[0],
						&interface_vtable, NULL, NULL, NULL);

	_LOGE("registration_id %d", registration_id);

	if (registration_id == 0) {
		_LOGE("Failed to g_dbus_connection_register_object");
		goto out;
	}
	ret = true;

out:
	FREE_AND_NULL(bus_name);
	if (!__gdbus_conn)
		g_object_unref(__gdbus_conn);
	if (introspection_data)
		g_dbus_node_info_unref(introspection_data);

	return ret;

}

void __list_free_port_list(gpointer data)
{
	port_list_info_s *n = (port_list_info_s *)data;

	FREE_AND_NULL(n->port_name);
	FREE_AND_NULL(n);
}

static void __hash_destory_local_value(gpointer data)
{
	message_port_local_port_info_s *mli = (message_port_local_port_info_s *)data;
	if (mli->port_name)
		free(mli->port_name);
}
static void __hash_destory_remote_value(gpointer data)
{
	message_port_remote_app_info_s *mri = (message_port_remote_app_info_s *)data;

	if (mri) {
		FREE_AND_NULL(mri->encoded_bus_name);
		FREE_AND_NULL(mri->sender_id);
		FREE_AND_NULL(mri->remote_app_id);
		if (mri->port_list) {
			g_list_free_full(mri->port_list, __list_free_port_list);
		}
	}
}

static bool __initialize(void)
{

	int pid = getpid();
	int ret = 0;
	char buffer[MAX_PACKAGE_STR_SIZE] = {0, };

	_LOGI("initialize");
	ret = aul_app_get_appid_bypid(pid, buffer, sizeof(buffer));
	retvm_if(ret != AUL_R_OK, false, "Failed to get the application ID: %d", ret);

	__app_id = strdup(buffer);
	retvm_if(!__app_id, false, "Malloc failed");
	_LOGI("init : %s", __app_id);

	if (__local_port_info == NULL) {
		__local_port_info = g_hash_table_new_full(g_direct_hash,  g_direct_equal, NULL, __hash_destory_local_value);
		retvm_if(!__local_port_info, false, "fail to create __local_port_info");
	}

	if (__remote_port_info == NULL) {
		__remote_port_info = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, __hash_destory_remote_value);
		retvm_if(!__remote_port_info, false, "fail to create __remote_port_info");
	}

	if (__sender_appid_hash == NULL) {
		__sender_appid_hash = g_hash_table_new(g_str_hash, g_str_equal);
		retvm_if(!__sender_appid_hash, false, "fail to create __sender_appid_hash");
	}

	if (__trusted_app_list_hash == NULL)
		__trusted_app_list_hash = g_hash_table_new(g_str_hash, g_str_equal);

	if (__checked_app_list_hash == NULL)
		__checked_app_list_hash =
			g_hash_table_new_full(g_str_hash, g_str_equal, NULL, __hash_destory_list_value);


	if (!__dbus_init()) {
		return false;
	}
	_initialized = true;

	return true;
}


static bool __message_port_register_port(const int local_id, const char *local_port, bool is_trusted, messageport_message_cb callback)
{
	message_port_local_port_info_s *mi = (message_port_local_port_info_s *)calloc(1, sizeof(message_port_local_port_info_s));
	retvm_if(!mi, false, "Malloc failed");

	mi->callback = callback;
	mi->is_trusted = is_trusted;
	mi->port_name = strdup(local_port);
	if (mi->port_name == NULL) {
		_LOGE("Malloc failed (%s)", local_port);
		free(mi);
		return false;
	}
	mi->local_id = local_id;

	g_hash_table_insert(__local_port_info, GINT_TO_POINTER(mi->local_id), mi);
	return true;
}

static int __register_message_port(const char *local_port, bool is_trusted, messageport_message_cb callback)
{
	_SECURE_LOGI("Register a message port : [%s:%s]", __app_id, local_port);

	int local_id = 0;

	// Check the message port is already registed
	if (__is_local_port_registed(local_port, is_trusted, &local_id, NULL)) {
		return local_id;
	}

	local_id = __get_next_id();

	if (!__message_port_register_port(local_id, local_port, is_trusted, callback)) {
		return MESSAGEPORT_ERROR_OUT_OF_MEMORY;
	}

	return local_id;
}

static int __message_port_send_message(const char *remote_appid, const char *remote_port,
		const char *local_port, bool trusted_message, bool local_trusted, bool bi_dir, bundle *message)
{
	int ret = MESSAGEPORT_ERROR_NONE;
	int len = 0;
	bundle_raw *raw = NULL;
	char *bus_name = NULL;

	message_port_remote_app_info_s *remote_app_info = NULL;
	port_list_info_s *port_info = NULL;
	GDBusMessage *msg = NULL;
	GError *err = NULL;
	GVariant *body = NULL;

	ret = __get_remote_port_info(remote_appid, remote_port, trusted_message, &remote_app_info, &port_info);
	if (ret != MESSAGEPORT_ERROR_NONE) {
		return ret;
	}

	if (trusted_message) {
		if (remote_app_info->certificate_info != CERTIFICATE_MATCH) {
			if (!__is_preloaded(__app_id, remote_appid)) {
				if (__check_certificate(__app_id, remote_appid) != MESSAGEPORT_ERROR_NONE) {
					ret = MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH;
					goto out;
				}
			}
			remote_app_info->certificate_info = CERTIFICATE_MATCH;
		}
	}

	if (port_info->exist == false) {
		bool exist = false;
		_LOGI("port exist check !!");
		ret =  __check_remote_port(remote_appid, remote_port, trusted_message, &exist);
		if (ret != MESSAGEPORT_ERROR_NONE) {
			goto out;
		} else if (!exist) {
			ret = MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
			goto out;
		}
	}

	bus_name = remote_app_info->encoded_bus_name;

	if (bundle_encode(message, &raw, &len) != BUNDLE_ERROR_NONE) {
		ret = MESSAGEPORT_ERROR_INVALID_PARAMETER;
		goto out;
	}

	if (MAX_MESSAGE_SIZE < len) {
		_LOGE("The size of message (%d) has exceeded the maximum limit.", len);
		ret = MESSAGEPORT_ERROR_MAX_EXCEEDED;
	}

	body = g_variant_new("(ssbbssbus)", __app_id, (local_port) ? local_port : "", local_trusted, bi_dir,
			  remote_appid, remote_port, trusted_message, len, raw);

	msg = g_dbus_message_new_method_call(bus_name, MESSAGEPORT_OBJECT_PATH, MESSAGEPORT_INTERFACE, "send_message");
	if (!msg) {
		_LOGE("Can't allocate new method call");
		ret = MESSAGEPORT_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	g_dbus_message_set_body(msg, body);
	g_dbus_message_set_flags(msg, G_DBUS_MESSAGE_FLAGS_NO_REPLY_EXPECTED);
	g_dbus_connection_send_message(__gdbus_conn, msg, G_DBUS_SEND_MESSAGE_FLAGS_NONE, NULL, &err);
	if (err != NULL) {
		_LOGE("No reply. error = %s", err->message);
		g_error_free(err);
		ret = MESSAGEPORT_ERROR_IO_ERROR;
		goto out;
	}

	out:
	if (msg)
		g_object_unref(msg);
	if (raw)
		bundle_free_encoded_rawdata(&raw);
	return ret;
}

int __message_send_bidirectional_message(int id, const char *remote_app_id, const char *remote_port,  bool trusted_message, bundle *message)
{
	message_port_local_port_info_s *local_info;
	int ret = __get_local_port_info(id, &local_info);
	if (ret != MESSAGEPORT_ERROR_NONE) {
		return ret;
	}

	_LOGE("bidirectional_message %s", local_info->port_name);
	return __message_port_send_message(remote_app_id, remote_port,
			local_info->port_name, trusted_message, local_info->is_trusted, true, message);
}

int messageport_unregister_local_port(int local_port_id, bool trusted_port)
{

	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GError *err = NULL;
	GVariant *body;
	char *bus_name = NULL;
	GList *checked_app_list = NULL;
	GList *checked_app = NULL;

	_LOGE("unregister : %d", local_port_id);

	message_port_local_port_info_s *mi =
		(message_port_local_port_info_s *)
		g_hash_table_lookup(__local_port_info, GINT_TO_POINTER(local_port_id));
	if (mi == NULL)
		return MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;

	if (mi->is_trusted != trusted_port)
		return MESSAGEPORT_ERROR_INVALID_PARAMETER;

	checked_app_list = (GList *)g_hash_table_lookup(__checked_app_list_hash, mi->port_name);
	checked_app = NULL;
	for (checked_app = checked_app_list; checked_app != NULL;
			checked_app = checked_app->next) {

		char *checked_app_id = (char *)checked_app->data;

		_LOGI("unregister appid: %s", checked_app_id);
		bus_name = __get_bus_name(checked_app_id);
		msg = g_dbus_message_new_method_call(bus_name, MESSAGEPORT_OBJECT_PATH,
				MESSAGEPORT_INTERFACE, "unregister_port");
		if (!msg) {
			_LOGI("Can't allocate new method call");
			return MESSAGEPORT_ERROR_OUT_OF_MEMORY;
		}

		g_dbus_message_set_body(msg,
				g_variant_new("(sbs)", __app_id, mi->is_trusted, mi->port_name));
		reply = g_dbus_connection_send_message_with_reply_sync(
				__gdbus_conn,
				msg,
				G_DBUS_SEND_MESSAGE_FLAGS_NONE,
				500,
				NULL,
				NULL,
				&err);

		if (err || (reply == NULL)) {
			if (err) {
				_LOGE("No reply. error = %s", err->message);
				g_error_free(err);
			}
		} else {
			if (g_dbus_message_to_gerror(reply, &err)) {
				if (err) {
					_LOGE("error = %s", err->message);
					g_error_free(err);
				}
			} else {
				int ret_val = MESSAGEPORT_ERROR_NONE;

				body = g_dbus_message_get_body(reply);
				g_variant_get(body, "(u)", &ret_val);

				if (ret_val == MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH) {
					_SECURE_LOGI("The remote application (%s) is not signed with the same certificate"
							, checked_app_id);
				}
			}
		}
		if (msg)
			g_object_unref(msg);
		if (reply)
			g_object_unref(reply);


	}
	g_hash_table_remove(__checked_app_list_hash, mi->port_name);
	g_hash_table_remove(__local_port_info, GINT_TO_POINTER(local_port_id));

	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	return MESSAGEPORT_ERROR_NONE;
}

int messageport_register_local_port(const char *local_port, messageport_message_cb callback)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}

	return __register_message_port(local_port, false, callback);
}

int messageport_register_trusted_local_port(const char *local_port, messageport_message_cb callback)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}

	return __register_message_port(local_port, true, callback);

}

int messageport_check_remote_port(const char *remote_app_id, const char *remote_port, bool *exist)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}

	return __check_remote_port(remote_app_id, remote_port, false, exist);
}

int messageport_check_trusted_remote_port(const char *remote_app_id, const char *remote_port, bool *exist)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}

	return __check_remote_port(remote_app_id, remote_port, true, exist);
}

int messageport_send_message(const char *remote_app_id, const char *remote_port, bundle *message)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}

	return __message_port_send_message(remote_app_id, remote_port, NULL, false, false, false, message);
}

int messageport_send_trusted_message(const char *remote_app_id, const char *remote_port, bundle *message)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}

	return __message_port_send_message(remote_app_id, remote_port, NULL, true, false, false, message);
}

int messageport_send_bidirectional_message(int id, const char *remote_app_id, const char *remote_port,
		bundle *message)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}

	return __message_send_bidirectional_message(id, remote_app_id, remote_port, false, message);
}

int messageport_send_bidirectional_trusted_message(int id, const char *remote_app_id, const char *remote_port,
		bundle *message)
{
	if (!_initialized) {
		if (!__initialize())
			return MESSAGEPORT_ERROR_IO_ERROR;
	}
	return __message_send_bidirectional_message(id, remote_app_id, remote_port, true, message);
}

int messageport_get_local_port_name(int id, char **name)
{
	message_port_local_port_info_s *local_info;
	int ret = __get_local_port_info(id, &local_info);

	if (ret != MESSAGEPORT_ERROR_NONE) {
		return ret;
	}

	*name = strdup(local_info->port_name);

	if (*name == NULL) {
		return MESSAGEPORT_ERROR_OUT_OF_MEMORY;
	}

	return MESSAGEPORT_ERROR_NONE;
}

int messageport_check_trusted_local_port(int id, bool *trusted)
{
	message_port_local_port_info_s *local_info;
	int ret = __get_local_port_info(id, &local_info);

	if (ret != MESSAGEPORT_ERROR_NONE) {
		return ret;
	}

	*trusted = local_info->is_trusted;

	return MESSAGEPORT_ERROR_NONE;;
}

