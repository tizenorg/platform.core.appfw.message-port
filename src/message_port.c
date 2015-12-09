/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <glib.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <message-port.h>
#include "message_port_internal.h"
#include "message_port_log.h"
#include "message_port.h"

typedef struct message_port_callback_item_s {
	message_port_message_cb callback;
	void *user_data;
} message_port_callback_item;

static GHashTable *__listeners;
static GHashTable *__trusted_listeners;
static pthread_mutex_t __mutex = PTHREAD_MUTEX_INITIALIZER;

static void do_callback(message_port_message_cb callback, int local_port_id, const char *remote_app_id, const char *remote_port, bool trusted_remote_port, bundle *message, void *user_data)
{
	if (callback) {
		callback(local_port_id, remote_app_id, remote_port, trusted_remote_port, message, user_data);
		bundle_free(message);
	} else {
		_LOGI("Ignored");
	}
}

static void message_dispatcher(int local_port_id, const char *remote_app_id, const char *remote_port, bool trusted_remote_port, bundle *message, void *user_data)
{
	message_port_callback_item *item =
		(message_port_callback_item *)g_hash_table_lookup(__listeners, GINT_TO_POINTER(local_port_id));
	do_callback(item->callback, local_port_id, remote_app_id, remote_port, trusted_remote_port, message, item->user_data);
}

static void trusted_message_dispatcher(int trusted_local_port_id, const char *remote_app_id, const char *remote_port, bool trusted_remote_port, bundle *message, void *user_data)
{
	message_port_callback_item *item =
		(message_port_callback_item *)g_hash_table_lookup(__trusted_listeners, GINT_TO_POINTER(trusted_local_port_id));
	do_callback(item->callback, trusted_local_port_id, remote_app_id, remote_port, trusted_remote_port, message, item->user_data);
}

int message_port_register_local_port(const char *local_port, message_port_message_cb callback, void *user_data)
{
	if (local_port == NULL || callback == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	}

	int local_port_id = messageport_register_local_port(local_port, message_dispatcher);
	if (local_port_id > 0) {
		_SECURE_LOGI("Register local port ID (%d).", local_port_id);

		if (__listeners == NULL)
			__listeners = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

		pthread_mutex_lock(&__mutex);
		message_port_callback_item *item =
			(message_port_callback_item *)g_hash_table_lookup(__listeners, GINT_TO_POINTER(local_port_id));
		if (item == NULL) {
			item = (message_port_callback_item *)calloc(1, sizeof(message_port_callback_item));
			if (item == NULL)
				return MESSAGE_PORT_ERROR_OUT_OF_MEMORY;

			g_hash_table_insert(__listeners, GINT_TO_POINTER(local_port_id), item);
		}

		item->callback = callback;
		item->user_data = user_data;
		pthread_mutex_unlock(&__mutex);

	} else
		_SECURE_LOGI("Register local port fail (%d).", local_port_id);

	return convert_to_tizen_error((messageport_error_e)local_port_id);
}

int message_port_register_trusted_local_port(const char *local_port, message_port_trusted_message_cb callback, void *user_data)
{
	if (local_port == NULL || callback == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	}

	int trusted_local_port_id = messageport_register_trusted_local_port(local_port, trusted_message_dispatcher);
	if (trusted_local_port_id > 0) {
		_SECURE_LOGI("Register trusted local port ID (%d).", trusted_local_port_id);

		if (__trusted_listeners == NULL)
			__trusted_listeners = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);

		pthread_mutex_lock(&__mutex);
		message_port_callback_item *item =
			(message_port_callback_item *)g_hash_table_lookup(__trusted_listeners, GINT_TO_POINTER(trusted_local_port_id));
		if (item == NULL) {
			item = (message_port_callback_item *)calloc(1, sizeof(message_port_callback_item));
			if (item == NULL)
				return MESSAGE_PORT_ERROR_OUT_OF_MEMORY;

			g_hash_table_insert(__trusted_listeners, GINT_TO_POINTER(trusted_local_port_id), item);
		}

		item->callback = callback;
		item->user_data = user_data;
		pthread_mutex_unlock(&__mutex);
	} else
		_SECURE_LOGI("Register trusted local port fail (%d).", trusted_local_port_id);

	return convert_to_tizen_error((messageport_error_e)trusted_local_port_id);
}

int message_port_unregister_local_port(int local_port_id)
{
	int res = MESSAGE_PORT_ERROR_NONE;
	if (local_port_id <= 0) {
		_LOGE("[MESSAGEPORT_ERROR_INVALID_PARAMETER] Neither 0 nor negative value is allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	} else {
		res = messageport_unregister_local_port(local_port_id, false);
		g_hash_table_remove(__listeners, GINT_TO_POINTER(local_port_id));
	}
	return convert_to_tizen_error((messageport_error_e)res);
}

int message_port_unregister_trusted_local_port(int trusted_local_port_id)
{

	int res = MESSAGE_PORT_ERROR_NONE;
	if (trusted_local_port_id <= 0) {
		_LOGE("[MESSAGEPORT_ERROR_INVALID_PARAMETER] Neither 0 nor negative value is allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	} else {
		res = messageport_unregister_local_port(trusted_local_port_id, true);
		g_hash_table_remove(__trusted_listeners, GINT_TO_POINTER(trusted_local_port_id));
	}

	return convert_to_tizen_error((messageport_error_e)res);
}

int message_port_check_remote_port(const char* remote_app_id, const char *remote_port, bool* exist)
{
	if (remote_app_id == NULL || remote_port == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	}
	_SECURE_LOGI("Check remote port (%s):(%s).", remote_app_id, remote_port);
	return convert_to_tizen_error((messageport_error_e)messageport_check_remote_port(remote_app_id, remote_port, exist));
}

int message_port_check_trusted_remote_port(const char* remote_app_id, const char *remote_port, bool *exist)
{
	if (remote_app_id == NULL || remote_port == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	}
	_SECURE_LOGI("Check trusted remote port (%s):(%s).", remote_app_id, remote_port);
	return convert_to_tizen_error((messageport_error_e)messageport_check_trusted_remote_port(remote_app_id, remote_port, exist));
}

int message_port_send_message(const char *remote_app_id, const char *remote_port, bundle *message)
{
	if (remote_app_id == NULL || remote_port == NULL || message == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	}
	return convert_to_tizen_error((messageport_error_e)messageport_send_message(remote_app_id, remote_port, message));
}

int message_port_send_trusted_message(const char *remote_app_id, const char *remote_port, bundle *message)
{
	if (remote_app_id == NULL || remote_port == NULL || message == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	}
	return convert_to_tizen_error((messageport_error_e)messageport_send_trusted_message(remote_app_id, remote_port, message));
}

int message_port_send_message_with_local_port(const char *remote_app_id, const char *remote_port, bundle *message, int local_port_id)
{
	if (remote_app_id == NULL || remote_port == NULL || message == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	} else if (local_port_id <= 0) {
		_LOGE("[MESSAGEPORT_ERROR_INVALID_PARAMETER] Neither 0 nor negative value is allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	} else {

		message_port_callback_item *item = NULL;
		message_port_callback_item *trusted_item = NULL;

		if (__listeners != NULL)
			item = (message_port_callback_item *)g_hash_table_lookup(__listeners, GINT_TO_POINTER(local_port_id));

		if (item == NULL && __trusted_listeners != NULL)
			trusted_item = (message_port_callback_item *)g_hash_table_lookup(__trusted_listeners, GINT_TO_POINTER(local_port_id));


		if (item == NULL && trusted_item == NULL) {
			_LOGE("[MESSAGE_PORT_ERROR_PORT_NOT_FOUND] The local port ID (%d) is not registered.", local_port_id);
			return MESSAGE_PORT_ERROR_PORT_NOT_FOUND;
		}
	}

	_SECURE_LOGI("Send a message to (%s):(%s) and listen at the local port ID (%d).", remote_app_id, remote_port, local_port_id);
	return convert_to_tizen_error((messageport_error_e)messageport_send_bidirectional_message(local_port_id, remote_app_id, remote_port, message));
}

int message_port_send_trusted_message_with_local_port(const char* remote_app_id, const char *remote_port, bundle* message, int local_port_id)
{
	if (remote_app_id == NULL || remote_port == NULL || message == NULL) {
		_LOGE("[MESSAGE_PORT_ERROR_INVALID_PARAMETER] NULL value is not allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	} else if (local_port_id <= 0) {
		_LOGE("[MESSAGEPORT_ERROR_INVALID_PARAMETER] Neither 0 nor negative value is allowed.");
		return MESSAGE_PORT_ERROR_INVALID_PARAMETER;
	} else {
		message_port_callback_item *item = NULL;
		message_port_callback_item *trusted_item = NULL;

		if (__listeners != NULL)
			item = (message_port_callback_item *)g_hash_table_lookup(__listeners, GINT_TO_POINTER(local_port_id));

		if (item == NULL && __trusted_listeners != NULL)
			trusted_item = (message_port_callback_item *)g_hash_table_lookup(__trusted_listeners, GINT_TO_POINTER(local_port_id));

		if (item == NULL && trusted_item == NULL) {
			_LOGE("[MESSAGE_PORT_ERROR_PORT_NOT_FOUND] The local port ID (%d) is not registered.", local_port_id);
			return MESSAGE_PORT_ERROR_PORT_NOT_FOUND;
		}
	}

	_SECURE_LOGI("Send a trusted message to (%s):(%s) and listen at the local port ID (%d).", remote_app_id, remote_port, local_port_id);
	return convert_to_tizen_error((messageport_error_e)messageport_send_bidirectional_trusted_message(local_port_id, remote_app_id, remote_port, message));
}

