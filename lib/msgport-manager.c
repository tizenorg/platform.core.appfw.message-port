/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of message-port.
 *
 * Copyright (C) 2013 Intel Corporation.
 *
 * Contact: Amarnath Valluri <amarnath.valluri@linux.intel.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include "config.h" /* MESSAGEPORT_BUS_ADDRESS */

#include "msgport-manager.h"
#include "msgport-service.h"
#include "msgport-utils.h" /* msgport_daemon_error_to_error */
#include "message-port.h" /* messageport_error_e */
#include "common/dbus-manager-glue.h"
#ifdef  USE_SESSION_BUS
#include "common/dbus-server-glue.h"
#endif
#include "common/log.h"
#include <gio/gio.h>

struct _MsgPortManager
{
    GObject parent;

    MsgPortDbusGlueManager *proxy;
    GHashTable *services; /* {gchar*:MsgPortService*} */
    GHashTable *local_services; /* {gint: gchar *} */ 
    GHashTable *remote_services; /* {gint: gchar *} */
};

G_DEFINE_TYPE (MsgPortManager, msgport_manager, G_TYPE_OBJECT)

static void
_unregister_service_cb (int service_id, const gchar *object_path, MsgPortManager *manager)
{
    MsgPortService *service = g_hash_table_lookup (manager->services, object_path);

    if (service) msgport_service_unregister (service);
}

static void
_finalize (GObject *self)
{
    MsgPortManager *manager = MSGPORT_MANAGER (self);

    if (manager->local_services) {
        g_hash_table_unref (manager->local_services);
        manager->local_services = NULL;
    }

    if (manager->remote_services) {
        g_hash_table_unref (manager->remote_services);
        manager->remote_services = NULL;
    }

    G_OBJECT_CLASS (msgport_manager_parent_class)->finalize (self);
}

static void
_dispose (GObject *self)
{
    MsgPortManager *manager = MSGPORT_MANAGER (self);

    g_hash_table_foreach (manager->local_services, (GHFunc)_unregister_service_cb, manager);

    if (manager->services) {
        g_hash_table_unref (manager->services);
        manager->services = NULL;
    }

    g_clear_object (&manager->proxy);

    G_OBJECT_CLASS (msgport_manager_parent_class)->dispose (self);
}

static void
msgport_manager_class_init (MsgPortManagerClass *klass)
{
    GObjectClass *g_klass = G_OBJECT_CLASS (klass);

    g_klass->finalize = _finalize;
    g_klass->dispose = _dispose;
}

static void
msgport_manager_init (MsgPortManager *manager)
{
    GError          *error = NULL;
    GDBusConnection *connection = NULL;
    gchar           *bus_address = NULL;

    manager->services = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
    manager->local_services = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, NULL);
    manager->remote_services = g_hash_table_new_full (g_direct_hash, g_direct_equal, NULL, NULL);

#ifdef USE_SESSION_BUS
    MsgPortDbusGlueServer *server = NULL;
    server = msgport_dbus_glue_server_proxy_new_for_bus_sync (G_BUS_TYPE_SESSION,
            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
            "org.tizen.messageport", "/", NULL, &error);

    if (error) {
        WARN ("fail to get server proxy : %s",  error->message);
        g_error_free (error);
    }
    else {
        msgport_dbus_glue_server_call_get_bus_address_sync (server, &bus_address, NULL, &error);
        if (error) {
            WARN ("Fail to get server bus address : %s", error->message);
            g_error_free (error);
        }
    }

    g_object_unref (server);
#endif
    if (!bus_address) {
        if (g_getenv("MESSAGEPORT_BUS_ADDRESS")) {
            bus_address = g_strdup (g_getenv ("MESSAGEPORT_BUS_ADDRESS"));
        }
        else {
#       ifdef MESSAGEPORT_BUS_ADDRESS
            bus_address = g_strdup_printf (MESSAGEPORT_BUS_ADDRESS);
#       endif
        }
    }
    if (!bus_address)
        bus_address = g_strdup_printf ("unix:path=%s/.message-port", g_get_user_runtime_dir());

    connection = g_dbus_connection_new_for_address_sync (bus_address,
            G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT, NULL, NULL, &error);
    if (error) {
        WARN ("Fail to connect messageport server at address %s: %s", bus_address, error->message);
        g_error_free (error);
    }
    else {
        manager->proxy = msgport_dbus_glue_manager_proxy_new_sync (
            connection, G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES, NULL, "/", NULL, &error);
        if (error) {
            WARN ("Fail to get manager proxy : %s", error->message);
            g_error_free (error);
        }
    }

    g_free (bus_address);
}

MsgPortManager * msgport_manager_new ()
{
    return g_object_new (MSGPORT_TYPE_MANAGER, NULL);
}

static messageport_error_e
_create_and_cache_service (MsgPortManager *manager, gchar *object_path, messageport_message_cb cb, int *service_id)
{
    int id;
    MsgPortService *service = msgport_service_new (
            g_dbus_proxy_get_connection (G_DBUS_PROXY(manager->proxy)),
            object_path, cb);
    if (!service) {
        g_free (object_path);
        return MESSAGEPORT_ERROR_OUT_OF_MEMORY;
    }

    id = msgport_service_id (service);

    g_hash_table_insert (manager->services, object_path, service);
    g_hash_table_insert (manager->local_services, GINT_TO_POINTER (id), object_path);

    if (service_id) *service_id = id;

    return MESSAGEPORT_ERROR_NONE;
}

typedef struct {
    const gchar *name;
    gboolean is_trusted;
} FindServiceData ;

static gboolean
_find_service (gpointer key, gpointer value, gpointer data)
{
    FindServiceData *service_data = (FindServiceData*)data;
    MsgPortService *service = (MsgPortService *)value;

    return g_strcmp0 (msgport_service_name (service), service_data->name) == 0
           && msgport_service_is_trusted (service) == service_data->is_trusted;
}
    

messageport_error_e
msgport_manager_register_service (MsgPortManager *manager, const gchar *port_name, gboolean is_trusted, messageport_message_cb message_cb, int *service_id)
{
    GError *error = NULL;
    gchar *object_path = NULL;
    FindServiceData service_data;
    MsgPortService *service = NULL;

    g_return_val_if_fail (manager && MSGPORT_IS_MANAGER (manager), MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (manager->proxy, MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (service_id && port_name && message_cb, MESSAGEPORT_ERROR_INVALID_PARAMETER);

    /* first check in cached services if found any */
    service_data.name = port_name;
    service_data.is_trusted = is_trusted;
    service = g_hash_table_find (manager->services, _find_service, &service_data);

    if (service) {
        int id = msgport_service_id (service);
        DBG ("Cached local port found for name '%s:%d' with ID : %d", port_name, is_trusted, id);

        /* update message handler */
        msgport_service_set_message_handler (service, message_cb);
        *service_id = id;

        return MESSAGEPORT_ERROR_NONE;
    }

    msgport_dbus_glue_manager_call_register_service_sync (manager->proxy,
            port_name, is_trusted, &object_path, NULL, &error);

    if (error) {
        messageport_error_e err = msgport_daemon_error_to_error (error);
        WARN ("unable to register service (%s): %s", port_name, error->message);
        g_error_free (error);
        return err; 
    }

    return _create_and_cache_service (manager, object_path, message_cb, service_id);
}

static MsgPortService *
_get_local_port (MsgPortManager *manager, int service_id)
{
    const gchar *object_path = NULL;
    MsgPortService *service = NULL;

    object_path = g_hash_table_lookup (manager->local_services, GINT_TO_POINTER(service_id));
    if (!object_path) return NULL;

    service = MSGPORT_SERVICE (g_hash_table_lookup (manager->services, object_path));
    if (!service) {
        g_hash_table_remove (manager->local_services, GINT_TO_POINTER (service_id));
        return NULL;
    }

    return service;
}

messageport_error_e
msgport_manager_unregister_servcie (MsgPortManager *manager, int service_id)
{
    const gchar *object_path = NULL;
    MsgPortService *service = NULL;
    g_return_val_if_fail (manager && MSGPORT_IS_MANAGER (manager), FALSE);
    g_return_val_if_fail (manager->proxy, MESSAGEPORT_ERROR_IO_ERROR);

    service = _get_local_port (manager, service_id);
    if (!service) {
        WARN ("No local service found for service id '%d'", service_id);
        return MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
    }

    if (!msgport_service_unregister (service)) 
        return MESSAGEPORT_ERROR_IO_ERROR;

    object_path = (const gchar *)g_hash_table_lookup (manager->local_services,
                                                      GINT_TO_POINTER(service_id));
    g_hash_table_remove (manager->local_services, GINT_TO_POINTER(service_id));
    g_hash_table_remove (manager->services, object_path);

    return MESSAGEPORT_ERROR_NONE;
}

messageport_error_e 
msgport_manager_check_remote_service (MsgPortManager *manager, const gchar *app_id, const gchar *port, gboolean is_trusted, guint *service_id_out)
{
    GError *error = NULL;
    guint remote_service_id = 0;

    if (service_id_out) *service_id_out = 0;

    g_return_val_if_fail (manager && MSGPORT_IS_MANAGER (manager), MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (manager->proxy, MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (app_id && port, MESSAGEPORT_ERROR_INVALID_PARAMETER);

    if (!app_id || !port) return MESSAGEPORT_ERROR_INVALID_PARAMETER;

    msgport_dbus_glue_manager_call_check_for_remote_service_sync (manager->proxy,
            app_id, port, is_trusted, &remote_service_id, NULL, &error);

    if (error) {
        messageport_error_e err = msgport_daemon_error_to_error (error);
        WARN ("No %sservice found for app_id %s, port name %s: %s", 
                is_trusted ? "trusted " : "", app_id, port, error->message);
        g_error_free (error);
        return err;
    }
    else {
        DBG ("Got service id %d for %s, %s", remote_service_id, app_id, port);
        if (service_id_out)  *service_id_out = remote_service_id;
    }

    return MESSAGEPORT_ERROR_NONE;
}

messageport_error_e
msgport_manager_get_service_name (MsgPortManager *manager, int service_id, gchar **name_out)
{
    MsgPortService *service = NULL;
    g_return_val_if_fail (manager && MSGPORT_IS_MANAGER (manager), MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (manager->proxy, MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (name_out && service_id, MESSAGEPORT_ERROR_INVALID_PARAMETER);

    service = _get_local_port (manager, service_id);
    if (!service) return MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;

    *name_out = g_strdup (msgport_service_name (service));

    return MESSAGEPORT_ERROR_NONE;
}

messageport_error_e
msgport_manager_get_service_is_trusted (MsgPortManager *manager, int service_id, gboolean *is_trusted_out)
{
    MsgPortService *service = NULL;
    g_return_val_if_fail (manager && MSGPORT_IS_MANAGER (manager), MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (manager->proxy, MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (service_id && is_trusted_out, MESSAGEPORT_ERROR_INVALID_PARAMETER);

    service = _get_local_port (manager, service_id);
    if (!service) return MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;

    *is_trusted_out = msgport_service_is_trusted (service);

    return MESSAGEPORT_ERROR_NONE;
}

messageport_error_e
msgport_manager_send_message (MsgPortManager *manager, const gchar *remote_app_id, const gchar *remote_port, gboolean is_trusted, GVariant *data)
{
    guint service_id = 0;
    GError *error = NULL;
    messageport_error_e err;

    g_return_val_if_fail (manager && MSGPORT_IS_MANAGER (manager), MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (manager->proxy, MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (remote_app_id && remote_port, MESSAGEPORT_ERROR_INVALID_PARAMETER);

    err = msgport_manager_check_remote_service (manager, remote_app_id, remote_port, is_trusted, &service_id);
    if (service_id == 0) return err;

    msgport_dbus_glue_manager_call_send_message_sync (manager->proxy, service_id, data, NULL, &error);

    if (error) {
        err = msgport_daemon_error_to_error (error);
        WARN ("Failed to send message to (%s:%s) : %s", remote_app_id, remote_port, error->message);
        g_error_free (error);
        return err;
    }

    return MESSAGEPORT_ERROR_NONE;
}

messageport_error_e
msgport_manager_send_bidirectional_message (MsgPortManager *manager, int local_port_id, const gchar *remote_app_id, const gchar *remote_port, gboolean is_trusted, GVariant *data)
{
    MsgPortService *service = NULL;
    guint remote_service_id = 0;
    messageport_error_e res = 0;

    g_return_val_if_fail (manager && MSGPORT_IS_MANAGER (manager), MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (manager->proxy, MESSAGEPORT_ERROR_IO_ERROR);
    g_return_val_if_fail (local_port_id > 0 && remote_app_id && remote_port, MESSAGEPORT_ERROR_INVALID_PARAMETER);

    service = _get_local_port (manager, local_port_id);
    if (!service) {
        WARN ("No local service found for service id '%d'", local_port_id);
        return MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
    }

    if ((res = msgport_manager_check_remote_service (manager, remote_app_id, remote_port, is_trusted, &remote_service_id) != MESSAGEPORT_ERROR_NONE)) {
        WARN ("No remote %sport informatuon for %s:%s, error : %d", is_trusted ? "trusted " : "", remote_app_id, remote_port, res);
        return MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
    }

    DBG ("Sending message from local service '%p' to remote sercie id '%d'", service, remote_service_id);
    return msgport_service_send_message (service, remote_service_id, data);
}

