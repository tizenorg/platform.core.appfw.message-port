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

#include <errno.h>
#include <string.h>
#include <gio/gio.h>
#include <glib/gstdio.h>

#include "config.h"
#include "common/log.h"
#include "dbus-server.h"
#include "dbus-manager.h"
#include "utils.h"


G_DEFINE_TYPE (MsgPortDbusServer, msgport_dbus_server, G_TYPE_OBJECT)


#define MSGPORT_DBUS_SERVER_GET_PRIV(obj) \
    G_TYPE_INSTANCE_GET_PRIVATE ((obj), MSGPORT_TYPE_DBUS_SERVER, MsgPortDbusServerPrivate)

enum
{
    PROP_0,

    PROP_ADDRESS,
    N_PROPERTIES
};

static GParamSpec *properties[N_PROPERTIES];

struct _MsgPortDbusServerPrivate
{
    GDBusServer    *bus_server;
    gchar          *address;
    GHashTable     *dbus_managers; /* {GDBusConnection,MsgPortDbusManager} */
};

static void _on_connection_closed (GDBusConnection *connection,
                       gboolean         remote_peer_vanished,
                       GError          *error,
                       gpointer         user_data);

static void
_set_property (GObject *object,
        guint property_id,
        const GValue *value, GParamSpec *pspec)
{
    MsgPortDbusServer *self = MSGPORT_DBUS_SERVER (object);

    switch (property_id) {
        case PROP_ADDRESS: {
            self->priv->address = g_value_dup_string (value);
            break;
        }
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
_get_property (GObject *object,
        guint property_id,
        GValue *value, 
        GParamSpec *pspec)
{
    MsgPortDbusServer *self = MSGPORT_DBUS_SERVER (object);

    switch (property_id) {
        case PROP_ADDRESS: {
            g_value_set_string (value, g_dbus_server_get_client_address (
                    self->priv->bus_server));
            break;
        }
        default:
            G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
    }
}

static void
_clear_watchers(gpointer connection, gpointer auth_service, gpointer userdata)
{
    g_signal_handlers_disconnect_by_func (connection, _on_connection_closed, userdata);
}

static void
_dispose (GObject *object)
{
    MsgPortDbusServer *self = MSGPORT_DBUS_SERVER (object);

    if (self->priv->bus_server) {
        if (g_dbus_server_is_active (self->priv->bus_server))
            g_dbus_server_stop (self->priv->bus_server);
        g_clear_object (&self->priv->bus_server);
    }

    if (self->priv->dbus_managers) {
        g_hash_table_foreach (self->priv->dbus_managers, _clear_watchers, self);
        g_hash_table_unref (self->priv->dbus_managers);
        self->priv->dbus_managers = NULL;
    }

    G_OBJECT_CLASS (msgport_dbus_server_parent_class)->dispose (object);
}

static void
_finalize (GObject *object)
{
    MsgPortDbusServer *self = MSGPORT_DBUS_SERVER (object);
    if (self->priv->address)  {
        g_unlink (self->priv->address);
        g_free (self->priv->address);
        self->priv->address = NULL;
    }

    G_OBJECT_CLASS (msgport_dbus_server_parent_class)->finalize (object);
}

static void
msgport_dbus_server_class_init (MsgPortDbusServerClass *klass)
{
    GObjectClass* object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (MsgPortDbusServerPrivate));

    object_class->get_property = _get_property;
    object_class->set_property = _set_property;
    object_class->dispose = _dispose;
    object_class->finalize = _finalize;

    properties[PROP_ADDRESS] = g_param_spec_string ("address",
                                                    "server address",
                                                    "Server socket address",
                                                    NULL,
                                                    G_PARAM_READWRITE | 
                                                    G_PARAM_CONSTRUCT_ONLY | 
                                                    G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties (object_class, N_PROPERTIES, properties);
}

static void
msgport_dbus_server_init (MsgPortDbusServer *self)
{
    self->priv = MSGPORT_DBUS_SERVER_GET_PRIV(self);
    self->priv->bus_server = NULL;
    self->priv->address = NULL;

    self->priv->dbus_managers = g_hash_table_new_full (
        g_direct_hash, g_direct_equal, NULL, g_object_unref);
}

const gchar *
msgport_dbus_server_get_address (MsgPortDbusServer *server)
{
    g_return_val_if_fail (server || MSGPORT_IS_DBUS_SERVER (server), NULL);

    return g_dbus_server_get_client_address (server->priv->bus_server);
}

static void
_on_connection_closed (GDBusConnection *connection,
                       gboolean         remote_peer_vanished,
                       GError          *error,
                       gpointer         user_data)
{
    MsgPortDbusServer *server = MSGPORT_DBUS_SERVER (user_data);

    g_signal_handlers_disconnect_by_func (connection, _on_connection_closed, user_data);
    DBG("dbus connection(%p) closed (peer vanished : %d) : %s",
            connection, remote_peer_vanished, error ? error->message : "unknwon reason");

    g_hash_table_remove (server->priv->dbus_managers, connection);
}

void
msgport_dbus_server_start_dbus_manager_for_connection (
    MsgPortDbusServer *server,
    GDBusConnection *connection)
{
    MsgPortDbusManager *dbus_manager = NULL;
    GError *error = NULL;

    DBG("Starting dbus manager on connection %p", connection);

    dbus_manager = msgport_dbus_manager_new (
        connection, server, &error);
    if (!dbus_manager) {
        WARN ("Could not create dbus manager on conneciton %p: %s", connection, error->message);
        g_error_free (error);
        return;
    }

    g_hash_table_insert (server->priv->dbus_managers, connection, dbus_manager);

    g_signal_connect (connection, "closed", G_CALLBACK(_on_connection_closed), server);
}

static gboolean
_on_client_request (GDBusServer *dbus_server, GDBusConnection *connection, gpointer userdata)
{
    MsgPortDbusServer *server = MSGPORT_DBUS_SERVER(userdata);
    
    g_return_val_if_fail (server && MSGPORT_IS_DBUS_SERVER (server), FALSE);

    msgport_dbus_server_start_dbus_manager_for_connection (server, connection);

    return TRUE;
}

static gboolean
_start_bus_server (MsgPortDbusServer *server)
{
    GError *err = NULL;
    gchar *guid = 0;
	gchar *address = NULL;
    const gchar *file_path = NULL;

    if (!server) return FALSE;

    if (g_getenv("MESSAGEPORT_BUS_ADDRESS")) {
        address = g_strdup (g_getenv ("MESSAGEPORT_BUS_ADDRESS"));
    }
    else {
#       ifdef MESSAGEPORT_BUS_ADDRESS
           address = g_strdup_printf (MESSAGEPORT_BUS_ADDRESS);
#       endif
    }
    if (!address)
        address = g_strdup_printf ("unix:path=%s/.message-port", g_get_user_runtime_dir());

    if (g_str_has_prefix(address, "unix:path=")) {
        file_path = g_strstr_len (address, -1, "unix:path=") + 10;

        if (g_file_test(file_path, G_FILE_TEST_EXISTS)) {
            g_unlink (file_path);
        }
        else {
            gchar *base_path = g_path_get_dirname (file_path);
            if (g_mkdir_with_parents (base_path, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
                WARN ("Could not create '%s', error: %s", base_path, strerror(errno));
            }
            g_free (base_path);
        }
    }

    guid = g_dbus_generate_guid ();

    server->priv->bus_server = g_dbus_server_new_sync (address,
            G_DBUS_SERVER_FLAGS_NONE, guid, NULL, NULL, &err);

    g_free (guid);

    if (!server->priv->bus_server) {
        ERR ("failed to start server at address '%s':%s", server->priv->address,
                 err->message);
        g_error_free (err);
 
        return FALSE;
    }

    DBG ("Dbus Server started at '%s'", address);

    server->priv->address = g_strdup (file_path);

    g_signal_connect (server->priv->bus_server, "new-connection", G_CALLBACK(_on_client_request), server);

    g_dbus_server_start (server->priv->bus_server);

    if (file_path)
        g_chmod (file_path, S_IRUSR | S_IWUSR);

    g_free (address);

    return TRUE;
}

MsgPortDbusServer *
msgport_dbus_server_new () {
    MsgPortDbusServer *server = NULL;
    
    server = MSGPORT_DBUS_SERVER (g_object_new (MSGPORT_TYPE_DBUS_SERVER, NULL));

   _start_bus_server (server);

    return server;
}

static gboolean
_find_dbus_manager_by_app_id (
    GDBusConnection *key,
    MsgPortDbusManager *value,
    const gchar *app_id_to_find)
{
    return !g_strcmp0 (msgport_dbus_manager_get_app_id (value), app_id_to_find);
}

MsgPortDbusManager *
msgport_dbus_server_get_dbus_manager_by_app_id (MsgPortDbusServer *server, const gchar *app_id)
{
    g_return_val_if_fail (server && MSGPORT_IS_DBUS_SERVER (server), NULL);

    return (MsgPortDbusManager *)g_hash_table_find (server->priv->dbus_managers,
            (GHRFunc)_find_dbus_manager_by_app_id, (gpointer)app_id);
}
