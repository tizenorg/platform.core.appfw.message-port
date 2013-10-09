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

#include "config.h"

#include <glib.h>
#include <glib-unix.h>
#include "common/log.h"
#ifdef USE_SESSION_BUS
#include "common/dbus-error.h"
#include "common/dbus-server-glue.h"
#include "utils.h"
#endif
#include "dbus-server.h"

typedef struct {
    GMainLoop             *m_loop;
    MsgPortDbusServer     *server;
#ifdef USE_SESSION_BUS
    MsgPortDbusGlueServer *dbus_skeleten;
#endif
} DaemonData;

static DaemonData *
daemon_data_new ()
{
    return g_slice_new0 (DaemonData);
}

static void
daemon_data_free (DaemonData *data)
{
    if (!data) return;
    if (data->server) g_clear_object (&data->server);
#ifdef USE_SESSION_BUS
    if (data->dbus_skeleten) {
        g_dbus_interface_skeleton_unexport (
              G_DBUS_INTERFACE_SKELETON (data->dbus_skeleten));
        g_clear_object (&data->dbus_skeleten);
    }
#endif
    if (data->m_loop) g_main_loop_unref (data->m_loop);

    g_slice_free (DaemonData, data);
}

#ifdef USE_SESSION_BUS
static gboolean
_handle_get_bus_address (DaemonData *data,
                         GDBusMethodInvocation *invocation,
                         gpointer               userdata)
{

    msgport_return_val_if_fail (data, FALSE);
    msgport_return_val_if_fail (data->server && MSGPORT_IS_DBUS_SERVER (data->server), FALSE);

    const gchar *server_address = msgport_dbus_server_get_address (data->server);

    if (server_address) {
        msgport_dbus_glue_server_complete_get_bus_address (data->dbus_skeleten,
                invocation, server_address);
    }
    else {
        g_dbus_method_invocation_take_error (invocation, msgport_error_unknown_new());
    }

    return TRUE;
}

static void
_on_bus_acquired (GDBusConnection *connection,
                 const gchar     *name,
                 gpointer         userdata)
{
    DaemonData *data = (DaemonData *) userdata;

    msgport_return_if_fail (data);
    GError *error = NULL;

    data->server = msgport_dbus_server_new ();
 
    data->dbus_skeleten = msgport_dbus_glue_server_skeleton_new ();

    g_signal_connect_swapped (data->dbus_skeleten, "handle-get-bus-address",
               G_CALLBACK (_handle_get_bus_address), data);

    if (!g_dbus_interface_skeleton_export (
            G_DBUS_INTERFACE_SKELETON (data->dbus_skeleten), connection, "/", &error)) {
        WARN ("Failed to export interface: %s", error->message);
        g_error_free (error);
        g_main_loop_quit (data->m_loop);
    }
}

static void
_on_name_acquired (GDBusConnection *connection,
                  const gchar     *name,
                  gpointer         userdata)
{
    DBG ("D-Bus name acquired: %s", name);
}

static void
_on_name_lost (GDBusConnection *connection,
              const gchar     *name,
              gpointer         userdata)
{
    DaemonData *data = (DaemonData *) userdata;
    DBG ("D-Bus name lost: %s", name);
    msgport_return_if_fail (data && data->m_loop);

    g_main_loop_quit (data->m_loop);
}
#endif /* USE_SESSION_BUS */

static gboolean
_on_unix_signal (gpointer data)
{
    g_main_loop_quit (((DaemonData *)data)->m_loop);

    return FALSE;
}

int main (int argc, char *argv[])
{
    DaemonData *data = daemon_data_new ();

#if !GLIB_CHECK_VERSION (2, 36, 0)
    g_type_init (&argc, &argv);
#endif

#if USE_SESSION_BUS
    guint bus_owner_id = g_bus_own_name (G_BUS_TYPE_SESSION,
            "org.tizen.messageport",
            G_BUS_NAME_OWNER_FLAGS_ALLOW_REPLACEMENT | G_BUS_NAME_OWNER_FLAGS_REPLACE,
            _on_bus_acquired,
            _on_name_acquired,
            _on_name_lost,
            data,
            NULL);
#else
    data->server = msgport_dbus_server_new();
    if (!data->server) {
        ERR ("Failed to start server");
        daemon_data_free (data);
        return (-1);
    }
#endif /* USE_SESSION_BUS */

    data->m_loop = g_main_loop_new (NULL, FALSE);
    g_unix_signal_add (SIGTERM, _on_unix_signal, data);
    g_unix_signal_add (SIGINT, _on_unix_signal, data);

    g_main_loop_run (data->m_loop);

    daemon_data_free (data);
#ifdef USE_SESSION_BUS
    g_bus_unown_name (bus_owner_id);
#endif

    DBG("Clean shutdown");

    return 0;
}

