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

#include "dbus-service.h"
#include "common/dbus-service-glue.h"
#include "common/dbus-error.h"
#include "common/log.h"
#include "manager.h"
#include "utils.h"

G_DEFINE_TYPE (MsgPortDbusService, msgport_dbus_service, G_TYPE_OBJECT)

#define MSGPORT_DBUS_SERVICE_GET_PRIV(obj) \
    G_TYPE_INSTANCE_GET_PRIVATE ((obj), MSGPORT_TYPE_DBUS_SERVICE, MsgPortDbusServicePrivate)

struct _MsgPortDbusServicePrivate {
    guint                   id;
    MsgPortDbusGlueService *dbus_skeleton;
    MsgPortDbusManager     *owner;
    gchar                  *port_name;
    gboolean                is_trusted;
};


static void
_dbus_service_finalize (GObject *self)
{
    MsgPortDbusService *dbus_service = MSGPORT_DBUS_SERVICE (self);

    if (dbus_service->priv->port_name) {
        g_free (dbus_service->priv->port_name);
        dbus_service->priv->port_name = NULL;
    }

    G_OBJECT_CLASS (msgport_dbus_service_parent_class)->finalize (self);
}

static void
_dbus_service_dispose (GObject *self)
{
    MsgPortDbusService *dbus_service = MSGPORT_DBUS_SERVICE (self);
    DBG ("Unregistering service '%s'", dbus_service->priv->port_name);
    if (dbus_service->priv->dbus_skeleton) {
        g_dbus_interface_skeleton_unexport (
                G_DBUS_INTERFACE_SKELETON (dbus_service->priv->dbus_skeleton));
        g_clear_object (&dbus_service->priv->dbus_skeleton);
    }

    G_OBJECT_CLASS (msgport_dbus_service_parent_class)->dispose (self);
}


static gboolean
_dbus_service_handle_send_message (
    MsgPortDbusService    *dbus_service,
    GDBusMethodInvocation *invocation,
    guint                   remote_service_id,
    GVariant              *data,
    gpointer               userdata)
{
    MsgPortDbusService *peer_dbus_service = NULL;
    MsgPortManager *manager = NULL;
    GError *error = NULL;

    msgport_return_val_if_fail (dbus_service &&  MSGPORT_IS_DBUS_SERVICE (dbus_service), FALSE);

    DBG ("Send Message rquest on service %p to remote service id : %d", dbus_service, remote_service_id);
    manager = msgport_dbus_manager_get_manager (dbus_service->priv->owner);
    peer_dbus_service = msgport_manager_get_service_by_id (manager, remote_service_id, &error);

    if (peer_dbus_service) {
        if (msgport_dbus_service_send_message (peer_dbus_service, data,
                msgport_dbus_service_get_app_id (dbus_service),
                dbus_service->priv->port_name,
                dbus_service->priv->is_trusted, &error)) {
            msgport_dbus_glue_service_complete_send_message (
                    dbus_service->priv->dbus_skeleton, invocation);

            return TRUE;
        }
    }
    
    if (!error) error = msgport_error_unknown_new ();
    g_dbus_method_invocation_take_error (invocation, error);

    return TRUE;
}

static gboolean
_dbus_service_handle_unregister (
    MsgPortDbusService    *dbus_service,
    GDBusMethodInvocation *invocation,
    gpointer               userdata)
{
    msgport_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), FALSE);

    /* FIXME unregister */
    return TRUE;
}

static void
msgport_dbus_service_init (MsgPortDbusService *self)
{
    MsgPortDbusServicePrivate *priv = MSGPORT_DBUS_SERVICE_GET_PRIV (self);

    priv->dbus_skeleton = msgport_dbus_glue_service_skeleton_new ();
    priv->owner = NULL;
    priv->id = 0;
    priv->port_name = NULL;

    g_signal_connect_swapped (priv->dbus_skeleton, "handle-send-message",
                G_CALLBACK (_dbus_service_handle_send_message), (gpointer)self);
    g_signal_connect_swapped (priv->dbus_skeleton, "handle-unregister",
                G_CALLBACK (_dbus_service_handle_unregister), (gpointer)self);

    self->priv = priv;
}

static void
msgport_dbus_service_class_init (MsgPortDbusServiceClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    g_type_class_add_private (klass, sizeof(MsgPortDbusServicePrivate));

    gklass->finalize = _dbus_service_finalize;
    gklass->dispose = _dbus_service_dispose;
}

MsgPortDbusService *
msgport_dbus_service_new (MsgPortDbusManager *owner, const gchar *name, gboolean is_trusted, GError **error)
{
    static guint object_conter = 0;

    MsgPortDbusService *dbus_service = NULL;
    GDBusConnection *connection = NULL;
    gchar *object_path = 0;

    msgport_return_val_if_fail_with_error (owner && MSGPORT_IS_DBUS_MANAGER (owner), NULL, error);
    msgport_return_val_if_fail_with_error (name && name[0], NULL, error);

    connection = msgport_dbus_manager_get_connection (owner),
    dbus_service = MSGPORT_DBUS_SERVICE (g_object_new (MSGPORT_TYPE_DBUS_SERVICE, NULL));
    if (!dbus_service) {
        if (error) *error = msgport_error_no_memory_new ();
        return NULL;
    }
    dbus_service->priv->owner = owner;
    dbus_service->priv->id = object_conter + 1;
    dbus_service->priv->port_name = g_strdup (name);
    dbus_service->priv->is_trusted = is_trusted;

    /* FIXME: better way of path creation */
    object_path = g_strdup_printf ("/%u", dbus_service->priv->id); 
    if (!g_dbus_interface_skeleton_export (
            G_DBUS_INTERFACE_SKELETON (dbus_service->priv->dbus_skeleton),
            connection,
            object_path,
            error)) {
        g_print ("Failed to export dbus object on connection %p : %s",
                    connection, error ? (*error)->message : "");
        g_object_unref (dbus_service);
        g_free (object_path);
        object_conter--;

        return NULL;
    }
    g_free (object_path);

    /* set dbus-properties */
    g_object_set (G_OBJECT (dbus_service->priv->dbus_skeleton), 
                            "id", dbus_service->priv->id,
                            "port-name", dbus_service->priv->port_name,
                            "is-trusted", dbus_service->priv->is_trusted, NULL);

    ++object_conter;
    
    return dbus_service;
}

guint
msgport_dbus_service_get_id (MsgPortDbusService *dbus_service)
{
    g_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), 0);

    return dbus_service->priv->id;
}

const gchar *
msgport_dbus_service_get_object_path (MsgPortDbusService *dbus_service)
{
    g_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), NULL);

    return g_dbus_interface_skeleton_get_object_path (
        G_DBUS_INTERFACE_SKELETON (dbus_service->priv->dbus_skeleton)) ;
}

GDBusConnection *
msgport_dbus_service_get_connection (MsgPortDbusService *dbus_service)
{
    g_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), NULL);

    return msgport_dbus_manager_get_connection (dbus_service->priv->owner);
}

MsgPortDbusManager *
msgport_dbus_service_get_owner (MsgPortDbusService *dbus_service)
{
    g_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), NULL);

    return dbus_service->priv->owner;
}

const gchar *
msgport_dbus_service_get_port_name (MsgPortDbusService *dbus_service)
{
    g_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), NULL);

    return (const gchar *)dbus_service->priv->port_name;
}

const gchar *
msgport_dbus_service_get_app_id (MsgPortDbusService *dbus_service)
{
    g_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), NULL);

    return msgport_dbus_manager_get_app_id (dbus_service->priv->owner);
}

gboolean
msgport_dbus_service_get_is_trusted (MsgPortDbusService *dbus_service)
{
    g_return_val_if_fail (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), FALSE);

    return dbus_service->priv->is_trusted;
}

gboolean
msgport_dbus_service_send_message (
    MsgPortDbusService *dbus_service,
    GVariant *data,
    const gchar *r_app_id,
    const gchar *r_port,
    gboolean r_is_trusted,
    GError **error)
{
    msgport_return_val_if_fail_with_error (dbus_service && MSGPORT_IS_DBUS_SERVICE (dbus_service), FALSE, error);

    if (dbus_service->priv->is_trusted &&
        !msgport_dbus_manager_validate_peer_certificate (dbus_service->priv->owner, r_app_id)) {
        if (error) *error = msgport_error_certificate_mismatch_new ();
        return FALSE;
    }

    DBG ("Sending message to %p from ('%s':'%s':%d)", dbus_service, r_app_id, r_port, r_is_trusted);
    msgport_dbus_glue_service_emit_on_message (dbus_service->priv->dbus_skeleton, data, r_app_id, r_port, r_is_trusted);
 
    return TRUE;
}

