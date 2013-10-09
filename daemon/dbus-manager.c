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

#include "dbus-manager.h"
#include "common/dbus-manager-glue.h"
#include "common/dbus-service-glue.h"
#include "common/dbus-error.h"
#include "common/log.h"
#include "dbus-service.h"
#include "dbus-server.h"
#include "manager.h"
#include "utils.h"

#include <aul/aul.h>
#include <pkgmgr-info.h>

G_DEFINE_TYPE (MsgPortDbusManager, msgport_dbus_manager, G_TYPE_OBJECT)

#define MSGPORT_DBUS_MANAGER_GET_PRIV(obj) \
    G_TYPE_INSTANCE_GET_PRIVATE ((obj), MSGPORT_TYPE_DBUS_MANAGER, MsgPortDbusManagerPrivate)

struct _MsgPortDbusManagerPrivate {
    MsgPortDbusGlueManager *dbus_skeleton;
    GDBusConnection        *connection;
    MsgPortManager         *manager;
    MsgPortDbusServer      *server;
    gchar                  *app_id;
    gboolean                is_null_cert;
    GHashTable             *peer_certs;
};


static void
_dbus_manager_finalize (GObject *self)
{
    //MsgPortDbusManager *manager = MSGPORT_DBUS_MANAGER (self);

    G_OBJECT_CLASS (msgport_dbus_manager_parent_class)->finalize (self);
}

static void
_dbus_manager_dispose (GObject *self)
{
    MsgPortDbusManager *dbus_mgr = MSGPORT_DBUS_MANAGER (self);

    DBG ("Unexporting dbus manager %p on connection %p", dbus_mgr, dbus_mgr->priv->connection);
    if (dbus_mgr->priv->dbus_skeleton) {
        g_dbus_interface_skeleton_unexport (
                G_DBUS_INTERFACE_SKELETON (dbus_mgr->priv->dbus_skeleton));
        g_clear_object (&dbus_mgr->priv->dbus_skeleton);
    }

    g_clear_object (&dbus_mgr->priv->connection);

    /* unregister all services owned by this connection */
    msgport_manager_unregister_services (dbus_mgr->priv->manager, dbus_mgr, NULL);

    g_clear_object (&dbus_mgr->priv->manager);

    if (dbus_mgr->priv->peer_certs) {
        g_hash_table_unref (dbus_mgr->priv->peer_certs);
        dbus_mgr->priv->peer_certs = NULL;
    }

    G_OBJECT_CLASS (msgport_dbus_manager_parent_class)->dispose (self);
}


static gboolean
_dbus_manager_handle_register_service (
    MsgPortDbusManager    *dbus_mgr,
    GDBusMethodInvocation *invocation,
    const gchar           *port_name,
    gboolean               is_trusted,
    gpointer               userdata)
{
    GError *error = NULL;
    MsgPortDbusService *dbus_service = NULL;
    msgport_return_val_if_fail (dbus_mgr &&  MSGPORT_IS_DBUS_MANAGER (dbus_mgr), FALSE);

    DBG ("register service request from %p('%s') for port '%s', is_trusted: %d",
        dbus_mgr, dbus_mgr->priv->app_id, port_name, is_trusted);

    dbus_service = msgport_manager_register_service (
            dbus_mgr->priv->manager, dbus_mgr, 
            port_name, is_trusted, &error);

    if (dbus_service) {
        msgport_dbus_glue_manager_complete_register_service (
                dbus_mgr->priv->dbus_skeleton, invocation, 
                msgport_dbus_service_get_object_path(dbus_service));
        return TRUE;
    }

    if (!error) error = msgport_error_unknown_new ();
    g_dbus_method_invocation_take_error (invocation, error);

    return TRUE;
}

static gboolean
_dbus_manager_handle_check_for_remote_service (
    MsgPortDbusManager    *dbus_mgr,
    GDBusMethodInvocation *invocation,
    const gchar    *remote_app_id,
    const gchar    *remote_port_name,
    gboolean        is_trusted,
    gpointer        userdata)
{
    GError *error = NULL;
    MsgPortDbusService *dbus_service = NULL;
    MsgPortDbusManager *remote_dbus_manager = NULL;

    msgport_return_val_if_fail (dbus_mgr && MSGPORT_IS_DBUS_MANAGER (dbus_mgr), FALSE);

    DBG ("check remote service request from %p for '%s' '%s', is_trusted: %d", 
            dbus_mgr, remote_app_id, remote_port_name, is_trusted);

    remote_dbus_manager = msgport_dbus_server_get_dbus_manager_by_app_id (
                dbus_mgr->priv->server, remote_app_id);

    if (remote_dbus_manager) {
        dbus_service = msgport_manager_get_service (dbus_mgr->priv->manager, 
                            remote_dbus_manager, remote_port_name, is_trusted, &error);
        if (dbus_service) {
            DBG ("Found service id : %d", msgport_dbus_service_get_id (dbus_service));
            msgport_dbus_glue_manager_complete_check_for_remote_service (
                dbus_mgr->priv->dbus_skeleton, invocation, 
                msgport_dbus_service_get_id (dbus_service));
            return TRUE;
        }
    }

    if (!error) error = msgport_error_port_not_found (remote_app_id, remote_port_name);
    g_dbus_method_invocation_take_error (invocation, error);

    return TRUE;
}

static gboolean
_dbus_manager_handle_send_message (
    MsgPortDbusManager    *dbus_mgr,
    GDBusMethodInvocation *invocation,
    guint                  service_id,
    GVariant              *data,
    gpointer               userdata)
{
    GError *error = NULL;
    MsgPortDbusService *peer_dbus_service = 0;

    msgport_return_val_if_fail (dbus_mgr && MSGPORT_IS_DBUS_MANAGER (dbus_mgr), FALSE);

    DBG ("send_message from %p('%s') to service_id %d", 
        dbus_mgr, dbus_mgr->priv->app_id, service_id);

    peer_dbus_service = msgport_manager_get_service_by_id (
            dbus_mgr->priv->manager, service_id, &error);

    if (peer_dbus_service) {
        if (msgport_dbus_service_send_message (peer_dbus_service, data, dbus_mgr->priv->app_id, "", FALSE, &error)) {
            msgport_dbus_glue_manager_complete_send_message (
                dbus_mgr->priv->dbus_skeleton, invocation);
            return TRUE;
        }
    }

    if (!error) error = msgport_error_unknown_new ();
    g_dbus_method_invocation_take_error (invocation, error);

    return TRUE;
}

static void
msgport_dbus_manager_class_init (MsgPortDbusManagerClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    g_type_class_add_private (klass, sizeof(MsgPortDbusManagerPrivate));

    gklass->finalize = _dbus_manager_finalize;
    gklass->dispose = _dbus_manager_dispose;
}

static void
msgport_dbus_manager_init (MsgPortDbusManager *self)
{
    MsgPortDbusManagerPrivate *priv = MSGPORT_DBUS_MANAGER_GET_PRIV (self);

    priv->dbus_skeleton = msgport_dbus_glue_manager_skeleton_new ();
    priv->manager = msgport_manager_new ();
    priv->is_null_cert = FALSE;
    priv->peer_certs = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    g_signal_connect_swapped (priv->dbus_skeleton, "handle-register-service",
                G_CALLBACK (_dbus_manager_handle_register_service), (gpointer)self);
    g_signal_connect_swapped (priv->dbus_skeleton, "handle-check-for-remote-service",
                G_CALLBACK (_dbus_manager_handle_check_for_remote_service), (gpointer)self);
    g_signal_connect_swapped (priv->dbus_skeleton, "handle-send-message",
                G_CALLBACK (_dbus_manager_handle_send_message), (gpointer)self);

    self->priv = priv;
}
static gchar *
_get_app_id_from_connection (GDBusConnection *connection, gboolean *is_valid)
{
    pid_t peer_pid;
    GError *error = NULL;
    char app_id[255];
    aul_return_val res;
    GCredentials *cred = g_dbus_connection_get_peer_credentials (connection);

    msgport_return_val_if_fail (cred != NULL, NULL);
#ifdef ENABLE_DEBUG
    gchar *str_cred = g_credentials_to_string (cred);
    DBG ("Client Credentials : %s", str_cred);
    g_free (str_cred);
#endif

    peer_pid = g_credentials_get_unix_pid (cred, &error);
    if (error) {
        WARN ("Faild to get peer pid on conneciton %p : %s", connection, error->message);
        g_error_free (error);
        return NULL;
    }

    if ((res = aul_app_get_appid_bypid (peer_pid, app_id, sizeof(app_id))) != AUL_R_OK) {
    	WARN ("Fail to get appid of peer pid '%d', error : %d, considering pid as app_id", peer_pid, res);
        if (is_valid) *is_valid = FALSE;
    	return g_strdup_printf ("%d", peer_pid);
    }
    if (is_valid) *is_valid = TRUE;
    return g_strdup (app_id);
}

MsgPortDbusManager *
msgport_dbus_manager_new (
    GDBusConnection *connection,
    MsgPortDbusServer *server,
    GError **error)
{
    MsgPortDbusManager *dbus_mgr = NULL;
    gboolean valid_app = FALSE;

    dbus_mgr = MSGPORT_DBUS_MANAGER (g_object_new (MSGPORT_TYPE_DBUS_MANAGER, NULL));
    if (!dbus_mgr) {
        if (error) *error = msgport_error_new (MSGPORT_ERROR_OUT_OF_MEMORY, "Out of memory");
        return NULL;
    }

    if (!g_dbus_interface_skeleton_export (
            G_DBUS_INTERFACE_SKELETON (dbus_mgr->priv->dbus_skeleton),
            connection,
            "/",
            error)) {
        WARN ("Failed to export dbus object on connection %p : %s",
                    connection, error ? (*error)->message : "");
        g_object_unref (dbus_mgr);
        return NULL;
    }
    dbus_mgr->priv->connection = g_object_ref (connection);
    dbus_mgr->priv->server = server;
    dbus_mgr->priv->app_id =  _get_app_id_from_connection (connection, &valid_app);
    /* treat invalid tizen apps has null certificate */
    if (!valid_app) dbus_mgr->priv->is_null_cert = TRUE;

    return dbus_mgr;
}

MsgPortManager *
msgport_dbus_manager_get_manager (MsgPortDbusManager *dbus_manager)
{
    msgport_return_val_if_fail (dbus_manager && MSGPORT_IS_DBUS_MANAGER (dbus_manager), NULL);

    return dbus_manager->priv->manager;
}

GDBusConnection *
msgport_dbus_manager_get_connection (MsgPortDbusManager *dbus_manager)
{
    msgport_return_val_if_fail (dbus_manager && MSGPORT_IS_DBUS_MANAGER (dbus_manager), NULL);

    return dbus_manager->priv->connection;
}

const gchar *
msgport_dbus_manager_get_app_id (MsgPortDbusManager *dbus_manager)
{
    msgport_return_val_if_fail (dbus_manager && MSGPORT_IS_DBUS_MANAGER (dbus_manager), NULL);

    return (const gchar *)dbus_manager->priv->app_id;
}

gboolean
msgport_dbus_manager_validate_peer_certificate (MsgPortDbusManager *dbus_manager, const gchar *peer_app_id)
{
    int res ;
    pkgmgrinfo_cert_compare_result_type_e compare_result;
    gboolean is_valid_cert = FALSE;

    /* check if the source application has no certificate info */
    if (dbus_manager->priv->is_null_cert) {
        DBG("Service owner has no certifcate information, treating port as untrusted");
        return TRUE; /* allow all peers to connect */
    }

    /* check if we have cached status */
    if (g_hash_table_contains (dbus_manager->priv->peer_certs, peer_app_id))
        return ((gboolean)(glong)g_hash_table_lookup (dbus_manager->priv->peer_certs, peer_app_id));

    if ((res = pkgmgrinfo_pkginfo_compare_app_cert_info (dbus_manager->priv->app_id,
                    peer_app_id, &compare_result)) != PMINFO_R_OK) {
        WARN ("Fail to compare certificates of applications('%s', '%s') : error %d", 
                dbus_manager->priv->app_id, peer_app_id, res);
        return FALSE;
    }

    if (compare_result == PMINFO_CERT_COMPARE_LHS_NO_CERT ||
        compare_result == PMINFO_CERT_COMPARE_BOTH_NO_CERT) {
        DBG("Service owner has no certifcate information, treating port as untrusted");
        dbus_manager->priv->is_null_cert = TRUE;
        return TRUE;
    }

    DBG("certificate comparison result : %d", compare_result);

    is_valid_cert = (compare_result == PMINFO_CERT_COMPARE_MATCH) ;
    g_hash_table_insert (dbus_manager->priv->peer_certs, g_strdup (peer_app_id),
            GUINT_TO_POINTER(is_valid_cert));

    return is_valid_cert;
}

