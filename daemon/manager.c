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

#include "manager.h"
#include "common/dbus-error.h"
#include "common/log.h"
#include "dbus-manager.h"
#include "dbus-service.h"
#include "utils.h"

G_DEFINE_TYPE (MsgPortManager, msgport_manager, G_TYPE_OBJECT)

#define MSGPORT_MANAGER_GET_PRIV(obj) \
    G_TYPE_INSTANCE_GET_PRIVATE ((obj), MSGPORT_TYPE_MANAGER, MsgPortManagerPrivate)

struct _MsgPortManagerPrivate {
    /*
     * Key :   guint - Id of the service
     * Value : MsgPortDbusService * (transfe full)
     */
    GHashTable *service_cache; /* {service_id,MsgPortDbusService} */

    /*
     * Holds services owned by a client 
     * Key : MsgPortDbusManager *
     * Value : GList<MsgPortDbusService *> (tranfer none)
     */
    GHashTable *owner_service_map; /* {MsgPortDbusManager*,GList[MsgPortDbusService]} */
};

static void
_manager_finalize (GObject *self)
{
    //MsgPortManager *manager = MSGPORT_MANAGER (self);

    G_OBJECT_CLASS (msgport_manager_parent_class)->finalize (self);
}

static void
_manager_dispose (GObject *self)
{
    MsgPortManager *manager = MSGPORT_MANAGER (self);

    g_hash_table_unref (manager->priv->owner_service_map);
    manager->priv->owner_service_map = NULL;

    g_hash_table_unref (manager->priv->service_cache);
    manager->priv->service_cache = NULL;

    G_OBJECT_CLASS (msgport_manager_parent_class)->dispose (self);
}

static void
msgport_manager_init (MsgPortManager *self)
{
    MsgPortManagerPrivate *priv = MSGPORT_MANAGER_GET_PRIV (self);

    priv->service_cache = g_hash_table_new_full (
                g_direct_hash, g_direct_equal, NULL, g_object_unref);
    priv->owner_service_map = g_hash_table_new_full (
                g_direct_hash, g_direct_equal, 
                NULL, (GDestroyNotify) g_list_free);

    self->priv = priv;
}

static void
msgport_manager_class_init (MsgPortManagerClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    g_type_class_add_private (klass, sizeof(MsgPortManagerPrivate));

    gklass->finalize = _manager_finalize;
    gklass->dispose = _manager_dispose;
}

MsgPortManager *
msgport_manager_new ()
{
    static GObject *manager = NULL;

    if (!manager) {
        manager =  g_object_new (MSGPORT_TYPE_MANAGER, NULL);
        g_object_add_weak_pointer (manager, (gpointer *)&manager);

        return MSGPORT_MANAGER (manager);
    }

    return MSGPORT_MANAGER (g_object_ref (manager));
}

/*
 * It returns the serice pointer, if found with given owner, port_name and is_trusted 
 * It assues the given arguments are valid.
 */
MsgPortDbusService *
_manager_get_service_internal (
    MsgPortManager     *manager,
    MsgPortDbusManager *owner,
    const gchar        *port_name,
    gboolean            is_trusted)
{
    GList *service_list = g_hash_table_lookup (manager->priv->owner_service_map, owner);
    
    DBG ("Checking for port '%s', is_tursted : %d owned by : %p('%s')",
            port_name, is_trusted, owner, msgport_dbus_manager_get_app_id (owner));

    while (service_list != NULL) {
        MsgPortDbusService *dbus_service = MSGPORT_DBUS_SERVICE (service_list->data);

        if ( !g_strcmp0 (port_name, msgport_dbus_service_get_port_name (dbus_service)) && 
             is_trusted == msgport_dbus_service_get_is_trusted (dbus_service)) {
            DBG ("   Found with %d", msgport_dbus_service_get_id (dbus_service));
            return dbus_service ;
        }

        service_list = service_list->next;
    }

    DBG ("   Not Found");

    return NULL;
}

MsgPortDbusService *
msgport_manager_register_service (
    MsgPortManager     *manager,
    MsgPortDbusManager *owner,
    const gchar        *port_name,
    gboolean            is_trusted,
    GError            **error)
{
    GList   *service_list  = NULL; /* services list owned by a client */
    gboolean list_was_empty = TRUE;
    MsgPortDbusService *dbus_service = NULL;

    msgport_return_val_if_fail_with_error (manager && MSGPORT_IS_MANAGER (manager), NULL, error);
    msgport_return_val_if_fail_with_error (owner && MSGPORT_IS_DBUS_MANAGER (owner), NULL, error);
    msgport_return_val_if_fail_with_error (port_name && port_name[0], NULL, error);

    /* check if port already existing with given params */
    dbus_service = _manager_get_service_internal (manager, owner, port_name, is_trusted);
    if (dbus_service != NULL)
        return dbus_service;

    /* create  new port/service */
    dbus_service = msgport_dbus_service_new (owner, port_name, is_trusted, error);
    if (!dbus_service) {
        ERR ("Failed to create new servcie");
        return NULL;
    }
    /* cache newly created service */
    g_hash_table_insert (manager->priv->service_cache, 
        GINT_TO_POINTER (msgport_dbus_service_get_id (dbus_service)),
        (gpointer)dbus_service);

    service_list = g_hash_table_lookup (manager->priv->owner_service_map, owner);
    list_was_empty = (service_list == NULL);

   /* append to list of services */
    service_list = g_list_append (service_list, dbus_service);
    if (list_was_empty) {
        g_hash_table_insert (manager->priv->owner_service_map, owner, service_list);
    }

    return dbus_service;
}


MsgPortDbusService *
msgport_manager_get_service (
    MsgPortManager      *manager,
    MsgPortDbusManager  *owner,
    const gchar         *port_name,
    gboolean             is_trusted,
    GError             **error)
{
    MsgPortDbusService *service = NULL;

    msgport_return_val_if_fail_with_error (manager && MSGPORT_IS_MANAGER (manager), NULL, error);
    msgport_return_val_if_fail_with_error (owner && MSGPORT_IS_DBUS_MANAGER (owner), NULL, error);
    msgport_return_val_if_fail_with_error (port_name && port_name[0], NULL, error);

    service = _manager_get_service_internal (manager, owner, port_name, is_trusted);

    if (!service && error) 
        *error = msgport_error_port_not_found (msgport_dbus_manager_get_app_id (owner), port_name);

    return service;
}

MsgPortDbusService *
msgport_manager_get_service_by_id (
    MsgPortManager *manager,
    guint           service_id,
    GError        **error)
{
    MsgPortDbusService *dbus_service = NULL;

    msgport_return_val_if_fail_with_error (manager && MSGPORT_IS_MANAGER (manager), NULL, error);
    msgport_return_val_if_fail_with_error (service_id != 0, NULL, error);

    dbus_service = MSGPORT_DBUS_SERVICE (g_hash_table_lookup (
            manager->priv->service_cache, GINT_TO_POINTER(service_id)));

    return dbus_service;
}

static void
_manager_unref_dbus_manager_cb (gpointer data, gpointer user_data)
{
    MsgPortManager *manager = MSGPORT_MANAGER (user_data);
    MsgPortDbusService *service = MSGPORT_DBUS_SERVICE (data);
    guint id = msgport_dbus_service_get_id (service);

#ifdef ENABLE_DEBUG
    DBG ("Unregistering service %s:%s(%d)", 
        msgport_dbus_manager_get_app_id (msgport_dbus_service_get_owner (service)),
        msgport_dbus_service_get_port_name (service), id);
#endif
    /* remove the service from id:service map,
     * as its being unregisted */
    g_hash_table_remove (manager->priv->service_cache, GINT_TO_POINTER(id));
}

/*
 * unregister a signle service for given service id
 */
gboolean
msgport_manager_unregister_service (
    MsgPortManager *manager,
    gint            service_id,
    GError        **error)
{
    MsgPortDbusService *service = NULL;
    MsgPortDbusManager *owner = NULL;
    GList *service_list = NULL, *new_service_list = NULL;

    msgport_return_val_if_fail_with_error (manager && MSGPORT_IS_MANAGER (manager), FALSE, error);

    service = g_hash_table_lookup (manager->priv->service_cache, GINT_TO_POINTER (service_id));

    if (!service) {
        if (error) *error = msgport_error_port_id_not_found_new (service_id);
        return FALSE;
    }

    owner = msgport_dbus_service_get_owner (service);

    service_list = g_hash_table_lookup (manager->priv->owner_service_map, owner);

    /* remove service from services list owned by the 'owner'*/
    new_service_list = g_list_remove (service_list, service);
    if (new_service_list != service_list) {
        g_hash_table_steal (manager->priv->owner_service_map, owner);
        /* update the new list on this owner */
        g_hash_table_insert (manager->priv->owner_service_map, owner, new_service_list);
    }

    /* remove from the service_id:servcie table */
    g_hash_table_remove (manager->priv->service_cache, GINT_TO_POINTER(service_id));

    return TRUE;
}

/*
 * unregister all the services owned by a client
 */
gboolean
msgport_manager_unregister_services (
    MsgPortManager     *manager,
    MsgPortDbusManager *owner,
    GError            **error)
{

    GList *service_list = NULL;

    msgport_return_val_if_fail_with_error (manager && MSGPORT_IS_MANAGER (manager), FALSE, error);

    /* fetch sevice list owned by the client */
    service_list = g_hash_table_lookup (manager->priv->owner_service_map, owner);
    if (!service_list) {
        DBG("no services found on client '%p'", owner);
        return TRUE;
    }

    /* remove all the service from the list */
    g_list_foreach (service_list, _manager_unref_dbus_manager_cb, manager);
    g_hash_table_remove (manager->priv->owner_service_map, owner);

    return TRUE;
}
