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

#ifndef __MSGPORT_DBUS_SERVICE_H
#define __MSGPORT_DBUS_SERVICE_H

#include <glib.h>
#include <gio/gio.h>
#include <glib-object.h>
#include "dbus-manager.h"

G_BEGIN_DECLS

#define MSGPORT_TYPE_DBUS_SERVICE (msgport_dbus_service_get_type())
#define MSGPORT_DBUS_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), MSGPORT_TYPE_DBUS_SERVICE, MsgPortDbusService))
#define MSGPORT_DBUS_SERVICE_CLASS(obj)  (G_TYPE_CHECK_CLASS_CAST((kls), MSGPORT_TYPE_DBUS_SERVICE, MsgPortDbusServiceClass))
#define MSGPORT_IS_DBUS_SERVICE(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), MSGPORT_TYPE_DBUS_SERVICE))
#define MSGPORT_IS_DBUS_SERVICE_CLASS(kls) (G_TYPE_CHECK_CLASS_TYPE((kls), MSGPORT_TYPE_DBUS_SERVICE))

typedef struct _MsgPortDbusService MsgPortDbusService;
typedef struct _MsgPortDbusServiceClass MsgPortDbusServiceClass;
typedef struct _MsgPortDbusServicePrivate MsgPortDbusServicePrivate;

struct _MsgPortDbusService
{
    GObject parent;

    /* private */
    MsgPortDbusServicePrivate *priv;
};

struct _MsgPortDbusServiceClass
{
    GObjectClass parenet_class;
};

GType msgport_dbus_service_get_type (void);

MsgPortDbusService *
msgport_dbus_service_new (MsgPortDbusManager *owner,
                          const gchar *name,
                          gboolean is_trusted,
                          GError **error_out);

const gchar *
msgport_dbus_service_get_object_path (MsgPortDbusService *dbus_service);

GDBusConnection *
msgport_dbus_service_get_connection (MsgPortDbusService *dbus_service);

guint
msgport_dbus_service_get_id (MsgPortDbusService *dbus_service);

MsgPortDbusManager *
msgport_dbus_service_get_owner (MsgPortDbusService *dbus_service);

const gchar *
msgport_dbus_service_get_app_id (MsgPortDbusService *dbus_service);

const gchar *
msgport_dbus_service_get_port_name (MsgPortDbusService *dbus_service);

gboolean
msgport_dbus_service_get_is_trusted (MsgPortDbusService *dbus_service);

gboolean
msgport_dbus_service_send_message (MsgPortDbusService *dbus_service,
                                   GVariant    *data,
                                   const gchar *remote_app_id,
                                   const gchar *remote_port_name,
                                   gboolean     remote_is_trusted,
                                   GError     **error_out);

G_END_DECLS

#endif /* __MSGPORT_DBUS_SERVICE_H */

