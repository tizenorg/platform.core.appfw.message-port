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

#ifndef __MSGPORT_DBUS_MANAGER_H
#define __MSGPORT_DBUS_MANAGER_H

#include <glib.h>
#include <gio/gio.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define MSGPORT_TYPE_DBUS_MANAGER (msgport_dbus_manager_get_type())
#define MSGPORT_DBUS_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), MSGPORT_TYPE_DBUS_MANAGER, MsgPortDbusManager))
#define MSGPORT_DBUS_MANAGER_CLASS(obj)  (G_TYPE_CHECK_CLASS_CAST((kls), MSGPORT_TYPE_DBUS_MANAGER, MsgPortDbusManagerClass))
#define MSGPORT_IS_DBUS_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), MSGPORT_TYPE_DBUS_MANAGER))
#define MSGPORT_IS_DBUS_MANAGER_CLASS(kls) (G_TYPE_CHECK_CLASS_TYPE((kls), MSGPORT_TYPE_DBUS_MANAGER))

typedef struct _MsgPortDbusManager MsgPortDbusManager;
typedef struct _MsgPortDbusManagerClass MsgPortDbusManagerClass;
typedef struct _MsgPortDbusManagerPrivate MsgPortDbusManagerPrivate;

typedef struct _MsgPortManager MsgPortManager;
typedef struct _MsgPortDbusServer MsgPortDbusServer;

struct _MsgPortDbusManager
{
    GObject parent;

    /* private */
    MsgPortDbusManagerPrivate *priv;
};

struct _MsgPortDbusManagerClass
{
    GObjectClass parenet_class;
};

GType msgport_dbus_manager_get_type (void);

MsgPortDbusManager *
msgport_dbus_manager_new (
    GDBusConnection *connection,
    MsgPortDbusServer *server,
    GError **error);

MsgPortManager *
msgport_dbus_manager_get_manager (MsgPortDbusManager *dbus_manager);

GDBusConnection *
msgport_dbus_manager_get_connection (MsgPortDbusManager *dbus_manager);

const gchar *
msgport_dbus_manager_get_app_id (MsgPortDbusManager *dbus_manager);

gboolean
msgport_dbus_manager_validate_peer_certificate (MsgPortDbusManager *dbus_manager,
                                                const gchar *peer_app_id);

G_END_DECLS

#endif /* __MSGPORT_DBUS_MANAER_H */

