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

#ifndef __MSGPORT_DBUS_SERVER_H
#define __MSGPORT_DBUS_SERVER_H

#include <config.h>
#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define MSGPORT_TYPE_DBUS_SERVER            (msgport_dbus_server_get_type())
#define MSGPORT_DBUS_SERVER(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MSGPORT_TYPE_DBUS_SERVER, MsgPortDbusServer))
#define MSGPORT_DBUS_SERVER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), MSGPORT_TYPE_DBUS_SERVER, MsgPortDbusServerClass))
#define MSGPORT_IS_DBUS_SERVER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MSGPORT_TYPE_DBUS_SERVER))
#define MSGPORT_IS_DBUS_SERVER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), MSGPORT_TYPE_DBUS_SERVER))
#define MSGPORT_DBUS_SERVER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), MSGPORT_TYPE_DBUS_SERVER, MsgPortDbusServerClass))

typedef struct _MsgPortManager MsgPortManager;
typedef struct _MsgPortDbusManager MsgPortDbusManager;
typedef struct _MsgPortDbusServer MsgPortDbusServer;
typedef struct _MsgPortDbusServerClass MsgPortDbusServerClass;
typedef struct _MsgPortDbusServerPrivate MsgPortDbusServerPrivate;

struct _MsgPortDbusServer
{
    GObject parent;

    /* priv */
    MsgPortDbusServerPrivate *priv;
};

struct _MsgPortDbusServerClass
{
    GObjectClass parent_class;
};

GType msgport_dbus_server_get_type();

const gchar *
msgport_dbus_server_get_address (MsgPortDbusServer *server) G_GNUC_CONST;

MsgPortDbusServer * msgport_dbus_server_new ();

MsgPortManager    * msgport_dbus_server_get_manager (MsgPortDbusServer *server);

MsgPortDbusManager *
msgport_dbus_server_get_dbus_manager_by_app_id (MsgPortDbusServer *server, const gchar *app_id);

#endif /* __MSGPORT_DBUS_SERVER_H */
