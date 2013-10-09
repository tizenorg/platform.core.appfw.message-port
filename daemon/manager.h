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

#ifndef __MSGPORT_MANAGER_H
#define __MSGPORT_MANAGER_H

#include <glib-object.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define MSGPORT_TYPE_MANAGER (msgport_manager_get_type())
#define MSGPORT_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), MSGPORT_TYPE_MANAGER, MsgPortManager))
#define MSGPORT_MANAGER_CLASS(obj)  (G_TYPE_CHECK_CLASS_CAST((kls), MSGPORT_TYPE_MANAGER, MsgPortManagerClass))
#define MSGPORT_IS_MANAGER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), MSGPORT_TYPE_MANAGER))
#define MSGPORT_IS_MANAGER_CLASS(kls) (G_TYPE_CHECK_CLASS_TYPE((kls), MSGPORT_TYPE_MANAGER))

typedef struct _MsgPortManager MsgPortManager;
typedef struct _MsgPortManagerClass MsgPortManagerClass;
typedef struct _MsgPortManagerPrivate MsgPortManagerPrivate;

typedef struct _MsgPortDbusManager MsgPortDbusManager;
typedef struct _MsgPortDbusService MsgPortDbusService;

struct _MsgPortManager
{
    GObject parent;

    /* private */
    MsgPortManagerPrivate *priv;
};

struct _MsgPortManagerClass
{
    GObjectClass parenet_class;
};

GType msgport_manager_get_type (void);

MsgPortManager *
msgport_manager_new ();

MsgPortDbusService *
msgport_manager_register_service (
    MsgPortManager     *manager,
    MsgPortDbusManager *owner,
    const gchar        *port_name,
    gboolean            is_trusted,
    GError            **error_out);

MsgPortDbusService *
msgport_manager_get_service (
    MsgPortManager     *manager,
    MsgPortDbusManager *owner,
    const gchar        *remote_port_name,
    gboolean            is_trusted,
    GError            **error_out);

MsgPortDbusService *
msgport_manager_get_service_by_id (
    MsgPortManager *manager,
    guint           service_id,
    GError        **error_out);

gboolean
msgport_manager_unregister_services (
    MsgPortManager     *manager,
    MsgPortDbusManager *owned_by,
    GError            **error_out);

G_END_DECLS

#endif /* __MSGPORT_MANAER_H */

