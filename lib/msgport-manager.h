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

#include <glib.h>
#include <glib-object.h>
#include <message-port.h>

#define MSGPORT_TYPE_MANAGER (msgport_manager_get_type())
#define MSGPORT_MANAGER(obj)          (G_TYPE_CHECK_INSTANCE_CAST((obj), MSGPORT_TYPE_MANAGER, MsgPortManager))
#define MSGPORT_MANAGER_CLASS(kls)    (G_TYPE_CHECK_CLASS_CAST((kls), MSGPORT_TYPE_MANAGER, MsgPortManagerClass))
#define MSGPORT_IS_MANAGER(obj)       (G_TYPE_CHECK_INSTANCE_TYPE((obj), MSGPORT_TYPE_MANAGER))
#define MSGPORT_IS_MANAGER_CLASS(kls) (G_TYPE_CHECK_CLASS_TYPE((kls), MSGPORT_TYPE_MANAGER)

typedef struct _MsgPortManager MsgPortManager;
typedef struct _MsgPortManagerClass MsgPortManagerClass;
typedef struct _MsgPortService MsgPortService;

G_BEGIN_DECLS

struct _MsgPortManagerClass
{
    GObjectClass parent_class;
};

GType msgport_manager_get_type (void);

MsgPortManager *
msgport_manager_new ();

messageport_error_e
msgport_manager_register_service (MsgPortManager *manager, const gchar *port_name, gboolean is_trusted, messageport_message_cb cb, int *service_id_out);

messageport_error_e
msgport_manager_check_remote_service (MsgPortManager *manager, const gchar *remote_app_id, const gchar *port_name, gboolean is_trusted, guint *service_id_out);

messageport_error_e
msgport_manager_get_service_name (MsgPortManager *manager, int port_id, gchar **name_out);

messageport_error_e
msgport_manager_get_service_is_trusted (MsgPortManager *manager, int port_id, gboolean *is_trusted_out);

messageport_error_e
msgport_manager_unregister_service (MsgPortManager *manager, int service_id);

messageport_error_e
msgport_manager_send_message (MsgPortManager *manager, const gchar *remote_app_id, const gchar *port_name, gboolean is_trusted, GVariant *data);

messageport_error_e
msgport_manager_send_bidirectional_message (MsgPortManager *manager, int from_id, const gchar *remote_app_id, const gchar *port_name, gboolean is_trusted, GVariant *data);

G_END_DECLS

#endif /* __MSGPORT_MANAGER_PROXY_H */
