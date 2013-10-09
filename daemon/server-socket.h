/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
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

#ifndef __MSGPORT_SERVER_SOCKET_H
#define __MSGPORT_SERVER_SOCKET_H

#include <glib.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define MSGPORT_TYPE_SERVER_SOCKET (msgport_server_socket_get_type())
#define MSGPORT_SERVER_SOCKET(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), MSGPORT_TYPE_SERVER_SOCKET, MsgPortServerSocket))
#define MSGPORT_SERVER_SOCKET_CLASS(obj)  (G_TYPE_CHECK_CLASS_CAST((kls), MSGPORT_TYPE_SERVER_SOCKET, MsgPortServerSocketClass))
#define MSGPORT_IS_SERVER_SOCKET(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), MSGPORT_TYPE_SERVER_SOCKET))
#define MSGPORT_IS_SERVER_SOCKET_CLASS(kls) (G_TYPE_CHECK_CLASS_TYPE((kls), MSGPORT_TYPE_SERVER_SOCKET))

typedef struct _MsgPortServerSocket MsgPortServerSocket;
typedef struct _MsgPortServerSocketClass MsgPortServerSocketClass;
typedef struct _MsgPortServerSocketPrivate MsgPortServerSocketPrivate;

struct _MsgPortServerSocket
{
    GObject parent;

    /* private */
    MsgPortServerSocketPrivate *priv;
};

struct _MsgPortServerSocketClass
{
    GObjectClass parenet_class;
};

GType msgport_server_socket_get_type (void);

MsgPortServerSocket *
msgport_server_socket_new ();

gboolean
msgport_server_socket_start ();

G_END_DECLS

#endif /* __MSGPORT_SERVER_SOCKET_H */

