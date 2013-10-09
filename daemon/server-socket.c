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

#include "server-socket.h"
#include "libwebsockets.h"
#include "priv-libwebsockets.h"

G_DEFINE_TYPE (MsgPortServerSocket, msgport_server_socket, G_TYPE_OBJECT)

#define MSGPORT_SERVER_SOCKET_GET_PRIV(obj) \
    G_TYPE_INSTANCE_GET_PRIVATE ((obj), MSGPORT_TYPE_SERVER_SOCKET, MsgPortServerSocketPrivate)

struct _MsgPortServerSocketPrivate {
    GMainLoop *ml;
    struct libwebsocket_context *context;
};


static void
_server_socket_finalize (GObject *self)
{
    MsgPortServerSocket *socket = MSGPORT_SERVER_SOCKET (self);

    if (socket->priv->context) {
        libwebsocket_context_destroy (socket->priv->context);
        socket->priv->context = NULL;
    }

    G_OBJECT_CLASS (msgport_server_socket_parent_class)->finalize (self);
}

static void
_server_socket_dispose (GObject *self)
{
    G_OBJECT_CLASS (msgport_server_socket_parent_class)->dispose (self);
}

static void
msgport_server_socket_init (MsgPortServerSocket *self)
{
    MsgPortServerSocketPrivate *priv = MSGPORT_SERVER_SOCKET_GET_PRIV (self);

    self->priv = priv;
}

static void
msgport_server_socket_class_init (MsgPortServerSocketClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    g_type_class_add_private (klass, sizeof(MsgPortServerSocketPrivate));

    gklass->finalize = _server_socket_finalize;
    gklass->dispose = _server_socket_dispose;
}

struct MsgPortCallbackData {
    MsgPortServerSocket *self;
    struct libwebsocket_context *wsctx;
};

static gboolean 
_fd_event (
    GIOChannel *source,
    GIOCondition condition,
    gpointer data)
{
    struct pollfd pollfd ;
    static libwebsocket_context *wsctx = (struct libwebsocket_context *)data;

    pollfd.fd = g_io_channel_get_unix_fd (source);
    pollfd.events = condition; // FIXME: convert to poll events ??
    pollfd.revents = ; // FIXME: what it should ?? 

    libwebsocket_service_fd (wsctx, pollfd);
};

static void
_add_fd_to_main_loop (
    MsgPortServerSocket *socket,
    int fd,
    int events)
{
    if (socket->priv->ml) {
        GIOChannel *io = g_io_channel_unix_new (fd);
        g_io_add_watch (io, events, _fd_event, socket);
    }


static int
_http_callback (
    struct libwebsocket_context       *context,
    struct libwebsocket               *wsi,
    enum libwebsocket_callback_reasons reason,
    void  *user,
    void  *in, 
    size_t len)
{
    switch (reason) {
        case LWS_CALLBACK_HTTP:
        /* client connected */
        break;

        default:
        g_print ("%s reason %d\n", __FUNCTION_NAME__, reason);
    }

    return 0;
}

static int
_msgport_callback (
    struct libwebsocket_context       *context,
    struct libwebsocket               *wsi,
    enum libwebsocket_callback_reasons reason,
    void  *user,
    void  *in, 
    size_t len)
{
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
        break;

        default:
        g_print ("%s reason %d\n", __FUNCTION_NAME__, reason);
    }

    return 0;
}



MsgPortServerSocket *
msgport_server_socket_new (GMainLoop *ml)
{
    struct lws_context_creation_info info;
    static struct libwebsocket_protocols protocols[] = {
        /* first protocol must always be HTTP handler */
        { "http-only",   _http_callback,    sizeof (void *), 0, },
        { "messge-port", _msgport_callback, sizeof (void *), 0, },
        { NULL, NULL, 0, 0 }
    };

    MsgPortServerSocket *socket = NULL;

    socket = MSGPORT_SERVER_SOCKET (g_object_new (MSGPORT_TYPE_SERVER_SOCKET, NULL));
    if (!socket) return NULL;

    info.port = 9000;
    info.iface = NULL;
    info.protocols = protocols;
    info.extensions = libwebsocket_get_internal_extensions();
    info.ssl_cert_filepath = NULL;
    info.ssl_private_key_filepath = NULL;
    info.ssl_cipher_list = NULL;
    /* FIXME: set socket permessions */
    info.gid = -1; info.uid = -1;
    info.options = 0;
    info.user = socket;
    info.ka_time = 0;
    info.ka_probes = 0;
    info.ka_interval = 0;

    socket->priv->context = libwebsocket_create_context (&info);
    socket->priv->ml = g_main_loop_ref (ml);
}

gboolean
msgport_server_socket_start (MsgPortServerSocket *socket)
{
    g_return_val_if_fail (socket && MSGPORT_IS_SERVER_SOCKET (socket), FALSE);

    if (!socket->priv->ml) {
        /* run libwesocket loop if no super mainloop */
        while (1) {
            libwebsocket_service (socket->priv.>context, 50);
        }
    }
    else {
        /* integrate to super mainloop */
    }

    return TRUE;
}

