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

#ifndef __MSGPORT_ERROR_H
#define __MSGPORT_ERROR_H

#include <glib.h>

#define MSGPORT_ERROR_QUARK (msgport_error_quark())

G_BEGIN_DECLS

typedef enum _MsgPortError
{
    MSGPORT_ERROR_IO_ERROR = 100,
    MSGPORT_ERROR_OUT_OF_MEMORY,
    MSGPORT_ERROR_INVALID_PARAMS,
    MSGPORT_ERROR_NOT_FOUND,
    MSGPORT_ERROR_ALREADY_EXISTING,
    MSGPORT_ERROR_CERTIFICATE_MISMATCH,
    MSGPORT_ERROR_UNKNOWN

} MsgPortError;

GQuark
msgport_error_quark ();

#define msgport_error_new(id, msg, args...) \
    g_error_new (MSGPORT_ERROR_QUARK, id, msg, ##args) 

#define msgport_error_port_existing_new(app_id, port_name) \
    msgport_error_new (MSGPORT_ERROR_ALREADY_EXISTING, \
                       "port already existing with name '%s' on application '%s'", port_name, app_id)

#define msgport_error_no_memory_new() \
    msgport_error_new (MSGPORT_ERROR_OUT_OF_MEMORY, "no memomry")

#define msgport_error_port_not_found(app_id, port_name) \
    msgport_error_new (MSGPORT_ERROR_NOT_FOUND, "port not found with name '%s' on application '%s'", port_name, app_id)

#define msgport_error_port_id_not_found_new(service_id) \
    msgport_error_new (MSGPORT_ERROR_NOT_FOUND, "no port found with id '%d'", service_id)

#define msgport_error_certificate_mismatch_new() \
    msgport_error_new (MSGPORT_ERROR_CERTIFICATE_MISMATCH, "cerficates not matched")

#define msgport_error_unknown_new() \
    msgport_error_new (MSGPORT_ERROR_UNKNOWN, "unknown")

G_END_DECLS

#endif /* __MSGPORT_ERROR_H */
