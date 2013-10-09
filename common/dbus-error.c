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

#include "dbus-error.h"

#include <gio/gio.h>

#define MSGPORT_ERROR_DOMAIN "messagport"
#define _PREFIX              "org.tizen.MessagePort.Error"

GDBusErrorEntry __msgport_errors [] = {
    {MSGPORT_ERROR_IO_ERROR,             _PREFIX".IOError"},
    {MSGPORT_ERROR_INVALID_PARAMS,       _PREFIX".InvalidParams"},
    {MSGPORT_ERROR_OUT_OF_MEMORY,        _PREFIX".OutOfMemory"},
    {MSGPORT_ERROR_NOT_FOUND,            _PREFIX".NotFound"},
    {MSGPORT_ERROR_ALREADY_EXISTING,     _PREFIX".AlreadyExisting"},
    {MSGPORT_ERROR_CERTIFICATE_MISMATCH, _PREFIX".CertificateMismatch"},
    {MSGPORT_ERROR_UNKNOWN,              _PREFIX".Unknown"}
};

GQuark
msgport_error_quark (void)
{
    static volatile gsize quark_volatile = 0;

    if (!quark_volatile) {
        g_dbus_error_register_error_domain (MSGPORT_ERROR_DOMAIN, 
                                            &quark_volatile,
                                            __msgport_errors,
                                            G_N_ELEMENTS (__msgport_errors));
    }

    return quark_volatile;
}
