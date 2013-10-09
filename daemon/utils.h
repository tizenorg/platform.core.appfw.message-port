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

#ifndef __MSGPORT_UTILS_H
#define __MSGPORT_UTILS_H

#include <glib.h>
#include "utils.h"

#define msgport_return_if_fail(expr)      g_return_if_fail (expr)
#define msgport_return_if_fail_with_error(expr, err) \
do {\
    if (G_LIKELY (expr)) { }\
    else \
        g_return_if_fail_warning (G_LOG_DOMAIN,__PRETTY_FUNCTION__, ##expr);\
        if (err) *err = msgport_error_new (MSGPORT_ERROR_INVALID_PARAMS, "assert("#expr")"); \
        return; \
    }\
} while(0);

#define msgport_return_val_if_fail(expr, ret)     g_return_val_if_fail (expr, ret)
#define msgport_return_val_if_fail_with_error(expr, ret, err) \
do {\
    if (G_LIKELY(expr)) { } \
    else {\
        g_return_if_fail_warning (G_LOG_DOMAIN,__PRETTY_FUNCTION__, #expr);\
        if (err) *err = msgport_error_new (MSGPORT_ERROR_INVALID_PARAMS, "assert("#expr")"); \
        return ret; \
    }\
} while (0);

#endif /* __MSGPORT_UTILS_H */
