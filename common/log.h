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

#ifndef __MSGPORT_LOG_H
#define __MSGPORT_LOG_H

#include <glib.h>
#include "config.h"

#ifdef HAVE_DLOG

#   include <dlog.h>


#   define DBG(frmt, args...)  LOGD(frmt, ##args)
#   define WARN(frmt, args...) LOGW(frmt, ##args)
#   define ERR(frmt, args...)  LOGE(frmt, ##args)

#else /* USE_DLOG */

#   define __LOG(log_func, frmt, args...) log_func("%s +%d:"frmt, __FILE__, __LINE__, ##args)

#   define DBG(frmt, args...)  __LOG(g_debug, frmt, ##args)
#   define WARN(frmt, args...) __LOG(g_warning, frmt, ##args)
#   define ERR(frmt, args...)  __LOG(g_error, frmt, ##args)

#endif /* USE_DLOG */

#endif /* __MSGPORT_LOG_H */
