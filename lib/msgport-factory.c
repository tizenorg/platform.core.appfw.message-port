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

#include "msgport-factory.h"
#include "msgport-manager.h"
#include "common/log.h"
#include <glib.h>

GHashTable *__managers = NULL; /* GThread:MsgPortManager */
G_LOCK_DEFINE(managers);

static 
void msgport_factory_init ()
{
    G_LOCK(managers);

    if (!__managers)
        __managers = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                              NULL, (GDestroyNotify)g_object_unref);

    G_UNLOCK(managers);
}

void msgport_factory_uninit ()
{
    G_LOCK(managers);

    if (__managers) {
        g_hash_table_destroy (__managers);
        __managers = NULL;
    }

    G_UNLOCK(managers);
}

MsgPortManager * msgport_factory_get_manager () 
{
    MsgPortManager *manager = NULL;
    GThread *self_thread = g_thread_self ();

    if (!__managers) msgport_factory_init ();

    G_LOCK(managers);

    manager = MSGPORT_MANAGER (g_hash_table_lookup (__managers, self_thread));

    if (!manager) {
        manager = msgport_manager_new ();

        if (manager) 
            g_hash_table_insert (__managers, (gpointer)self_thread, manager);
    }

    G_UNLOCK(managers);

    return manager;
}
