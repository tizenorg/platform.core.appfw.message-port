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

#include "msgport-utils.h"
#include "common/dbus-error.h" /* MsgPortError */
#include "common/log.h"

static void
_bundle_iter_cb (const char *key, const int type, const bundle_keyval_t *kv, void *user_data)
{
    GVariantBuilder *builder = (GVariantBuilder *)user_data;
    void *val;
    size_t size;

    /* NOTE: we support only string values as 
     * MessagePort API support key,value strings 
     */
    if (bundle_keyval_get_type ((bundle_keyval_t*)kv) != BUNDLE_TYPE_STR) return;

    bundle_keyval_get_basic_val ((bundle_keyval_t*)kv, &val, &size);

    g_variant_builder_add (builder, "{sv}", key, g_variant_new_string ((const gchar *)val));
}

GVariant * bundle_to_variant_map (bundle *b)
{
    GVariantBuilder builder;

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

    bundle_foreach (b, _bundle_iter_cb, &builder);

    return g_variant_builder_end (&builder);
}

bundle * bundle_from_variant_map (GVariant *v_data)
{
    bundle *b = NULL;
    GVariantIter iter;
    gchar *key = NULL;
    GVariant *value  = NULL;

    if (!v_data) return b;

    g_variant_iter_init (&iter, v_data);

    b = bundle_create ();

    while (g_variant_iter_next (&iter, "{sv}", &key, &value)) {
        bundle_add (b, key, g_variant_get_string (value, NULL));
        g_free (key);
        g_variant_unref (value);
    }

    return b;
}

messageport_error_e
msgport_daemon_error_to_error (const GError *error)
{
    if (!error) return MESSAGEPORT_ERROR_NONE;

    switch (error->code) {
        case MSGPORT_ERROR_OUT_OF_MEMORY:
            return MESSAGEPORT_ERROR_OUT_OF_MEMORY;
        case MSGPORT_ERROR_NOT_FOUND:
            return MESSAGEPORT_ERROR_MESSAGEPORT_NOT_FOUND;
        case MSGPORT_ERROR_INVALID_PARAMS:
            return MESSAGEPORT_ERROR_INVALID_PARAMETER;
        case MSGPORT_ERROR_CERTIFICATE_MISMATCH:
            return MESSAGEPORT_ERROR_CERTIFICATE_NOT_MATCH;
        case MSGPORT_ERROR_UNKNOWN:
        case MSGPORT_ERROR_IO_ERROR:
            return MESSAGEPORT_ERROR_IO_ERROR;
    }

    return MESSAGEPORT_ERROR_IO_ERROR;
}
