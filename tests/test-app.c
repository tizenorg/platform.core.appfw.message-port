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

#include "config.h"
#include <bundle.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib-unix.h>
#include <message-port.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __pipe[2]; /* pipe between two process */
pid_t __daemon_pid; /* dbus daemon pid */

const gchar *PARENT_TEST_PORT = "parent_test_port";
const gchar *PARENT_TEST_TRUSTED_PORT = "parent_test_trusted_port";
const gchar *CHILD_TEST_PORT = "child_test_port";
const gchar *CHILD_TEST_TRUSTED_PORT = "child_test_trusted_port";

struct AsyncTestData
{
    GMainLoop *m_loop;
    gboolean   result;
} *__test_data  = NULL;

#define TEST_CASE(case) \
do { \
    if (case() != TRUE) { \
        g_printerr ("%s: FAIL\n", #case); \
        return -1; \
    } \
    else g_print ("%s: SUCCESS\n", #case); \
}while (0)


#define test_assert(expr, msg, args...) \
do { \
    if ((expr) == FALSE) {\
        g_print ("%s +%d: assert(%s):"msg"\n", __FUNCTION__, __LINE__, #expr, ##args); \
        return FALSE; \
    } \
} while(0);


static void _dump_data (const char *key, const int type, const bundle_keyval_t *kv, void *user_data)
{
    gchar *val = NULL;
    size_t size;
    bundle_keyval_get_basic_val ((bundle_keyval_t*)kv, (void**)&val, &size);
    g_debug ("       %s - %s", key, val);
}

void (_on_child_got_message)(int port_id, const char* remote_app_id, const char* remote_port, gboolean trusted_message, bundle* data)
{
    gchar *name = NULL;
    messageport_get_local_port_name (port_id, &name),
    g_debug ("CHILD: GOT MESSAGE at prot '%s' FROM :'%s' - '%s", name,
        remote_app_id ? remote_app_id : "unknwon app", remote_port ? remote_port : "unknwon");
    g_free (name);
    g_assert (data);

    bundle_foreach (data, _dump_data, NULL);

    /* Write acknoledgement */
    if (write (__pipe[1], "OK", strlen("OK") + 1) < 3) {
        g_warning ("WRITE failed");
    }

    if (__test_data) {
        __test_data->result = TRUE;
        g_main_loop_quit (__test_data->m_loop);
    }
}

void (_on_parent_got_message)(int port_id, const char* remote_app_id, const char* remote_port, gboolean trusted_message, bundle* data)
{
    gchar *name = NULL;
    gboolean found = FALSE;
    messageport_get_local_port_name (port_id, &name),
    g_debug ("PARENT: GOT MESSAGE at prot %s FROM :'%s' app - '%s' port", name,
        remote_app_id ? remote_app_id : "unknwon", remote_port ? remote_port : "unknwon");
    g_free (name);

    g_assert (data);

    bundle_foreach (data, _dump_data, NULL);

    /* Write acknoledgement */
    if ( write (__pipe[1], "OK", strlen("OK") + 1) < 3) {
        g_warning ("WRITE failed");
    }

    /* check message is coming from remote port to send back to message,
     * if not ignore */
    if (!remote_app_id || !remote_port) {
        return;
    }

    messageport_error_e res = trusted_message ? messageport_check_trusted_remote_port (remote_app_id, remote_port, &found)
                                              : messageport_check_remote_port (remote_app_id, remote_port, &found);
    if (!found) {
        g_warning ("PARENT: Could not found remote port (%d)", res);
        return ;
    }

    g_debug ("PARENT: Found remote prot");

    bundle *reply = bundle_create ();

    bundle_add (reply, "Results", "GOT_IT");

    g_debug ("PARENT: Sending reply ....");
    res = trusted_message ? messageport_send_trusted_message (remote_app_id, remote_port, reply)
                          : messageport_send_message (remote_app_id, remote_port, reply);
    bundle_free (reply);
    if (res != MESSAGEPORT_ERROR_NONE)
    {
        g_warning ("PARENT: Faile to send message to server : %d", res);
    }
    else g_debug ("PARENT: Data sent successfully");
}

int _register_test_port (const gchar *port_name, gboolean is_trusted, messageport_message_cb cb)
{
    int port_id = is_trusted ? messageport_register_trusted_local_port (port_name, cb)
                             : messageport_register_local_port (port_name, cb);

    return port_id;
}

static gboolean
test_register_local_port ()
{
    int port_id =  _register_test_port (PARENT_TEST_PORT, FALSE, _on_parent_got_message);

    test_assert (port_id >= 0, "Failed to register port '%s', error : %d", PARENT_TEST_PORT, port_id);

    return TRUE;
}

static gboolean
test_register_trusted_local_port()
{
    int port_id =  _register_test_port (PARENT_TEST_TRUSTED_PORT, TRUE, _on_parent_got_message);

    test_assert (port_id >= 0, "Failed to register port '%s', error : %d", PARENT_TEST_TRUSTED_PORT, port_id);

    return TRUE;
}

static gboolean
test_check_remote_port()
{
    gchar remote_app_id[128];
    gboolean found = FALSE;
    messageport_error_e res;

    g_sprintf (remote_app_id, "%d", getppid());

    res = messageport_check_remote_port (remote_app_id, PARENT_TEST_PORT, &found);

    test_assert (res == MESSAGEPORT_ERROR_NONE, "Fail to find remote port '%s' at app_id '%s', error: %d", PARENT_TEST_PORT, remote_app_id, res);

    return TRUE;
}

static gboolean
test_check_trusted_remote_port()
{
    gchar remote_app_id[128];
    gboolean found = FALSE;
    messageport_error_e res;

    g_sprintf (remote_app_id, "%d", getppid());

    res = messageport_check_trusted_remote_port (remote_app_id, PARENT_TEST_TRUSTED_PORT, &found);
    test_assert (res == MESSAGEPORT_ERROR_NONE, "Fail to find trusted remote port '%s' at app_id '%s', error: %d", PARENT_TEST_TRUSTED_PORT, remote_app_id, res);

    return TRUE;
}

static gboolean
test_send_message()
{
    messageport_error_e res;
    gchar remote_app_id[128];
    bundle *b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");

    g_sprintf (remote_app_id, "%d", getppid());
    res = messageport_send_message (remote_app_id, PARENT_TEST_PORT, b);
    bundle_free (b);
    test_assert (res == MESSAGEPORT_ERROR_NONE, "Fail to send message to port '%s' at app_id : '%s', error : %d", PARENT_TEST_PORT, remote_app_id, res);

    gchar result[32];

    test_assert ((read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert ((g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    return TRUE;
}

static gboolean
test_send_trusted_message()
{
    messageport_error_e res;
    gchar remote_app_id[128];
    bundle *b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");

    g_sprintf (remote_app_id, "%d", getppid());
    res = messageport_send_trusted_message (remote_app_id, PARENT_TEST_TRUSTED_PORT, b);
    bundle_free (b);
    test_assert (res == MESSAGEPORT_ERROR_NONE, "Fail to send message to port '%s' at app_id : '%s', error : %d", PARENT_TEST_PORT, remote_app_id, res);

    gchar result[32];

    test_assert( (read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert( (g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    return TRUE;
}

static gboolean
_update_test_result (gpointer data)
{
    if (__test_data) {
        __test_data->result = FALSE;
        g_main_loop_quit (__test_data->m_loop);
    }

    return FALSE;
}

static gboolean
test_send_bidirectional_message()
{
    messageport_error_e res;
    int local_port_id = 0;
    gchar remote_app_id[128];
    gchar result[32];
    gboolean child_got_message = FALSE;
    bundle *b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");

    child_got_message = FALSE;

    /* register local message port for return message */
    test_assert ((local_port_id = _register_test_port (CHILD_TEST_PORT, FALSE, _on_child_got_message)) > 0,
        "Fail to register message port");

    g_sprintf (remote_app_id, "%d", getppid());
    res = messageport_send_bidirectional_message (local_port_id, remote_app_id, PARENT_TEST_PORT, b);
    bundle_free (b);
    test_assert (res == MESSAGEPORT_ERROR_NONE,
        "Fail to send message to port '%s' at app_id : '%s', error : %d", PARENT_TEST_PORT, remote_app_id, res);


    test_assert( (read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert( (g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    __test_data = g_new0 (struct AsyncTestData, 1);
    __test_data->m_loop = g_main_loop_new (NULL, FALSE);
    g_timeout_add_seconds (5, _update_test_result, NULL);

    g_main_loop_run (__test_data->m_loop);
    child_got_message = __test_data->result;

    g_main_loop_unref (__test_data->m_loop);
    g_free (__test_data);
    __test_data = NULL;

    test_assert (child_got_message == TRUE, "Child did not recieved reply");

    return TRUE;
}

static gboolean
test_send_bidirectional_trusted_message()
{
    messageport_error_e res;
    int local_port_id = 0;
    gchar remote_app_id[128];
    gchar result[32];
    gboolean child_got_message = FALSE;
    bundle *b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");

    child_got_message = FALSE;

    /* register local message port for return message */
    test_assert ((local_port_id = _register_test_port (CHILD_TEST_TRUSTED_PORT, FALSE, _on_child_got_message)) > 0,
        "Fail to register message port");

    g_sprintf (remote_app_id, "%d", getppid());
    res = messageport_send_bidirectional_trusted_message (local_port_id, remote_app_id, PARENT_TEST_TRUSTED_PORT, b);
    bundle_free (b);
    test_assert (res == MESSAGEPORT_ERROR_NONE,
        "Fail to send message to port '%s' at app_id : '%s', error : %d", PARENT_TEST_TRUSTED_PORT, remote_app_id, res);


    test_assert( (read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert( (g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    __test_data = g_new0 (struct AsyncTestData, 1);
    __test_data->m_loop = g_main_loop_new (NULL, FALSE);
    g_timeout_add_seconds (5, _update_test_result, NULL);

    g_main_loop_run (__test_data->m_loop);
    child_got_message = __test_data->result;

    g_main_loop_unref (__test_data->m_loop);
    g_free (__test_data);
    __test_data = NULL;

    test_assert (child_got_message == TRUE, "Child did not recieved reply");

    return TRUE;
}

static gboolean
test_get_local_port_name()
{
    int local_port_id = 0;
    messageport_error_e res;
    gchar *port_name = NULL;

    test_assert ((local_port_id = _register_test_port (CHILD_TEST_TRUSTED_PORT, FALSE, _on_child_got_message)) > 0,
        "Fail to register test port : error : %d", local_port_id);
    
    res = messageport_get_local_port_name (local_port_id, &port_name);
    test_assert (res == MESSAGEPORT_ERROR_NONE, "Failed to get message port name, error: %d", res);

    test_assert (g_strcmp0 (port_name, CHILD_TEST_TRUSTED_PORT) == 0, "Got wrong port name");

    return TRUE;
}

static gboolean
test_check_trusted_local_port ()
{
    int local_port_id = 0;
    messageport_error_e res;
    gboolean is_trusted;

    test_assert ((local_port_id = _register_test_port (CHILD_TEST_PORT, FALSE, _on_child_got_message)) > 0,
        "Fail to register test port : error : %d", local_port_id);
    
    res = messageport_check_trusted_local_port (local_port_id, &is_trusted);
    test_assert (res == MESSAGEPORT_ERROR_NONE, "Failed to get message port name, error: %d", res);
    test_assert (is_trusted == FALSE, "Go FLSE for trusted port");

    test_assert ((local_port_id = _register_test_port (CHILD_TEST_TRUSTED_PORT, TRUE, _on_child_got_message)) > 0,
        "Fail to register test port : error : %d", local_port_id);
    
    res = messageport_check_trusted_local_port (local_port_id, &is_trusted);
    test_assert (res == MESSAGEPORT_ERROR_NONE, "Failed to get message port name, error: %d", res);
    test_assert (is_trusted == TRUE, "Go TRUE for untrusted port");

    return TRUE;
}


static gboolean
_on_term (gpointer userdata)
{
    g_main_loop_quit ((GMainLoop *)userdata);

    return FALSE;
}

static gboolean
test_setup ()
{
#ifdef USE_SESSION_BUS
    GIOChannel *channel = NULL;
    gchar *bus_address = NULL;
    gint tmp_fd = 0;
    gint pipe_fd[2];
    gchar *argv[4] ;
    gsize len = 0;
    const gchar *dbus_monitor = NULL;
    GError *error = NULL;

    argv[0] = "dbus-daemon";
    argv[1] = "--print-address=<<fd>>";
    argv[2] = "--config-file="TEST_DBUS_DAEMON_CONF_FILE;
    argv[3] = NULL;

    if (pipe(pipe_fd)== -1) {
        GSpawnFlags flags = G_SPAWN_SEARCH_PATH;
        argv[1] = g_strdup_printf ("--print-address=1");
        g_spawn_async_with_pipes (NULL, argv, NULL, flags, NULL, NULL, &__daemon_pid, NULL, NULL, &tmp_fd, &error);
    } else {
        GSpawnFlags flags = (GSpawnFlags)(G_SPAWN_SEARCH_PATH | G_SPAWN_LEAVE_DESCRIPTORS_OPEN);
        tmp_fd = pipe_fd[0];
        argv[1] = g_strdup_printf ("--print-address=%d", pipe_fd[1]);
        g_spawn_async (NULL, argv, NULL, flags, NULL, NULL, &__daemon_pid, &error);
        g_free (argv[1]);
    }
    test_assert (error == NULL, "Failed to span daemon : %s", error->message);
    test_assert (__daemon_pid != 0, "Failed to get daemon pid");
    sleep (5); /* 5 seconds */

    channel = g_io_channel_unix_new (tmp_fd);
    g_io_channel_read_line (channel, &bus_address, NULL, &len, &error);
    test_assert (error == NULL, "Failed to daemon address : %s", error->message);
    g_io_channel_unref (channel);

    if (pipe_fd[0]) close (pipe_fd[0]);
    if (pipe_fd[1]) close (pipe_fd[1]);

    if (bus_address) bus_address[len] = '\0';
    test_assert (bus_address != NULL && bus_address[0] != 0, "Failed to get dbus-daemon address");

    setenv("DBUS_SESSION_BUS_ADDRESS", bus_address, TRUE);

    g_print ("Dbus daemon start at : %s\n", bus_address);

    g_free (bus_address);
#endif /* USE_SESSION_BUS */

    return TRUE;
}

static void
test_cleanup ()
{
#ifdef USE_SESSION_BUS
   if (__daemon_pid) kill (__daemon_pid, SIGTERM);
#endif /* USE_SESSION_BUS */
}


int main (int argc, char *argv[])
{
    pid_t child_pid;

    if (!test_setup()) {
        g_error ("Could not start session bus!!! \n");
        return -1;
    }

    if (pipe (__pipe)) {
        g_warning ("Failed to open pipe");
        return -1;
    }

    child_pid = fork ();
    
    if (child_pid < 0) {
        g_error ("Failed to fork ");
    }
    else if (child_pid > 0)  {
        /* parent process */
        GMainLoop *m_loop = g_main_loop_new (NULL, FALSE);
        /* server ports */
        TEST_CASE(test_register_local_port);
        TEST_CASE(test_register_trusted_local_port);
        TEST_CASE(test_get_local_port_name);
        TEST_CASE(test_check_trusted_local_port);

        g_unix_signal_add (SIGTERM, _on_term, m_loop);

        g_main_loop_run (m_loop);
        g_main_loop_unref (m_loop);
    }
    else {
        /* child process */
        /* sleep sometime till server ports are ready */
        sleep (3);

        TEST_CASE(test_check_remote_port);
        TEST_CASE(test_check_trusted_remote_port);
        TEST_CASE(test_send_message);
        TEST_CASE(test_send_bidirectional_message);
        TEST_CASE(test_send_trusted_message);
        TEST_CASE(test_send_bidirectional_trusted_message);

        /* end of tests */
        kill(getppid(), SIGTERM);

    }

    test_cleanup();

    return 0;
}

