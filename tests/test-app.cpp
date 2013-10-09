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
#include <message-port.h>
#include <bundle.h>       // bundle 
#include <string>         // std::string
#include <map>            // std::map
#include <iostream>       // cout, cerr
#include <unistd.h>       // pipe ()
#include <stdio.h>        // 
#include <glib.h>
#include <glib-unix.h>    // g_unix_signal_add()

using namespace std;

struct AsyncTestData {
    GMainLoop *m_loop;
    bool result;
}; 
static int __pipe[2];
#ifdef USE_SESSION_BUS
static pid_t __daemon_pid = 0;
#endif // USE_SESSION_BUS

#define TEST_PARENT_PORT "test-parent-port"
#define TEST_PARENT_TRUSTED_PORT "test-parent-trusted-port"
#define TEST_CHILD_PORT  "test-child-port"
#define TEST_CHILD_TRUSTED_PORT "test-child-trusted-port"

#define TEST_CASE(case) \
    do { \
        if (case() != true) { \
            cerr << #case << ": FAIL\n"; \
            return -1; \
        } \
        else cout << #case << ": SUCCESS\n"; \
    }while (0)


#define test_assert(expr, msg) \
    do { \
        if ((expr) == false) {\
            cerr << __FUNCTION__ << "-" << __LINE__ << ": assert(" << #expr << ") : " << msg << "\n"; \
            return false; \
        } \
    } while(0);


std::string toString (int a)
{
    char str[256];

    snprintf (str, 255, "%d", a);

    return std::string(str);
}

std::string toString (messageport_error_e err)
{
    return toString ((int)err);
}

class RemotePort;

class LocalPort {

protected:
    static void onMessage (int portId, const char *remoteAppId, const char *remotePort, bool isTrusted, bundle *message);

public:
    typedef void (*MessageHandler)(LocalPort *port, bundle *message, RemotePort *remotePort, void *userdata);

    LocalPort (const std::string &name, bool is_trusted, LocalPort::MessageHandler message_handler, void *userdata)
        : m_name (name), m_trusted(is_trusted), m_msgCb(message_handler), m_cbData(userdata) {
        if (Register ()) {
            cachedPorts[m_portId] = this;
        }
    }

    ~LocalPort() { 
        cachedPorts.erase(m_portId);
    }

    bool Register () {
        int res ;
        res = m_trusted ? messageport_register_trusted_local_port (m_name.c_str(), onMessage)
                        : messageport_register_local_port (m_name.c_str(), onMessage);

        if (res < 0) {
            cerr << "Failed to register port '"<< m_name << "'";
            m_err = (messageport_error_e) res;
            return false;
        }
        
        m_portId = res;

        return true;
    }

    bool SendMessage (const std::string &app_id, const std::string &port_name, bool is_trusted, bundle *data)
    {
        m_err = is_trusted ? messageport_send_bidirectional_trusted_message (m_portId, app_id.c_str(), port_name.c_str(), data)
                         : messageport_send_bidirectional_message (m_portId, app_id.c_str(), port_name.c_str(), data);
        if (m_err < 0) {
            cerr << "Fail to send bidirectional message to '" << app_id << "/" << port_name << ":" << m_err ;
            return false;
        }

        return true;
    }

    const std::string& name () const {
        return m_name;
    }

    bool isTrusted () const {
        return m_trusted;
    }

    int id () const {
        return m_portId;
    }

    messageport_error_e lastError () {
        return (messageport_error_e) m_err;
    }

private:
    string m_name;
    bool   m_trusted;
    int    m_portId;
    int    m_err;
    LocalPort::MessageHandler m_msgCb;
    void  *m_cbData;

    static std::map<int,LocalPort*> cachedPorts ;
};
std::map<int,LocalPort*> LocalPort::cachedPorts ;

class RemotePort {
public:
    RemotePort (const string &appId, const string &portName, bool isTrusted)
        :m_appId(appId), m_portName(portName), m_isTrusted (isTrusted), m_isValid (false)
    {
        m_err = isTrusted ? messageport_check_trusted_remote_port (appId.c_str(), portName.c_str(), &m_isValid)
                          : messageport_check_remote_port (appId.c_str(), portName.c_str(), &m_isValid);
        if (m_err != MESSAGEPORT_ERROR_NONE) {
            cerr << std::string ("Fail to find remote port '") + appId + "', '" + portName + "': error : " + toString (m_err) + "\n";
        }
    }

    ~RemotePort () { }

    bool sendMessage (bundle *b) {
        
        m_err = m_isTrusted ? messageport_send_trusted_message (m_appId.c_str(), m_portName.c_str(), b)
                            : messageport_send_message (m_appId.c_str(), m_portName.c_str(), b);

        return m_err == MESSAGEPORT_ERROR_NONE;
    }

    bool sendBidirectionalMessage (bundle *b, const LocalPort &port) {
        m_err = m_isTrusted ? messageport_send_bidirectional_trusted_message (port.id(), m_appId.c_str(), m_portName.c_str(), b)
                            : messageport_send_bidirectional_message (port.id(), m_appId.c_str(), m_portName.c_str(), b);
        return m_err == MESSAGEPORT_ERROR_NONE;
    }

    bool isValid () const {
        return m_isValid;
    }

    messageport_error_e lastError () const {
        return m_err;
    }

    const string & appId () const {
        return m_appId;
    }

    const string & portName () const {
        return m_portName;
    }

    bool isTrusted () const {
        return m_isTrusted;
    }
private:
    string m_appId;
    string m_portName;
    bool   m_isTrusted;
    messageport_error_e m_err;
    bool   m_isValid;
};

void LocalPort::onMessage (int portId, const char *remoteAppId, const char *portName, bool isTrusted, bundle *message)
{
    LocalPort * port = LocalPort::cachedPorts[portId];
    if (port) {
        RemotePort *remotePort = NULL;
        if (remoteAppId && portName)
            remotePort = new RemotePort (string(remoteAppId), string(portName), isTrusted);
        port->m_msgCb (port, message, remotePort, port->m_cbData);

        delete remotePort;
    }
    else cerr <<"No cached Port found\n" ;
}

static void
_onParentGotMessage (LocalPort *port, bundle *data, RemotePort *remotePort, void *userdata)
{
    /* Write acknoledgement */
    string ok("OK");
    int len = ok.length() + 1;
    if ( write (__pipe[1], ok.c_str(), len) < len) {
        cerr << "WRITE failed" ;
    }

    if (remotePort) {
        bundle *reply = bundle_create ();
        bundle_add (reply, "Results", "GOT_IT");
        remotePort->sendMessage (reply);

        bundle_free (reply);
    }
}

static void
_onChildGotMessage (LocalPort *port, bundle *data, RemotePort *remotePort, void *userdata)
{
    AsyncTestData *test_data = (AsyncTestData *)userdata;
    string ack("OK");
    int len = ack.length () + 1;
    /* Write acknoledgement */
    if (write (__pipe[1], ack.c_str(), len) < len) {
        cerr << "WRITE to pipe failed";
    }

    if (test_data) {
        test_data->result = TRUE;
        g_main_loop_quit (test_data->m_loop);
    }

}

static bool
test_register_local_port ()
{
    static LocalPort *port = new LocalPort(TEST_PARENT_PORT, false, _onParentGotMessage, NULL);

    test_assert (port->Register() == true, "Failed to register port : " + toString(port->lastError ()));

    return true;
}

static bool
test_register_trusted_local_port ()
{
    static LocalPort *trused_port = new LocalPort(TEST_PARENT_TRUSTED_PORT, true, _onParentGotMessage, NULL);

    test_assert (trused_port->Register() == true, "Failed to regiser trusted port :" + toString (trused_port->lastError ()));

    return true;
}

static gboolean
test_get_local_port_name()
{
    LocalPort port("dummy_port", false, _onParentGotMessage, NULL);
    test_assert (port.Register() == true, "Failed to regiser trusted port :" + toString (port.lastError ()));
    test_assert (port.name() == "dummy_port", "Wrong port name : " + port.name());
 
    LocalPort trusted_port("dummy_trusted_port", true, _onParentGotMessage, NULL);
    test_assert (trusted_port.Register() == true, "Failed to regiser trusted port :" + toString (trusted_port.lastError ()));
    test_assert (trusted_port.name() == "dummy_trusted_port", "Wrong port name : " + trusted_port.name());

    return true;
}

static gboolean
test_check_trusted_local_port ()
{
    LocalPort port("dummy_port", false, _onParentGotMessage, NULL);
    test_assert (port.Register() == true, "Failed to regiser trusted port :" + toString (port.lastError ()));
    test_assert (port.isTrusted() == false, "Wrong port type : " + port.isTrusted());

    LocalPort trusted_port("dummy_trusted_port", true, _onParentGotMessage, NULL);
    test_assert (trusted_port.Register() == true, "Failed to regiser trusted port :" + toString (trusted_port.lastError ()));
    test_assert (trusted_port.isTrusted() == true, "Wrong port type : " + trusted_port.isTrusted());

    return true;
}

static bool
test_check_remote_port ()
{
    RemotePort p(toString(getppid()), TEST_PARENT_PORT, false);

    test_assert (p.isValid() == true, "Could not get remote port : " + toString(p.lastError()));

    return true;
}

static bool
test_check_remote_trusted_port ()
{
    RemotePort p(toString(getppid()), TEST_PARENT_TRUSTED_PORT, true);

    test_assert (p.isValid() == true, "Could not get remote trusted port : " + toString(p.lastError()));

    return true;
}

static bool
test_send_message ()
{
    bool res;
    bundle *b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");

    RemotePort port (toString (getppid()), TEST_PARENT_PORT, false);

    res = port.sendMessage (b);
    bundle_free (b);
    test_assert (res == true, std::string("Fail to send message to port '") + 
                              TEST_PARENT_PORT + "' at app_id : '" + toString(getppid()) +
                              "', error : " + toString (port.lastError()));

    gchar result[32];

    test_assert ((read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert ((g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    return true;
}

static bool
test_send_trusted_message ()
{
    bool res;
    bundle *b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");

    RemotePort port (toString (getppid()), TEST_PARENT_TRUSTED_PORT, true);

    res = port.sendMessage (b);
    bundle_free (b);
    test_assert (res == true, std::string("Fail to send trusted message to port '") + 
                              TEST_PARENT_TRUSTED_PORT + "' at app_id : '" + toString(getppid()) +
                              "', error : " + toString (port.lastError()));

    gchar result[32];
    test_assert ((read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert ((g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    return true;
}

static gboolean
_update_test_result (gpointer userdata)
{
    AsyncTestData *test_data = (AsyncTestData *)userdata;
    test_data->result = false;
    g_main_loop_quit (test_data->m_loop);

    return FALSE;
}

static bool
test_send_bidirectional_message ()
{
    bool res;
    bundle *b = NULL;;
    AsyncTestData *test_data = new AsyncTestData();
    test_data->m_loop = g_main_loop_new (NULL, FALSE);

    LocalPort localPort(TEST_CHILD_PORT, false, _onChildGotMessage, test_data);

    test_assert (localPort.Register() == true, "Failed to register local port: Error: " + toString(localPort.lastError()));

    RemotePort remotePort (toString (getppid()), TEST_PARENT_PORT, false);

    test_assert (remotePort.isValid() == true, "Invalid remote port, Erorr: " + toString(remotePort.lastError()));

    b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");
    res = remotePort.sendBidirectionalMessage (b, localPort);
    bundle_free (b);

    test_assert (res == true, "Fail to send bidirectional message , Error : " + toString(remotePort.lastError()));

    gchar result[32];
    test_assert ((read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert ((g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    g_timeout_add_seconds (5, _update_test_result, test_data);

    g_main_loop_run (test_data->m_loop);
    bool child_got_message = test_data->result;

    g_main_loop_unref (test_data->m_loop);
    delete test_data ;

    test_assert (child_got_message == true, "Timeout, Child did not recieved reply");

    return true;
}

static bool
test_send_bidirectional_trusted_message()
{
    bool res;
    bundle *b = NULL;;
    AsyncTestData *test_data = new AsyncTestData();
    test_data->m_loop = g_main_loop_new (NULL, FALSE);

    LocalPort localPort(TEST_CHILD_TRUSTED_PORT, true, _onChildGotMessage, test_data);
    test_assert (localPort.Register() == true, "Failed to register trusted local port: Error: " + toString(localPort.lastError()));

    RemotePort remotePort (toString (getppid()), TEST_PARENT_TRUSTED_PORT, true);
    test_assert (remotePort.isValid() == true, "Invalid remote port, Erorr: " + toString(remotePort.lastError()));

    b = bundle_create ();
    bundle_add (b, "Name", "Amarnath");
    bundle_add (b, "Email", "amarnath.valluri@intel.com");
    res = remotePort.sendBidirectionalMessage (b, localPort);
    bundle_free (b);

    test_assert (res == true, "Fail to send bidirectional message , Error : " + toString(remotePort.lastError()));

    gchar result[32];
    test_assert ((read (__pipe[0], &result, sizeof(result)) > 0), "Parent did not received the message");
    test_assert ((g_strcmp0 (result, "OK") == 0), "Parent did not received the message");

    g_timeout_add_seconds (5, _update_test_result, test_data);

    g_main_loop_run (test_data->m_loop);
    bool child_got_message = test_data->result;

    g_main_loop_unref (test_data->m_loop);
    delete test_data ;

    test_assert (child_got_message == true, "Timeout, Child did not recieved reply");

    return true;
}

static gboolean
_on_term (gpointer userdata)
{
    g_main_loop_quit ((GMainLoop *)userdata);

    return FALSE;
}

static bool
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

    argv[0] = const_cast<gchar*>("dbus-daemon");
    argv[1] = const_cast<gchar*>("--config-file="TEST_DBUS_DAEMON_CONF_FILE);
    argv[2] = const_cast<gchar*>("--print-address=<<fd>>");
    argv[3] = NULL;

    if (pipe(pipe_fd)== -1) {
    	GSpawnFlags flags = G_SPAWN_SEARCH_PATH;
        cerr << "Failed to open temp file :" << error->message;
        argv[2] = g_strdup_printf ("--print-address=1");
        g_spawn_async_with_pipes (NULL, argv, NULL, flags, NULL, NULL, &__daemon_pid, NULL, NULL, &tmp_fd, &error);
    } else {
        GSpawnFlags flags = (GSpawnFlags)(G_SPAWN_SEARCH_PATH | G_SPAWN_LEAVE_DESCRIPTORS_OPEN);
        tmp_fd = pipe_fd[0];
        argv[2] = g_strdup_printf ("--print-address=%d", pipe_fd[1]);
        g_spawn_async (NULL, argv, NULL, flags, NULL, NULL, &__daemon_pid, &error);
        g_free (argv[2]);
    }
    test_assert (error == NULL, std::string("Failed to span daemon : ") + error->message);
    test_assert (__daemon_pid != 0, "Failed to get daemon pid");
    sleep (5); /* 5 seconds */

    channel = g_io_channel_unix_new (tmp_fd);
    g_io_channel_read_line (channel, &bus_address, NULL, &len, &error);
    test_assert (error == NULL, "Failed to daemon address : " << error->message);
    g_io_channel_unref (channel);

    if (pipe_fd[0]) close (pipe_fd[0]);
    if (pipe_fd[1]) close (pipe_fd[1]);

    if (bus_address) bus_address[len] = '\0';
    test_assert (bus_address != NULL && bus_address[0] != 0, "Failed to get dbus-daemon address");

    cout << "Dbus daemon start at : " << bus_address << "\n";

    setenv("DBUS_SESSION_BUS_ADDRESS", bus_address, TRUE);

    g_free (bus_address);
#endif /* USE_SESSION_BUS */

    return true;
}

static void
test_cleanup ()
{
#ifdef USE_SESSION_BUS
    if (__daemon_pid) kill (__daemon_pid, SIGTERM);
#endif /* USE_SESSION_BUS */
}

int main (int argc, const char *argv[])
{
    pid_t child_pid;

    if (test_setup () != true) {
        cerr << "Test setup failur!!!\n";
        return -1;
    }

    if (pipe(__pipe) < 0) {
        cerr << "Failed to create pipe. Cannot run tests!!!" ;
        return -1;
    }
    child_pid = fork ();
    if ( child_pid < 0) {
        cerr << "Failed to fork process, Cannot run tests!!!";
        return -1;
    }
     else if (child_pid != 0) 
    {
        /* parent process */
        GMainLoop *m_loop = g_main_loop_new (NULL, FALSE);

        TEST_CASE (test_register_local_port);
        TEST_CASE (test_register_trusted_local_port);
        TEST_CASE(test_get_local_port_name);
        TEST_CASE(test_check_trusted_local_port); 

        g_unix_signal_add (SIGTERM, _on_term, m_loop);

        g_main_loop_run (m_loop);
        g_main_loop_unref (m_loop);
    }
    else {
        /* child porcess */
        sleep (3);
        TEST_CASE(test_check_remote_port);
        TEST_CASE(test_check_remote_trusted_port);
        TEST_CASE(test_send_message); 
        TEST_CASE(test_send_bidirectional_message);
        TEST_CASE(test_send_trusted_message);
        TEST_CASE(test_send_bidirectional_trusted_message);

        kill (getppid(), SIGTERM);
    }
    test_cleanup ();

    return 0;
}

