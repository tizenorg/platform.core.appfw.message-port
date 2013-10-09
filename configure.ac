#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.60])
AC_INIT([message-port], [1.0.0], [http://bugs.tizen.org/jira], [], [])
AC_CONFIG_SRCDIR([daemon/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.11 nostdinc silent-rules subdir-objects tar-pax -Wno-portability])
LT_INIT([disable-static])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.30])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES([GIO],[gio-2.0])
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

PKG_CHECK_MODULES([GIOUNIX],[gio-unix-2.0])
AC_SUBST(GIOUNIX_CFLAGS)
AC_SUBST(GIOUINX_LIBS)

PKG_CHECK_MODULES([AUL], [aul])
AC_SUBST(AUL_CFLAGS)
AC_SUBST(AUL_LIBS)

PKG_CHECK_MODULES([PKGMGRINFO], [pkgmgr-info])
AC_SUBST(PKGMGRINFO_CFLAGS)
AC_SUBST(PKGMGRINFO_LIBS)

PKG_CHECK_MODULES([BUNDLE], [bundle])
AC_SUBST(BUNDLE_CFLAGS)
AC_SUBST(BUNDLE_LIBS)

PKG_CHECK_MODULES([DLOG], [dlog], [AC_DEFINE([HAVE_DLOG], [1], [Use DLOG])])
AC_SUBST(DLOG_CFLAGS)
AC_SUBST(DLOG_LIBS)

AC_DEFINE(MESSAGEPORT_BUS_ADDRESS, 
         ["unix:path=%s/.message-port", "/tmp"],
         [messageport daemon server socket address])

# Use Session bus for daemon activation
AC_ARG_ENABLE(sessionbus,
             [  --enable-sessionbus     Use Session bus for activation],
             [enable_sessionbus=$enableval], [enable_sessionbus=no])
AM_CONDITIONAL(USE_SESSION_BUS, [test "x$enable_sessionbus" = "xyes"])
if test "x$enable_sessionbus" = "xyes" ; then
    AC_DEFINE(USE_SESSION_BUS, [1], [Use session bus])
fi

# Enable Debug
AC_ARG_ENABLE(debug, 
              [  --enable-debug         Eenable debug features],
              [enable_debug=$enableval], [enable_debug=no])
if test "x$enable_debug" = "xyes" ; then
    AC_DEFINE(ENABLE_DEBUG, [1], [Enable debug features])
    AC_DEFINE_UNQUOTED([TEST_DBUS_DAEMON_CONF_FILE],
                       ["`pwd`/tests/test-dbus-daemon.conf"],
                       [dbus configuration for tests])
else
    AC_DEFINE([TEST_DBUS_DAEMON_CONF_FILE],
              ["/etc/dbus-1/session.conf"],
              [dbus configuration for tests])
fi

# build tests
AC_ARG_ENABLE(tests,
              [  --enable-tests      Build unit tests],
              [enable_tests=$enable_tests], [enable_tests=no])
AM_CONDITIONAL(BUILD_TESTS, [test "x$enable_tests" = "xyes"])
AC_PROG_CXX

# Checks for header files.
AC_CHECK_HEADERS([string.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT([
Makefile
common/Makefile
daemon/Makefile
lib/Makefile
lib/message-port.pc
messageportd.service
])

if test "x$enable_sessionbus" = "xyes"; then
    AC_OUTPUT([
    daemon/org.tizen.messageport.service
    ])
fi

if test "x$enable_tests" = "xyes"; then
    AC_OUTPUT([
    tests/Makefile
    ])
    if test "x$enable_sessionbus" = "xyes"
       -a "x$enable_debug" == "xyes" ; then
        AC_OUTPUT([
        tests/test-dbus-daemon.conf
        tests/services/org.tizen.messageport.service
        ])
    fi
fi

