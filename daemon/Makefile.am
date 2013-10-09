bin_PROGRAMS = messageportd
NULL = 

if USE_SESSION_BUS
servicedir = $(datadir)/dbus-1/services
service_DATA = org.tizen.messageport.service
endif

messageportd_SOURCES = \
    dbus-service.h \
    dbus-service.c \
    dbus-manager.h \
    dbus-manager.c \
    dbus-server.h \
    dbus-server.c \
    manager.h \
    manager.c \
    main.c \
    $(NULL)

messageportd_CPPFLAGS = \
    -I$(top_builddir) \
    -DLOG_TAG=\"MESSAGEPORT/DAEMON\" \
    $(GLIB_CLFAGS) $(GIO_CFLAGS) $(AUL_CFLAGS) $(PKGMGRINFO_CFLAGS) $(DLOG_CFLAGS) \
    $(NULL)

messageportd_LDADD = \
    ../common/libmessageport-common.la \
    $(GLIB_LIBS) $(GIO_LIBS) $(AUL_LIBS) $(PKGMGRINFO_LIBS) $(DLOG_LIBS) \
    $(NULL)

CLEANFILES = 
