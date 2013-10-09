noinst_LTLIBRARIES = libmessageport-dbus-glue.la  libmessageport-common.la
NULL = 

if USE_SESSION_BUS
dbus-server-glue.c dbus-server-glue.h : org.tizen.messageport.Server.xml
	$(AM_V_GEM)gdbus-codegen                                \
        --interface-prefix org.tizen.messageport \
        --c-namespace      MsgPort_Dbus_Glue     \
        --generate-c-code  dbus-server-glue     \
        $<
endif

dbus-manager-glue.c dbus-maanager-glue.h : org.tizen.messageport.Manager.xml
	$(AM_V_GEM)gdbus-codegen                                \
        --interface-prefix org.tizen.messageport \
        --c-namespace      MsgPort_Dbus_Glue     \
        --generate-c-code  dbus-manager-glue     \
        $<

dbus-service-glue.c dbus-service-glue.h : org.tizen.messageport.Service.xml
	$(AM_V_GEM)gdbus-codegen                                \
        --interface-prefix org.tizen.messageport \
        --c-namespace      MsgPort_Dbus_Glue     \
        --generate-c-code  dbus-service-glue     \
        $<

#
# libmessageport-dbus-glue.la
#
libmessageport_dbus_glue_la_SOURCES = \
    dbus-manager-glue.h \
    dbus-manager-glue.c \
    dubs-service-glue.h \
    dbus-service-glue.c \
    $(NULL)

if USE_SESSION_BUS
libmessageport_dbus_glue_la_SOURCES += \
    dbus-server-glue.h \
    dbus-server-glue.c \
    $(NULL)
endif
    
libmessageport_dbus_glue_la_CPPFLAGS = \
    -I$(top_builddir) \
    $(GLIB_CFLAGS) $(GIO_CFLAGS) $(GIOUNIX_CFLAGS) $(DLOG_CFLAGS) \
    $(NULL)

libmessageport_dbus_glue_la_LIBADD = \
    $(GLIB_LIBS) $(GIO_LIBS) $(GIOUNIX_LIBS) $(DLOG_LIBS) \
    $(NULL)


#
# libmessageport-common.la
#
libmessageport_common_la_SOURCES = \
    dbus-error.h \
    dbus-error.c \
    $(NULL)

libmessageport_common_la_CPPFLAGS = \
    -I$(top_builddir) \
    $(GLIB_CFLAGS) $(GIO_CFLAGS) $(GIOUNIX_CFLAGS) \
    $(NULL)

libmessageport_common_la_LIBADD = \
    ./libmessageport-dbus-glue.la \
    $(GLIB_LIBS) $(GIO_LIBS) $(GIOUNIX_LIBS) \
    $(NULL)

CLEANFILES = 
