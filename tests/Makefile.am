if BUILD_TESTS
bin_PROGRAMS = msgport-test-app msgport-test-app-cpp

msgport_test_app_SOURCES = test-app.c 
msgport_test_app_LDADD = ../lib/libmessage-port.la $(GLIB_LIBS) $(BUNDLE_LIBS) $(DLOG_LIBS)
msgport_test_app_CPPFLAGS  = -I../lib/ -I ../ $(GLIB_CFLAGS) $(BUNDLE_CFLAGS) $(DLOG_CFLAGS)

msgport_test_app_cpp_SOURCES = test-app.cpp
msgport_test_app_cpp_LDADD = ../lib/libmessage-port.la $(GLIB_LIBS) $(BUNDLE_LIBS) $(DLOG_LIBS)
msgport_test_app_cpp_CXXFLAGS  = -I../lib/ -I ../ $(GLIB_CFLAGS) $(BUNDLE_CFLAGS) $(DLOG_CFLAGS)
endif
