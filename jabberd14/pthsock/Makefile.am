EXTRA_DIST = CREDITS README.pthsock_client

lib_LTLIBRARIES = libjabberdpthsock.la

libjabberdpthsock_la_SOURCES = client.c
libjabberdpthsock_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberdpthsock_la_LDFLAGS = @LDFLAGS@ -module

INCLUDES = -I../jabberd -I../jabberd/lib
