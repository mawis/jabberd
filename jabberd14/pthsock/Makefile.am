EXTRA_DIST = CREDITS README.pthsock_client

lib_LTLIBRARIES = libjabberdpthsock.la

libjabberdpthsock_la_SOURCES = client.cc
libjabberdpthsock_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberdpthsock_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module -version-info 2:0:0

INCLUDES = -I../jabberd -I../jabberd/lib
