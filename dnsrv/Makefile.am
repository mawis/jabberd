lib_LTLIBRARIES = libjabberddnsrv.la

noinst_HEADERS = srv_resolv.h

libjabberddnsrv_la_SOURCES = dnsrv.c srv_resolv.c
libjabberddnsrv_la_LIBADD = @LDFLAGS@ $(top_builddir)/jabberd/libjabberd.la

INCLUDES = -I../jabberd -I../jabberd/lib
