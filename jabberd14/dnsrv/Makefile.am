lib_LTLIBRARIES = libjabberddnsrv.la

noinst_HEADERS = srv_resolv.h

libjabberddnsrv_la_SOURCES = dnsrv.c srv_resolv.c
libjabberddnsrv_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberddnsrv_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module -version-info 1:0:0

INCLUDES = -I../jabberd -I../jabberd/lib
