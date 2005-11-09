lib_LTLIBRARIES = libjabberddialback.la

noinst_HEADERS = dialback.h

libjabberddialback_la_SOURCES = dialback.c  dialback_in.c  dialback_out.c
libjabberddialback_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberddialback_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module

INCLUDES = -I../jabberd -I../jabberd/lib
