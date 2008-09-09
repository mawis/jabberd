lib_LTLIBRARIES = libjabberdresolver.la

noinst_HEADERS = resolver.h

libjabberdresolver_la_SOURCES = resolver.cc
libjabberdresolver_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberdresolver_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module -version-info 2:0:0

INCLUDES = -I../jabberd -I../jabberd/lib
