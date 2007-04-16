lib_LTLIBRARIES = libjabberdproxy65.la

noinst_HEADERS = proxy65.h

libjabberdproxy65_la_SOURCES = proxy65.cc
libjabberdproxy65_la_LIBADD = $(top_builddir)/jabberd/libjabberd.la
libjabberdproxy65_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module -version-info 2:0:0

INCLUDES = -I../jabberd -I../jabberd/lib
