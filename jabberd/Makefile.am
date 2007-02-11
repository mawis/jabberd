SUBDIRS = base lib
DIST_SUBDIRS = base lib

bin_PROGRAMS = jabberd

jabberd_SOURCES = jabberd.cc

jabberd_LDADD = $(top_builddir)/jabberd/base/libjabberdbase.la \
		$(top_builddir)/jabberd/libjabberd.la \
		-lpopt
jabberd_LDFLAGS = @LDFLAGS@ -export-dynamic

include_HEADERS = jabberd.h

INCLUDES = -Ilib
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

EXTRA_DIST = README README.CONFIG README.SM

lib_LTLIBRARIES = libjabberd.la

libjabberd_la_SOURCES = acl.c config.c heartbeat.c mio.c mio_tls.cc mtq.c xdb.c deliver.c log.c mio_raw.c mio_xml.c subjectAltName_asn1_tab.c
libjabberd_la_LIBADD = -lexpat $(top_builddir)/jabberd/lib/libjabberdlib.la
libjabberd_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -export-dynamic -version-info 1:0:0
