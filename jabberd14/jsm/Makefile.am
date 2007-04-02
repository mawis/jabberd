SUBDIRS = modules
DIST_SUBDIRS = modules

lib_LTLIBRARIES = libjabberdsm.la

noinst_HEADERS = jsm.h

libjabberdsm_la_SOURCES = authreg.cc deliver.cc jsm.cc modules.cc offline.cc server.cc sessions.cc serialization.cc users.cc util.cc
libjabberdsm_la_LIBADD = $(top_builddir)/jsm/modules/libjabberdsmmods.la $(top_builddir)/jabberd/libjabberd.la
libjabberdsm_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module -version-info 2:0:0

INCLUDES = -I../jabberd -I../jabberd/lib
