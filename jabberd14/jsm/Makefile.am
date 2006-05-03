SUBDIRS = modules
DIST_SUBDIRS = modules

lib_LTLIBRARIES = libjabberdsm.la

noinst_HEADERS = jsm.h

libjabberdsm_la_SOURCES = authreg.c deliver.c jsm.c modules.c offline.c server.c sessions.c serialization.c users.c util.c
libjabberdsm_la_LIBADD = $(top_builddir)/jsm/modules/libjabberdsmmods.la $(top_builddir)/jabberd/libjabberd.la
libjabberdsm_la_LDFLAGS = @LDFLAGS@ @VERSION_INFO@ -module

INCLUDES = -I../jabberd -I../jabberd/lib
