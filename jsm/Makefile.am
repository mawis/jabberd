SUBDIRS = modules
DIST_SUBDIRS = modules

EXTRA_DIST = README

lib_LTLIBRARIES = libjabberdsm.la

noinst_HEADERS = jsm.h

libjabberdsm_la_SOURCES = authreg.c deliver.c jsm.c modules.c offline.c server.c sessions.c users.c util.c
libjabberdsm_la_LIBADD = @LDFLAGS@ $(top_builddir)/jsm/modules/libjabberdsmmods.la $(top_builddir)/jabberd/libjabberd.la

INCLUDES = -I../jabberd -I../jabberd/lib
