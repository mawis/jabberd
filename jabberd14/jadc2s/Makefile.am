sysconf_DATA = jadc2s.xml
EXTRA_DIST = PROTO

SUBDIRS = ac-helpers mio util xmlparse
DIST_SUBDIRS = ac-helpers mio util xmlparse

bin_PROGRAMS = jadc2s

jadc2s_SOURCES = clients.c  conn.c  connect.c  jadc2s.c  rate.c
noinst_HEADERS = jadc2s.h

jadc2s_LDADD = $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la \
            $(top_builddir)/xmlparse/libxmlparse.la
