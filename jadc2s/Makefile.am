sysconf_DATA = jadc2s.xml.dist
EXTRA_DIST = PROTO jadc2s.xml.dist README.SASL

SUBDIRS = ac-helpers mio util
DIST_SUBDIRS = ac-helpers mio util

bin_PROGRAMS = jadc2s

jadc2s_SOURCES = clients.cc conn.cc connect.cc jadc2s.cc rate.cc
jadc2s_LDADD = $(top_builddir)/mio/libmio.la \
		   $(top_builddir)/util/libutil.la
noinst_HEADERS = jadc2s.h

#jadc2s_LDADD = libjad.la
jadc2s_LDFLAGS = @LDFLAGS@

#lib_LTLIBRARIES = libjad.la
#
#libjad_la_SOURCES =
#libjad_la_LIBADD = $(top_builddir)/mio/libmio.la \
#		   $(top_builddir)/util/libutil.la
#libjad_la_LDFLAGS = @LDFLAGS@ -export-dynamic

install-data-hook:
	@list='$(sysconf_DATA)'; for p in $$list; do \
      dest=`echo $$p | sed -e s/.dist//`; \
	  if test -f $(DESTDIR)$(sysconfdir)/$$dest; then \
        echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/$$dest"; \
      else \
	    echo " $(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest"; \
	    $(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest; \
	  fi; \
	done

