sysconf_DATA = jadc2s.xml.dist
EXTRA_DIST = PROTO jadc2s.xml.dist

SUBDIRS = ac-helpers mio util
DIST_SUBDIRS = ac-helpers mio util

bin_PROGRAMS = jadc2s

jadc2s_SOURCES = clients.c  conn.c  connect.c  jadc2s.c  rate.c
noinst_HEADERS = jadc2s.h

jadc2s_LDADD = $(top_builddir)/mio/libmio.la \
            $(top_builddir)/util/libutil.la

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

