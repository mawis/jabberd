EXTRA_DIST = UPGRADE jabber.xml.dist.in README.SQL README.karma README.config README.protocols README.filespool mysql.sql pgsql_createdb.sql xdb_postgresql.xml cacerts.pem

SUBDIRS = jabberd dialback dnsrv jsm pthsock xdb_file xdb_sql man po
DIST_SUBDIRS = jabberd dialback dnsrv jsm pthsock xdb_file xdb_sql man po

sysconf_DATA = jabber.xml.dist

logdir = $(localstatedir)/log/jabberd

log_DATA =

spooldir = $(localstatedir)/spool/jabberd

spool_DATA =

rundir = $(localstatedir)/run/jabberd

run_DATA =

edit = sed \
       -e 's,\@sysconfdir\@,$(sysconfdir),g' \
       -e 's,\@localstatedir\@,$(localstatedir),g' \
       -e 's,\@libdir\@,$(libdir),g'

$(sysconf_DATA):
	@echo "generating $@ from $@.in"; \
	edit='$(edit)'; \
	rm -f $@ $@.tmp; \
	eval "$$edit < $@.in > $@.tmp"; \
	mv $@.tmp $@

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
	@if test -f $(DESTDIR)$(sysconfdir)/cacerts.pem; then \
	    echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/cacerts.pem"; \
	else \
	    cp cacerts.pem $(DESTDIR)$(sysconfdir)/cacerts.pem; \
	fi;

clean-local:
	rm -f $(sysconf_DATA)
