EXTRA_DIST = generateSSLkey UPGRADE jabber.xml.dist.in selfsigned.cnf README.SQL README.karma README.config

SUBDIRS = jabberd dialback dnsrv jsm pthsock xdb_file xdb_sql ac-helpers man
DIST_SUBDIRS = jabberd dialback dnsrv jsm pthsock xdb_file xdb_sql ac-helpers man

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

clean-local:
	rm -f $(sysconf_DATA)
