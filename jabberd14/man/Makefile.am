man_MANS = jabberd.8 jabber.xml.5
EXTRA_DIST = jabberd.8.in jabber.xml.5.in

edit = sed \
	-e 's,\@sysconfdir\@,$(sysconfdir),g' \
	-e 's,\@VERSION\@,$(VERSION),g'

$(man_MANS):
	@echo "generating $@ from $@.in"; \
	edit='$(edit)'; \
	rm -f $@ $@.tmp; \
	eval "$$edit < $@.in > $@.tmp"; \
	mv $@.tmp $@ 
    
clean-local:
	rm -f $(man_MANS)
