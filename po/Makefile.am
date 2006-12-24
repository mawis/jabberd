EXTRA_DIST = de.po fr.po hu.po it.po nl.po

LANGS = de.po fr.po hu.po it.po nl.po

jabberd14.pot:
	-xgettext -o jabberd14.pot --from-code=UTF-8 --msgid-bugs-address=mail@amessage.eu --keyword=N_ `(find .. -name "*.cc" ; find .. -name "*.c" ; find .. -name "*.h") | xargs`

$(LANGS): jabberd14.pot
	-msgmerge $@ jabberd14.pot > $@.bak ; mv $@.bak $@


install-data-hook:
	-for f in $(LANGS); do \
	    test -z "$(localedir)/$${f%.po}/LC_MESSAGES" || $(mkdir_p) "$(localedir)/$${f%.po}/LC_MESSAGES"; \
	     msgfmt -o "$(localedir)/$${f%.po}/LC_MESSAGES/jabberd14.mo" $$f; \
	     done
