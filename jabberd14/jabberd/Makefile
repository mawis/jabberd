#
# Ok this is taken from an automaked file and tweaked out
#
include ../platform-settings

ifeq ($(ISSINGLE),1)
	DEFINES=-DHOME="\"$(JHOME)\"" -DSINGLE
else
	DEFINES=-DHOME="\"$(JHOME)\"" -DCONFIGXML="\"jabber.xml\""
endif
ifeq ($(ISSTATIC),1)
	DEFINES=-DHOME="\"$(JHOME)\"" -DSTATIC
endif

CFLAGS:=$(CFLAGS) $(DEFINES)

jabberd_HEADERS=jabberd.h single.h

SUBDIRS=base lib $(PSUBDIR)

jabberd_OBJECTS = \
	config.o \
	mio.o \
	mio_raw.o \
	mio_xml.o \
    mio_ssl.o \
	deliver.o \
	heartbeat.o \
	jabberd.o \
	load.o \
	xdb.o \
	mtq.o \
	static.o \
	log.o

jabberd_EXOBJECTS = \
	lib/expat.o \
	lib/genhash.o \
	lib/hashtable.o \
	lib/jid.o \
	lib/jpacket.o \
	lib/jutil.o \
	lib/karma.o \
	lib/pool.o \
	lib/pproxy.o \
	lib/rate.o \
	lib/sha.o \
	lib/snprintf.o \
	lib/socket.o \
	lib/str.o \
	lib/xmlnode.o \
	lib/xmlparse.o \
	lib/xmlrole.o \
	lib/xmltok.o \
	lib/xstream.o \
	base/base_connect.o \
	base/base_dynamic.o \
	base/base_exec.o \
	base/base_stdout.o \
	base/base_accept.o \
	base/base_file.o \
	base/base_format.o \
	base/base_stderr.o \
	base/base_to.o
	
jabberd_STATICOBJS=\
	$(JHOME)/jsm/deliver.o \
	$(JHOME)/jsm/jsm.o \
	$(JHOME)/jsm/modules.o \
	$(JHOME)/jsm/offline.o \
	$(JHOME)/jsm/server.o \
	$(JHOME)/jsm/authreg.o \
	$(JHOME)/jsm/sessions.o \
	$(JHOME)/jsm/users.o \
	$(JHOME)/jsm/util.o \
	$(JHOME)/jsm/modules/mod_admin.o \
	$(JHOME)/jsm/modules/mod_agents.o \
	$(JHOME)/jsm/modules/mod_archive.o \
	$(JHOME)/jsm/modules/mod_announce.o \
	$(JHOME)/jsm/modules/mod_auth_plain.o \
	$(JHOME)/jsm/modules/mod_auth_digest.o \
	$(JHOME)/jsm/modules/mod_auth_0k.o \
	$(JHOME)/jsm/modules/mod_echo.o \
	$(JHOME)/jsm/modules/mod_filter.o \
	$(JHOME)/jsm/modules/mod_groups.o \
	$(JHOME)/jsm/modules/mod_presence.o \
	$(JHOME)/jsm/modules/mod_private.o \
	$(JHOME)/jsm/modules/mod_roster.o \
	$(JHOME)/jsm/modules/mod_time.o \
	$(JHOME)/jsm/modules/mod_vcard.o \
	$(JHOME)/jsm/modules/mod_version.o \
	$(JHOME)/jsm/modules/mod_register.o \
	$(JHOME)/jsm/modules/mod_log.o \
	$(JHOME)/jsm/modules/mod_offline.o \
	$(JHOME)/dnsrv/dnsrv.o \
	$(JHOME)/dnsrv/srv_resolv.o \
	$(JHOME)/pthsock/dialback.o \
	$(JHOME)/pthsock/client.o \
	$(JHOME)/xdb_file/xdb_file.o

single: static

all: all-recursive

clean: clean-recursive

static: static-recursive

$(jabberd_OBJECTS): $(jabberd_HEADERS)

all-local: $(jabberd_OBJECTS)
	$(CC) $(CFLAGS) -o jabberd $(jabberd_OBJECTS) $(jabberd_EXOBJECTS) $(XLDFLAGS) $(LDFLAGS) $(LIBS)

static-local: $(jabberd_OBJECTS)
	$(CC) $(CFLAGS) -o jabberd $(jabberd_OBJECTS) $(jabberd_EXOBJECTS) $(jabberd_STATICOBJS) $(LDFLAGS) $(LIBS) $(PLINK)

install-local:

all-recursive install-data-recursive install-exec-recursive \
installdirs-recursive install-recursive uninstall-recursive  \
check-recursive installcheck-recursive info-recursive static-recursive:
	@set fnord $(MAKEFLAGS); amf=$$2; \
	dot_seen=no; \
	target=`echo $@ | sed s/-recursive//`; \
	list='$(SUBDIRS)'; for subdir in $$list; do \
	  echo "Making $$target in $$subdir"; \
	  if test "$$subdir" = "."; then \
	    dot_seen=yes; \
	    local_target="$$target-local"; \
	  else \
	    local_target="$$target"; \
	  fi; \
      if test "$$subdir" = "pth-1.3.7"; then \
        local_target="all"; \
      fi; \
	  (cd $$subdir && $(MAKE) $$local_target) \
	   || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac; \
	done; \
	if test "$$dot_seen" = "no"; then \
	  echo "Making $$target"; \
	  $(MAKE) "$$target-local" || exit 1; \
	fi; test -z "$$fail"

clean-local:
	rm -f $(jabberd_OBJECTS) jabberd

mostlyclean-recursive clean-recursive distclean-recursive \
maintainer-clean-recursive:
	@set fnord $(MAKEFLAGS); amf=$$2; \
	dot_seen=no; \
	rev=''; list='$(SUBDIRS)'; for subdir in $$list; do \
	  rev="$$subdir $$rev"; \
	  test "$$subdir" = "." && dot_seen=yes; \
	done; \
	test "$$dot_seen" = "no" && rev=". $$rev"; \
	target=`echo $@ | sed s/-recursive//`; \
	for subdir in $$rev; do \
	  echo "Making $$target in $$subdir"; \
	  if test "$$subdir" = "."; then \
	    local_target="$$target-local"; \
	  else \
	    local_target="$$target"; \
	  fi; \
	  (cd $$subdir && $(MAKE) $$local_target) \
	   || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"

.PHONY: clean static single
