#
# Ok this is taken from an automaked file and tweaked out
#
CC=gcc
DEFINES=-DVERSION=\"1.1.4\" -DPACKAGE=\"jsm\"
CFLAGS=-fPIC -shared -g $(DEFINES) -I./ -I../ -I../jabberd `libxode-config --cflags` -Wall
LDFLAGS=`libxode-config --ldflags` `libxode-config --libs` `pth-config --libs --ldflags` `jabber-config --ldflags` `jabber-config --libs` -ldl

jsm_OBJECTS = \
	deliver.o \
	jsm.o \
	modules.o \
	offline.o \
	server.o \
	authreg.o \
	sessions.o \
	users.o \
	util.o

jsm_EXOBJECTS = \
	modules/mod_admin.o \
	modules/mod_agents.o \
	modules/mod_announce.o \
	modules/mod_auth.o \
	modules/mod_auth_sha1.o \
	modules/mod_echo.o \
	modules/mod_filter.o \
	modules/mod_presence.o \
	modules/mod_private.o \
	modules/mod_roster.o \
	modules/mod_time.o \
	modules/mod_vcard.o \
	modules/mod_version.o \
	modules/mod_register.o \
	modules/mod_log.o \
	modules/mod_auth_0k.o \
	modules/mod_offline.o

SUBDIRS=modules

all: all-recursive

clean: clean-recursive

all-local: $(jsm_OBJECTS)
	$(CC) $(CFLAGS) -o jsm.so $(jsm_OBJECTS) $(jsm_EXOBJECTS) $(LDFLAGS)

install-local:

all-recursive install-data-recursive install-exec-recursive \
installdirs-recursive install-recursive uninstall-recursive  \
check-recursive installcheck-recursive info-recursive dvi-recursive:
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
	  (cd $$subdir && $(MAKE) $$local_target) \
	   || case "$$amf" in *=*) exit 1;; *k*) fail=yes;; *) exit 1;; esac; \
	done; \
	if test "$$dot_seen" = "no"; then \
	  $(MAKE) "$$target-local" || exit 1; \
	fi; test -z "$$fail"

clean-local:
	rm -f $(jsm_OBJECTS) jsm.so

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
