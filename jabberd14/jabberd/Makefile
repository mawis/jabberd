#
# Ok this is taken from an automaked file and tweaked out
#
include ../platform-settings

# add -DSTATIC for a rudimentary static build, and make sure all the needed .o's are linked in below!
DEFINES=-DCONFIGXML="\"jabber.xml\"" -DHOME="\"$(JHOME)\""
CFLAGS:=$(CFLAGS) $(DEFINES)

jabberd_HEADERS=jabberd.h

jabberd_OBJECTS = \
	config.o \
	mio.o \
	mio_raw.o \
	mio_xml.o \
	deliver.o \
	heartbeat.o \
	jabberd.o \
	load.o \
	xdb.o \
	mtq.o \
	static.o \
	log.o \
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
	base/base_exec.o \
	base/base_stdout.o \
	base/base_accept.o \
	base/base_file.o \
	base/base_format.o \
	base/base_stderr.o \
	base/base_to.o

SUBDIRS=

all: all-recursive

clean: clean-recursive

$(jabberd_OBJECTS): $(jabberd_HEADERS)

all-local: $(jabberd_OBJECTS) $(jabberd_HEADERS)
	$(CC) $(CFLAGS) -o jabberd $(jabberd_OBJECTS) $(jabberd_EXOBJECTS) $(XLDFLAGS) $(LDFLAGS) $(LIBS)

#STATIC: ../jsm/*.o ../jsm/modules/*.o ../xdb_file/xdb_file.o ../pthsock/client.o ../pthsock/dialback.o ../dnsrv/*.o

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


