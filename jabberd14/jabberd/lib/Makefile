#
# Ok this is taken from an automaked file and tweaked out
#
include ../../platform-settings

# add -DSTATIC for a rudimentary static build, and make sure all the needed .o's are linked in below!
DEFINES=-DCONFIGXML="\"jabber.xml\"" -DHOME="\"$(JHOME)\""
CFLAGS:=$(CFLAGS) $(DEFINES)

lib_HEADERS= \
	asciitab.h \
	hashtable.h \
	iasciitab.h \
	latin1tab.h \
	lib.h \
	nametab.h \
	utf8tab.h \
	xmldef.h \
	xmlparse.h \
	xmlrole.h \
	xmltok.h \
	xmltok_impl.h

lib_OBJECTS = \
    expat.o \
	genhash.o \
	hashtable.o \
	jid.o \
	jpacket.o \
	jutil.o \
	karma.o \
	pool.o \
	pproxy.o \
	rate.o \
	sha.o \
	snprintf.o \
	socket.o \
	str.o \
	xmlnode.o \
	xmlparse.o \
	xmlrole.o \
	xmltok.o \
	xstream.o

SUBDIRS=

all: all-recursive

clean: clean-recursive

$(lib_OBJECTS): $(lib_HEADERS)

all-local: $(lib_OBJECTS) $(lib_HEADERS)

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
	rm -f $(lib_OBJECTS) jabberd

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


