#
# Ok this is taken from an automaked file and tweaked out
#
include ../platform-settings

DEFINES=-DCONFIGXML="\"jabber.xml\"" -DHOME="\"$(JHOME)\""
CFLAGS:=$(CFLAGS) $(DEFINES)

jabberd_HEADERS=jabberd.h

jabberd_OBJECTS = \
	config.o \
	deliver.o \
	heartbeat.o \
	jabberd.o \
	load.o \
	log.o

jabberd_EXOBJECTS = \
	gen/base_host.o \
	io/base_connect.o \
	io/base_exec.o \
	io/base_stdout.o \
	io/base_load.o \
	io/base_accept.o \
	log/base_file.o \
	log/base_format.o \
	log/base_logtype.o \
	log/base_stderr.o \
	log/base_to.o \
	xdb/base_ns.o

SUBDIRS=io log xdb

all: all-recursive

clean: clean-recursive

$(jabberd_OBJECTS): $(jabberd_HEADERS)

all-local: $(jabberd_OBJECTS) $(jabberd_HEADERS)
	$(CC) $(CFLAGS) -o jabberd $(jabberd_OBJECTS) $(jabberd_EXOBJECTS) $(XLDFLAGS) $(LDFLAGS) $(LIBS)

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
