#
# Ok this is taken from an automaked file and tweaked out
#
include ../../platform-settings

# add -DSTATIC for a rudimentary static build, and make sure all the needed .o's are linked in below!
DEFINES=-DCONFIGXML="\"jabber.xml\"" -DHOME="\"$(JHOME)\""
CFLAGS:=$(CFLAGS) $(DEFINES)

base_OBJECTS = \
	base_connect.o \
	base_dynamic.o \
	base_exec.o \
	base_stdout.o \
	base_accept.o \
	base_file.o \
	base_format.o \
	base_stderr.o \
	base_to.o

static: $(base_OBJECTS)

all: $(base_OBJECTS)

clean:
	rm -f $(base_OBJECTS)
