CC=gcc
DEFINES=-DCONFIGXML="\"jabber.xml\""
CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ `libxode-config --cflags` -Wall

log_OBJECTS=\
	base_file.o \
	base_format.o \
	base_logtype.o \
	base_stderr.o \
	base_to.o

all: $(log_OBJECTS)

clean:
	rm -f $(log_OBJECTS)
