CC=gcc
DEFINES=-DCONFIGXML="\"jabber.xml\""
CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ `libxode-config --cflags` -Wall

io_OBJECTS=\
	base_connect.o \
	base_exec.o \
	base_stdout.o \
	base_load.o \
	base_accept.o

all: $(io_OBJECTS)

clean:
	rm -rf $(io_OBJECTS)
