CC=gcc
DEFINES=-DCONFIGXML="\"jabber.xml\""
#CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ `libxode-config --cflags` -Wall

gen_OBJECTS=\
	base_host.o

all: $(gen_OBJECTS)

clean:
	rm -f $(gen_OBJECTS)
