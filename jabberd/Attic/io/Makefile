include ../../platform-settings

io_HEADERS=../jabberd.h

io_OBJECTS=\
	base_connect.o \
	base_exec.o \
	base_stdout.o \
	base_load.o \
	base_accept.o

$(io_OBJECTS): $(io_HEADERS)

all: $(io_OBJECTS) $(io_HEADERS)

clean:
	rm -rf $(io_OBJECTS)
