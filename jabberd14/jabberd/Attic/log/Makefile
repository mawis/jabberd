include ../../platform-settings

log_HEADERS=../jabberd.h

log_OBJECTS=\
	base_file.o \
	base_format.o \
	base_logtype.o \
	base_stderr.o \
	base_to.o

$(log_OBJECTS): $(log_HEADERS)

all: $(log_OBJECTS) $(log_HEADERS)

clean:
	rm -f $(log_OBJECTS)
