CC=gcc
CFLAGS=-fPIC -g -DVERSION=\"0.1\" -DPACKAGE=\"jsm\" -I./ -I../ `libxode-config --cflags` -Wall

SUBDIRS = modules

jsm_OBJECTS = \
    modules/mod_admin.o \
    modules/mod_agents.o \
    modules/mod_announce.o \
    modules/mod_auth.o \
    modules/mod_auth_sha1.o \
    modules/mod_echo.o \
    modules/mod_log.o \
    modules/mod_offline.o \
    modules/mod_presence.o \
    modules/mod_private.o \
    modules/mod_roster.o \
    modules/mod_time.o \
    modules/mod_vcard.o \
    modules/mod_version.o \
    config.o \
    deliver.o \
    init.o \
    jsm.o \
    modules.o \
    offline.o \
    server.o \
    services.o \
    sessions.o \
    shutdown.o \
    unknown.o \
    users.o \
    util.o

all: jsm_build

jsm_build: $(jsm_OBJECTS)
	$(CC) -fPIC -shared -o jsm.so $(jsm_OBJECTS)

clean:
	rm $(jsm_OBJECTS) jsm.so
