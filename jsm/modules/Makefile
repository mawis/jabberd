CC=gcc
DEFINES=-DVERSION=\"1.1.4\" -DPACKAGE=\"jsm\"
CFLAGS=-fPIC -g $(DEFINES) -I./ -I../ -I../../jabberd `libxode-config --cflags` -Wall

jsm_modules_OBJECTS=\
	mod_admin.o \
	mod_agents.o \
	mod_announce.o \
	mod_auth_plain.o \
	mod_auth_digest.o \
	mod_auth_0k.o \
	mod_echo.o \
	mod_filter.o \
	mod_presence.o \
	mod_private.o \
	mod_roster.o \
	mod_time.o \
	mod_vcard.o \
	mod_version.o \
	mod_register.o \
	mod_log.o \
	mod_offline.o

all: $(jsm_modules_OBJECTS)

clean:
	rm -f $(jsm_modules_OBJECTS)
