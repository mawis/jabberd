# just copy all the cygwin-specifc files into place... ugly, but it works 

# copy in all the makefiles
cp cygwin/Makefile.top Makefile
cp cygwin/Makefile.xdb_file xdb_file/Makefile
cp cygwin/Makefile.jsm jsm/Makefile
cp cygwin/Makefile.pthsock pthsock/Makefile
cp cygwin/Makefile.jabberd jabberd/Makefile
cp cygwin/Makefile.dialback dialback/Makefile

# copy in a whole new dnsrv
cp cygwin/dnsrv/* dnsrv/

# copy dll files into everywhere
cp cygwin/dllinit.c xdb_file/
cp cygwin/dllinit.c jsm/
cp cygwin/dllinit.c dialback/
cp cygwin/dllinit.c pthsock/
cp cygwin/dllinit.c dnsrv/
cp cygwin/dllinit.c jabberd/
cp cygwin/dllfixup.c jabberd/

# hmm, I guess that's it?
# Not quite, create a new config file using .dll's instead of .so's
mv jabber.xml jabber.xml.orig
cat jabber.xml.orig | sed 's/\.so/\.dll/g' > jabber.xml
