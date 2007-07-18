dnl jabberd14 configure script
dnl based on the configure script of jadc2s,
dnl that is for most parts the jabberd2 configure script

AC_PREREQ(2.50)


AC_INIT(jabberd/jabberd.h)
AM_INIT_AUTOMAKE(jabberd14,1.6.1.1)
AM_CONFIG_HEADER(config.h)
AC_LANG(C++)

dnl version info for libraries
VERSION_INFO="-version-info 2:0:0"
AC_SUBST(VERSION_INFO)

dnl helper macros
sinclude(ac-helpers/ac_define_dir.m4)

dnl for developers
AC_MSG_CHECKING(if developer mode enabled)
AC_ARG_ENABLE(developer, AC_HELP_STRING([--enable-developer],
                    [Developer mode]),
              developer=yes)

if test x-$developer = "x-yes" ; then
    AC_MSG_RESULT(yes)
    CPPFLAGS="$CPPFLAGS -Wall -g"
else
    AC_MSG_RESULT(no)
fi

dnl Check for programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_ICONV

AC_LIBTOOL_DLOPEN
AC_DISABLE_STATIC
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

AC_SUBST([localedir], ['${datadir}/locale'])

dnl use libtool to compile checks (particularly lib checks), mostly so we don't have to worry about how/if the os supports -R
ac_link="${SHELL} ${srcdir}/libtool --mode=link $ac_link"

dnl headers we need
AC_HEADER_STDC

dnl static builds
AC_MSG_CHECKING(if static builds enabled)
AC_ARG_ENABLE(all-static, AC_HELP_STRING([--enable-all-static], [Build static binaries]), all_static=yes, all_static=no)
if test "x-$all_static" = "x-yes" ; then
    LDFLAGS="$LDFLAGS -Wl,-static -static"
fi
AC_MSG_RESULT($all_static)

AC_MSG_CHECKING(if partial static builds enabled)
AC_ARG_ENABLE(partial-static, AC_HELP_STRING([--enable-partial-static], [Build partially static binaries]), partial_static=yes, partial_static=no)
if test "x-$partial_static" = "x-yes" ; then
    LDFLAGS="$LDFLAGS -Wl,-lc,-static -static"
fi
AC_MSG_RESULT($partial_static)

dnl solaris has socket functions in libsocket
AC_CHECK_FUNC(socket, have_libsocket=yes, have_libsocket=no)
if test "$have_libsocket" = "yes"; then
    AC_DEFINE(HAVE_LIBSOCKET, 1, [Define if socket and associated functions are available.])
else
    AC_CHECK_LIB(socket, socket, have_libsocket=yes, have_libsocket=no)
    if test "$have_libsocket" = "yes"; then
        AC_DEFINE(HAVE_LIBSOCKET, 1, [Define if socket and associated functions are available.])
        LIBS="$LIBS -lsocket"
    fi
fi
if test "$have_libsocket" = "no" ; then
    AC_MSG_ERROR([Couldn't find required function socket])
fi

dnl check if we have to link against libdl
AC_CHECK_FUNC(dlopen, have_dlopen=yes, have_dlopen=no)
if test "$have_dlopen" = "yes"; then
    AC_DEFINE(HAVE_DLOPEN, 1, [Define if dlopen is available.])
else
    AC_CHECK_LIB(dl, dlopen, have_dlopen=yes, have_dlopen=no)
    if test "$have_dlopen" = "yes"; then
	AC_DEFINE(HAVE_DLOPEN, 1, [Define if dlopen is available.])
	LIBS="$LIBS -ldl"
    fi
fi
if test "$have_dlopen" = "no"; then
    AC_MSG_ERROR([Couldn't find required function dlopen])
fi

dnl check for res_querydomain in libc, libbind and libresolv
AC_CHECK_FUNCS(res_querydomain)
if test "x-$ac_cv_func_res_querydomain" = "x-yes" ; then
    have_res_querydomain=yes
else
    AC_CHECK_LIB(resolv, res_querydomain)
    if test "x-$ac_cv_lib_resolv_res_querydomain" = "x-yes" ; then
	have_res_querydomain=yes
    else
	AC_CHECK_LIB(bind, res_querydomain)
	if test "x-$ac_cv_lib_bind_res_querydomain" = "x-yes" ; then
	    have_res_querydomain=yes
	else
	    AC_MSG_CHECKING([for res_querydomain in -lresolv (alternate version)])
	    save_libs="$LIBS"
	    LIBS="-lresolv $LIBS"
	    AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <resolv.h>]],
					    [[res_querydomain(0,0,0,0,0,0)]])],
			   [AC_MSG_RESULT(yes)
			    have_res_querydomain=yes],
			   [AC_MSG_RESULT(no)
			    LIBS="$save_libs"])
	fi
    fi
fi

AC_MSG_CHECKING(for syslog)
AC_TRY_COMPILE([#include <syslog.h>], [syslog(LOG_ERR, "jabber")], has_syslog=yes, has_syslog=no)
if test "$has_syslog" = yes; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_SYSLOG,,[Syslog functionality enabled])
else
    AC_MSG_RESULT(no)
fi

dnl check for libpopt
AC_MSG_CHECKING(for libpopt)
AC_TRY_COMPILE([#include <popt.h>], [poptStrerror(0)], has_popt=yes, has_popt=no)
if test "$has_popt" = yes; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_ERROR(no)
fi

dnl check for needed functions to enable IPv6

AC_MSG_CHECKING(for inet_pton)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>], [inet_pton(0, (char *)0, (char *)0);], has_inet_pton=yes, has_inet_pton=no)
if test "$has_inet_pton" = yes; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(for inet_ntop)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>], [inet_ntop(0, (char *)0, (char *)0, 0);], has_inet_ntop=yes, has_inet_ntop=no)
if test "$has_inet_ntop" = yes; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(for getaddrinfo)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>], [getaddrinfo(NULL, NULL, NULL, NULL)], has_getaddrinfo=yes, has_getaddrinfo=no)
if test "$has_getaddrinfo" = yes; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(if IPv6 is requested)
AC_ARG_ENABLE(ipv6, AC_HELP_STRING([--enable-ipv6], [Enable IPv6 code]), ipv6=yes)
if test x-$has_inet_pton = "x-no" ; then
    AC_MSG_RESULT(disabled: inet_pton missing)
else if test x-$has_inet_ntop = "x-no" ; then
    AC_MSG_RESULT(disabled: inet_ntop missing)
else if test x-$has_getaddrinfo = "x-no" ; then
    AC_MSG_RESULT(disabled: getaddrinfo missing)
else if test x-$ipv6 = "x-yes" ; then
    AC_MSG_RESULT(enabled)
    AC_DEFINE(WITH_IPV6,,[IPv6 code enabled])
else
    AC_MSG_RESULT(disabled)
fi
fi
fi
fi

AC_SUBST(WITH_IPV6)

dnl ** Check for broken glibc with __ss_family
                                                                                                                             
AC_MSG_CHECKING(for broken glibc with __ss_family)
AC_TRY_COMPILE([#include <sys/socket.h>], [struct sockaddr_storage s; s.__ss_family = AF_INET;], have_broken_ss_family=yes, have_broken_ss_family=no)
if test "$have_broken_ss_family" = yes; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(ss_family,__ss_family,[use __ss_family instead of ss_family])
else
    AC_MSG_RESULT(no)
fi

dnl ** Check for broken glibc with __ss_len

AC_MSG_CHECKING(for broken glibc with __ss_len)
AC_TRY_COMPILE([#include <sys/socket.h>], [struct sockaddr_storage s; s.__ss_len = 0;], have_broken_ss_len=yes, have_broken_ss_len=no)
if test "$have_broken_ss_len" = yes; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(ss_len,__ss_len,[use __ss_len instead of ss_len])
else
    AC_MSG_RESULT(no)
fi

dnl check for crypt.h
AC_MSG_CHECKING(for crypt.h)
AC_CHECK_HEADER(crypt.h, crypt_header=yes, crypt_header=no)
if test "$crypt_header" != "no"; then
    AC_DEFINE(INCLUDE_CRYPT_H,,[include the crypt.h header file])
fi

dnl debugging
AC_MSG_CHECKING(if debug messages wanted)
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
                    [Enable debug messages]),
              debug=yes)

if test x-$debug = "x-yes" ; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(DEBUG,,[app debug enabled])
else
    AC_MSG_RESULT(no)
fi

AC_SUBST(DEBUG)

AC_MSG_CHECKING(if pool debugging wanted)
AC_ARG_ENABLE(pool_debug, AC_HELP_STRING([--enable-pool-debug], [Enable pool debugging]), pool_debug=yes)
if test x-$pool_debug = "x-yes" ; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(POOL_DEBUG,,[pool debug enabled])
else
    AC_MSG_RESULT(no)
fi

AC_SUBST(POOL_DEBUG)

dnl first check for GnuTLS (required)
AC_MSG_CHECKING(for GnuTLS)
PKG_CHECK_MODULES(GNUTLS, gnutls >= 1.4.0, hasgnutls=yes, hasgnutls=no)
if test $hasgnutls = "no" ; then
    AC_MSG_RESULT($GNUTLS_PKG_ERRORS)
    AC_MSG_ERROR([Couldn't find required GnuTLS installation])
fi
CPPFLAGS="$CPPFLAGS $GNUTLS_CFLAGS"
LDFLAGS="$LDFLAGS $GNUTLS_LIBS"

AC_MSG_CHECKING(for TLS 1.2 support in GnuTLS)
AC_TRY_COMPILE([#include <gnutls/gnutls.h>], [gnutls_protocol_t pversion = GNUTLS_TLS1_2;], have_tls1_2_support=yes, have_tls1_2_support=no)
if test "$have_tls1_2_support" = yes; then
    AC_MSG_RESULT(yes)
    AC_DEFINE(HAVE_TLS1_2,,[if GnuTLS has support for TLS 1.2])
else
    AC_MSG_RESULT(no)
fi

dnl then check for GnuTLS extra
PKG_CHECK_MODULES(GNUTLSEXTRA, gnutls-extra >= 1.4.0, hasgnutlsextra=yes, hasgnutlsextra=no)
if test $hasgnutls = "yes" ; then
    CPPFLAGS="$CPPFLAGS $GNUTLSEXTRA_CFLAGS"
    LDFLAGS="$LDFLAGS $GNUTLSEXTRA_LIBS"
    AC_DEFINE(HAVE_GNUTLS_EXTRA,,[if GnuTLS-extra should be compiled in])
fi

dnl check for libidn
AC_ARG_WITH(libidn, AC_HELP_STRING([--with-libidn=DIR],
	    [Where to find libidn (required)]),
	    libidn=$withval, libidn=yes)
if test "$libidn" != "no"; then
    if test "$libidn" != "yes"; then
	LDFLAGS="${LDFLAGS} -L$libidn/lib"
	CPPFLAGS="${CPPFLAGS} -I$libidn/include"
    fi
    AC_CHECK_HEADER(idna.h,
		    AC_CHECK_LIB(idn, stringprep_check_version,
				 [libidn=yes LIBS="${LIBS} -lidn"], libidn=no),
				 libidn=no)
fi
if test "$libidn" != "no"; then
    AC_DEFINE(LIBIDN, 1, [Define to 1 if you want IDN support.])
else
    AC_MSG_ERROR([Couldn't find required libidn installation])
fi

dnl check for pth
AC_ARG_WITH(libpth, AC_HELP_STRING([--with-libpth=DIR],
	    [Where to find libpth (required)]),
	    libpth=$withval, libpth=yes)
if test "$libpth" != "no"; then
    if test "$libpth" != "yes"; then
	LDFLAGS="${LDFLAGS} -L$libpth/lib"
	CPPFLAGS="${CPPFLAGS} -I$libpth/include"
    fi
    AC_CHECK_HEADER(pth.h,
		    AC_CHECK_LIB(pth, pth_version,
				 [libpth=yes LIBS="${LIBS} -lpth"], libpth=no),
				 libpth=no)
fi
if test "$libpth" != "yes"; then
    AC_MSG_ERROR([Couldn't find required libpth installation])
fi

dnl check for expat
AC_ARG_WITH(libexpat, AC_HELP_STRING([--with-expat=DIR],
	    [Where to find libexpat (required)]),
	    libexpat=$withval, libexpat=yes)
if test "$libexpat" != "no"; then
    if test "$libexpat" != "yes"; then
	LDFLAGS="${LDFLAGS} -L$libexpat/lib"
	CPPFLAGS="${CPPFLAGS} -I$libexpat/include"
    fi
    AC_CHECK_HEADER(expat.h,
		    AC_CHECK_LIB(expat, XML_ParserCreate,
				 [libexpat=yes LIBS="${LIBS} -lexpat"], libexpat=no),
				 libexpat=no)
fi
if test "$libexpat" != "yes"; then
    AC_MSG_ERROR([Couldn't find required libexpat installation])
fi


dnl check for mysql
AC_ARG_WITH(mysql, AC_HELP_STRING([--with-mysql=DIR],
	    [Include mysql support for xdb_sql]),
	    mysql=$withval, mysql=yes)
if test "$mysql" != "no"; then
    if test "$mysql" != "yes"; then
	LDFLAGS="${LDFLAGS} -L$mysql/lib -L$mysql/lib/mysql"
	CPPFLAGS="${CPPFLAGS} -I$mysql/include"
    fi
    AC_CHECK_HEADER(mysql/mysql.h,
		    AC_CHECK_LIB(mysqlclient, mysql_close,
				 [mysql=yes LIBS="${LIBS} -lmysqlclient"], mysql=no),
				 mysql=no)
fi
AC_MSG_CHECKING([for mysql])
AC_MSG_RESULT($mysql)
if test "$mysql" != "no"; then
    AC_DEFINE(HAVE_MYSQL,,[mysql is available])
fi

dnl check for postgresql
AC_ARG_WITH(postgresql, AC_HELP_STRING([--with-postgresql=DIR],
	    [Include postgresql support for xdb_sql]),
	    postgresql=$withval, postgresql=yes)
if test "$postgresql" != "no"; then
    if test "$postgresql" != "yes"; then
	LDFLAGS="${LDFLAGS} -L$postgresql/lib"
	CPPFLAGS="${CPPFLAGS} -I$postgresql/include"
    fi
    AC_CHECK_HEADER(postgresql/libpq-fe.h,
		    AC_CHECK_LIB(pq, PQconnectdb,
				 [postgresql=yes LIBS="${LIBS} -lpq"], postgresql=no),
				 postgresql=no)
fi
AC_MSG_CHECKING([for postgresql])
AC_MSG_RESULT($postgresql)
if test "$postgresql" != "no"; then
    AC_DEFINE(HAVE_POSTGRESQL,,[postgresql is available])
fi

dnl define where the configuration file is located
AC_DEFINE_DIR(CONFIG_DIR,sysconfdir,[where the configuration file can be found])

dnl Create the makefiles
AC_OUTPUT(Makefile \
	  jabberd/Makefile \
	  jabberd/base/Makefile \
	  jabberd/lib/Makefile \
	  dialback/Makefile \
	  dnsrv/Makefile \
	  jsm/Makefile \
	  jsm/modules/Makefile \
	  man/Makefile \
	  pthsock/Makefile \
	  xdb_file/Makefile \
	  xdb_sql/Makefile \
	  po/Makefile)

printf "\nYou may now type 'make' to build your new Jabber system.\nType 'make install' to install then.\n"

if test "$mysql" = "no" -a "$postgresql" = "no"; then
    printf "\n\nWARNING:\n"
    printf "Your jabberd14 build will neither support PostgreSQL nor MySQL.\n"
    printf "You will have to reconfigure the server to store data in files.\n"
    printf "Please see at README.filespool on how to do this.\n"
fi
