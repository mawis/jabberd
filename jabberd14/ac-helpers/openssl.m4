dnl This was heavily modified from berkeley-db.m4 included with
dnl Subversion (r5118). Originally copyright (c) 2002-2003 CollabNet.
dnl The version that checks for openssl has been included from jabberd2

dnl   JABBERD_LIB_OPENSSL(major, minor, fix, patch)
dnl
dnl   Search for a useable version of OpenSSL in a number of
dnl   common places.  The installed lib must be no older than the
dnl   version given by MAJOR, MINOR, FIX and PATCH. PATCH corresponds
dnl   to the OpenSSL patchlevel: 0 = none, 1 = a, 2 = b, etc.
dnl
dnl   If we find a useable version, set CPPFLAGS and LIBS as
dnl   appropriate, and set the shell variable `jabberd_lib_openssl' to
dnl   `yes'.  Otherwise, set `jabberd_lib_openssl' to `no'.
dnl
dnl   This macro also checks for the `--with-openssl=PATH' flag;
dnl   if given, the macro will use the PATH specified, and the
dnl   configuration script will die if it can't find the library.
dnl
dnl   We cache the results of individual searches under particular
dnl   prefixes, not the overall result of whether we found OpenSSL
dnl   That way, the user can re-run the configure script with
dnl   different --with-openssl switch values, without interference
dnl   from the cache.


AC_DEFUN(JABBERD_LIB_OPENSSL,
[
  openssl_version=$1.$2.$3.$4
  dnl  Process the `with-openssl' switch. We set the variable `places' to
  dnl  either `search', meaning we should check in a list of typical places,
  dnl  or to a single place spec.
  dnl
  dnl  A `place spec' is either:
  dnl    - the string `std', indicating that we should look for headers and
  dnl      libraries in the standard places,
  dnl    - a directory prefix P, indicating we should look for headers in
  dnl      P/include and libraries in P/lib, or
  dnl    - a string of the form `HEADER:LIB', indicating that we should look
  dnl      for headers in HEADER and libraries in LIB.
  dnl 
  dnl  You'll notice that the value of the `--with-openssl' switch is a
  dnl  place spec.

  AC_ARG_WITH(openssl,
    AC_HELP_STRING(--with-openssl=PATH, [alternate location of OpenSSL headers and libs]),
  [
    if test "$withval" = "yes"; then
      places=search
    else
      places="$withval"
    fi
  ],
  [
      places=search
  ])

  if test "$places" = "search"; then
    places="std /usr/local/openssl /usr/local/ssl /sw"
  fi
  # Now `places' is guaranteed to be a list of place specs we should
  # search, no matter what flags the user passed.

  # Save the original values of the flags we tweak.
  JABBERD_LIB_OPENSSL_save_libs="$LIBS"
  JABBERD_LIB_OPENSSL_save_cppflags="$CPPFLAGS"

  # The variable `found' is the prefix under which we've found
  # OpenSSL, or `not' if we haven't found it anywhere yet.
  found=not
  for place in $places; do

    LIBS="$JABBERD_LIB_OPENSSL_save_libs"
    CPPFLAGS="$JABBERD_LIB_OPENSSL_save_cppflags"
    case "$place" in
      "std" )
        description="the standard places"
      ;;
      *":"* )
        header="`echo $place | sed -e 's/:.*$//'`"
        lib="`echo $place | sed -e 's/^.*://'`"
	  CPPFLAGS="$CPPFLAGS -I$header"
	  LIBS="$LIBS -L$lib -R$lib"
	  description="$header and $lib"
      ;;
      * )
	  LIBS="$LIBS -L$place/lib -R$place/lib"
	  CPPFLAGS="$CPPFLAGS -I$place/include"
	  description="$place"
      ;;
    esac

    # We generate a separate cache variable for each prefix
    # we search under.  That way, we avoid caching information that
    # changes if the user runs `configure' with a different set of
    # switches.
    changequote(,)
    cache_id="`echo jabberd_cv_lib_openssl_$1_$2_$3_$4_in_${place} \
                 | sed -e 's/[^a-zA-Z0-9_]/_/g'`"
    changequote([,])
    dnl We can't use AC_CACHE_CHECK here, because that won't print out
    dnl the value of the computed cache variable properly.
    AC_MSG_CHECKING([for OpenSSL in $description])
    AC_CACHE_VAL($cache_id,
      [
       JABBERD_LIB_OPENSSL_TRY($1, $2, $3, $4)
         eval "$cache_id=$jabberd_have_openssl"
      ])
    result="`eval echo '$'$cache_id`"
    AC_MSG_RESULT($result)

    # If we found it, no need to search any more.
    if test "`eval echo '$'$cache_id`" = "yes"; then
      found="$place"
      break
    fi

    test "$found" != "not" && break
  done

  # Restore the original values of the flags we tweak.
  LIBS="$JABBERD_LIB_OPENSSL_save_libs"
  CPPFLAGS="$JABBERD_LIB_OPENSSL_save_cppflags"

  case "$found" in
    "not" )
	AC_MSG_ERROR([Could not find OpenSSL $openssl_version (or higher)])
	jabberd_lib_openssl=no
    ;;
    "std" )
        JABBERD_SSL_INCLUDES=
        JABBERD_SSL_LIBS="-lssl -lcrypto"
        jabberd_lib_openssl=yes
    ;;
    *":"* )
	header="`echo $found | sed -e 's/:.*$//'`"
	lib="`echo $found | sed -e 's/^.*://'`"
      JABBERD_SSL_INCLUDES="-I$header"
      JABBERD_SSL_LIBS="-L$lib -R$lib -lssl -lcrypto"
      jabberd_lib_openssl=yes
    ;;
    * )
      JABBERD_SSL_INCLUDES="-I$found/include"
      JABBERD_SSL_LIBS="-L$found/lib -R$found/lib -lssl -lcrypto"
	jabberd_lib_openssl=yes
    ;;
  esac
])


dnl   JABBERD_LIB_OPENSSL_TRY(major, minor, fix, patch)
dnl
dnl   A subroutine of JABBERD_LIB_OPENSSL.
dnl
dnl   Check that a new-enough version of OpenSSL is installed.
dnl   "New enough" means no older than the version given by MAJOR,
dnl   MINOR, FIX and PATCH.  The result of the test is not cached; no
dnl   messages are printed.
dnl
dnl   Set the shell variable `jabberd_have_openssl' to `yes' if we found
dnl   an appropriate version installed, or `no' otherwise.
dnl
dnl   This macro uses the OpenSSL library function `SSLeay' to
dnl   find the version.  If the library installed doesn't have this
dnl   function, then this macro assumes it is too old.


AC_DEFUN(JABBERD_LIB_OPENSSL_TRY,
  [
    jabberd_lib_openssl_try_save_libs="$LIBS"

    jabberd_check_openssl_major=$1
    jabberd_check_openssl_minor=$2
    jabberd_check_openssl_fix=$3
    jabberd_check_openssl_patch=$4

    LIBS="$LIBS -lssl -lcrypto"

    AC_TRY_RUN(
      [
#include "openssl/opensslv.h"
#include "openssl/crypto.h"
#include <stdio.h>
main ()
{
  int major, minor, fix, patch;

  /* sanity; ensure that headers match the lib proper */
  if(SSLeay() != OPENSSL_VERSION_NUMBER)
    exit(1);
  
  /* extract version info */
  major = (OPENSSL_VERSION_NUMBER & 0xFF0000000L) >> 28;
  minor = (OPENSSL_VERSION_NUMBER & 0x00FF00000L) >> 20;
  fix =   (OPENSSL_VERSION_NUMBER & 0x0000FF000L) >> 12;
  patch = (OPENSSL_VERSION_NUMBER & 0x000000FF0L) >> 4;
  
  /* ensure that the lib is good enough for us */
  if(major < $jabberd_check_openssl_major)
    exit(1);
  if(major > $jabberd_check_openssl_major)
    exit(0);

  if(minor < $jabberd_check_openssl_minor)
    exit(1);
  if(minor > $jabberd_check_openssl_minor)
    exit(0);

  if(fix > $jabberd_check_openssl_fix)
    exit(0);

  if(patch >= $jabberd_check_openssl_patch)
    exit(0);

  exit(1);
}
      ],
      [jabberd_have_openssl=yes],
      [jabberd_have_openssl=no],
      [jabberd_have_openssl=yes]
    )

  LIBS="$jabberd_lib_openssl_try_save_libs"
  ]
)
