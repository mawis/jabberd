#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "util2.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <strings.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#ifdef USE_SSL
# include <openssl/err.h>
#endif

/*
**  Arrange to use either varargs or stdargs
*/

#define MAXSHORTSTR	203		/* max short string length */
#define QUAD_T	unsigned long long

#ifdef __STDC__

#include <stdarg.h>

# define VA_LOCAL_DECL	va_list ap;
# define VA_START(f)	va_start(ap, f)
# define VA_END		va_end(ap)

#else /* __STDC__ */

# include <varargs.h>

# define VA_LOCAL_DECL	va_list ap;
# define VA_START(f)	va_start(ap)
# define VA_END		va_end(ap)

#endif /* __STDC__ */


#ifndef INCL_UTIL_H
#define INCL_UTIL_H

/* --------------------------------------------------------- */
/*                                                           */
/* SHA calculations                                          */
/*                                                           */
/* --------------------------------------------------------- */
#if (SIZEOF_INT == 4)
typedef unsigned int uint32;
#elif (SIZEOF_SHORT == 4)
typedef unsigned short uint32;
#else
typedef unsigned int uint32;
#endif /* HAVEUINT32 */

void shahash_r(const char* str, char hashbuf[40]); /* USE ME */

int strprintsha(char *dest, int *hashval);

typedef struct {
  unsigned long H[5];
  unsigned long W[80];
  int lenW;
  unsigned long sizeHi,sizeLo;
} j_SHA_CTX;

void shaInit(j_SHA_CTX *ctx);
void shaUpdate(j_SHA_CTX *ctx, unsigned char *dataIn, int len);
void shaFinal(j_SHA_CTX *ctx, unsigned char hashout[20]);
void shaBlock(unsigned char *dataIn, int len, unsigned char hashout[20]);


/* Logging */
#ifdef USE_SYSLOG
# include <syslog.h>
#else
# define LOG_EMERG   (0)
# define LOG_ALERT   (1)
# define LOG_CRIT    (2)
# define LOG_ERR     (3)
# define LOG_WARNING (4)
# define LOG_NOTICE  (5)
# define LOG_INFO    (6)
# define LOG_DEBUG   (7)
#endif

/* Not A DOM */

/* using nad:
 * 
 * nad is very simplistic, and requires all string handling to use a length.
 * apps using this must be aware of the structure and access it directly for most information.
 * nads can only be built by successively using the _append_ functions correctly.
 * after built, they can be modified using other functions, or by direct access.
 * to access cdata on an elem or attr, use nad->cdata + nad->xxx[index].ixxx for the start, and .lxxx for len.
 */

typedef struct nad_st **nad_cache_t;

struct nad_elem_st
{
    int iname, lname;
    int icdata, lcdata; /* cdata within this elem (up to first child) */
    int itail, ltail; /* cdata after this elem */
    int attr;
    int depth;
};

struct nad_attr_st
{
    int iname, lname;
    int ival, lval;
    int next;
};

typedef struct nad_st
{
    nad_cache_t cache;   /* he who gave us life */
    struct nad_elem_st *elems;
    struct nad_attr_st *attrs;
    char *cdata;
    int *depths; /* for tracking the last elem at a depth */
    int elen, alen, clen, dlen;
    int ecur, acur, ccur;
    struct nad_st *next; /* for keeping a list of nads */
} *nad_t;

/* create a new cache for nads */
nad_cache_t nad_cache_new(void);

/* free the cache */
void nad_cache_free(nad_cache_t cache);

/* create a new nad */
nad_t nad_new(nad_cache_t cache);

/* free that nad */
void nad_free(nad_t nad);

/* find the next element with this name/depth */
/* 0 for siblings, 1 for children and so on */
int nad_find_elem(nad_t nad, int elem, char *name, int depth);

/* find the first matching attribute (and optionally value) */
int nad_find_attr(nad_t nad, int elem, const char *name, const char *val);

/* reset or store the given attribute */
void nad_set_attr(nad_t nad, int elem, const char *name, const char *val);

/* insert and return a new element as a child of this one */
/* currently not needed in jadc2s
int nad_insert_elem(nad_t nad, int elem, char *name, char *cdata);
*/

/* wrap an element with another element */
void nad_wrap_elem(nad_t nad, int elem, char *name);

/* append and return a new element */
int nad_append_elem(nad_t nad, const char *name, int depth);

/* append attribs to the last element */
int nad_append_attr(nad_t nad, const char *name, const char *val);

/* append more cdata to the last element */
void nad_append_cdata(nad_t nad, const char *cdata, int len, int depth);

/* create a string representation of the given element (and children), point references to it */
std::string nad_print(nad_t nad, int elem);

/* these are some helpful macros */
#define NAD_ENAME(N,E) (N->cdata + N->elems[E].iname)
#define NAD_ENAME_L(N,E) (N->elems[E].lname)
#define NAD_CDATA(N,E) (N->cdata + N->elems[E].icdata)
#define NAD_CDATA_L(N,E) (N->elems[E].lcdata)
#define NAD_ANAME(N,A) (N->cdata + N->attrs[A].iname)
#define NAD_ANAME_L(N,A) (N->attrs[A].lname)
#define NAD_AVAL(N,A) (N->cdata + N->attrs[A].ival)
#define NAD_AVAL_L(N,A) (N->attrs[A].lval)


#endif	/* INCL_UTIL_H */


