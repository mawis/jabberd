#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

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

#ifdef __cplusplus
extern "C" {
#endif


#ifndef HAVE_SNPRINTF
extern int ap_snprintf(char *, size_t, const char *, ...);
#define snprintf ap_snprintf
#endif

#ifndef HAVE_VSNPRINTF
extern int ap_vsnprintf(char *, size_t, const char *, va_list ap);
#define vsnprintf ap_vsnprintf
#endif

/* --------------------------------------------------------- */
/*                                                           */
/* Pool-based memory management routines                     */
/*                                                           */
/* --------------------------------------------------------- */

#ifdef POOL_DEBUG
# define POOL_NUM 40009 
#endif

/* pheap - singular allocation of memory */
struct pheap
{
    void *block;
    int size, used;
};

/* pool_cleaner - callback type which is associated
   with a pool entry; invoked when the pool entry is 
   free'd */
typedef void (*pool_cleaner)(void *arg);

/* pfree - a linked list node which stores an
   allocation chunk, plus a callback */
struct pfree
{
    pool_cleaner f;
    void *arg;
    struct pheap *heap;
    struct pfree *next;
};

/* pool - base node for a pool. Maintains a linked list
   of pool entries (pfree) */
typedef struct pool_struct
{
    int size;
    struct pfree *cleanup;
    struct pheap *heap;
#ifdef POOL_DEBUG
    char name[8], zone[32];
    int lsize;
} _pool, *pool;
#define pool_new() _pool_new(__FILE__,__LINE__) 
#define pool_heap(i) _pool_new_heap(i,__FILE__,__LINE__) 
#else
} _pool, *pool;
#define pool_heap(i) _pool_new_heap(i,NULL,0)
#define pool_new() _pool_new(NULL,0)
#endif

pool _pool_new(char *zone, int line); /* new pool :) */
pool _pool_new_heap(int size, char *zone, int line); /* creates a new memory pool with an initial heap size */
void *pmalloc(pool p, int size); /* wrapper around malloc, takes from the pool, cleaned up automatically */
void *pmalloco(pool p, int size); /* YAPW for zeroing the block */
char *pstrdup(pool p, const char *src); /* wrapper around strdup, gains mem from pool */
void pool_stat(int full); /* print to stderr the changed pools and reset */
char *pstrdupx(pool p, const char *src, int len); /* use given len */
void pool_cleanup(pool p, pool_cleaner f, void *arg); /* calls f(arg) before the pool is freed during cleanup */
void pool_free(pool p); /* calls the cleanup functions, frees all the data on the pool, and deletes the pool itself */
int pool_size(pool p); /* returns total bytes allocated in this pool */




/* --------------------------------------------------------- */
/*                                                           */
/* String management routines                                */
/*                                                           */
/* --------------------------------------------------------- */
char *j_strdup(const char *str); /* provides NULL safe strdup wrapper */
char *j_strcat(char *dest, char *txt); /* strcpy() clone */
int j_strcmp(const char *a, const char *b); /* provides NULL safe strcmp wrapper */
int j_strcasecmp(const char *a, const char *b); /* provides NULL safe strcasecmp wrapper */
int j_strncmp(const char *a, const char *b, int i); /* provides NULL safe strncmp wrapper */
int j_strncasecmp(const char *a, const char *b, int i); /* provides NULL safe strncasecmp wrapper */
int j_strlen(const char *a); /* provides NULL safe strlen wrapper */
int j_atoi(const char *a, int def); /* checks for NULL and uses default instead, convienence */
void str_b64decode(char *str); /* what it says */
char *j_attr(const char** atts, char *attr); /* decode attr's (from expat) */

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

char *shahash(char *str);	/* NOT THREAD SAFE */
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


/* --------------------------------------------------------- */
/*                                                           */
/* Hashtable functions                                       */
/*                                                           */
/* --------------------------------------------------------- */
typedef struct xhn_struct
{
    struct xhn_struct *next;
    const char *key;
    void *val;
} *xhn, _xhn;

typedef struct xht_struct
{
    pool p;
    int prime;
    int dirty;
    int count;
    struct xhn_struct *zen;
} *xht, _xht;

xht xhash_new(int prime);
void xhash_put(xht h, const char *key, void *val);
void *xhash_get(xht h, const char *key);
void *xhash_getx(xht h, const char *key, int len);
void xhash_zap(xht h, const char *key);
void xhash_free(xht h);
typedef void (*xhash_walker)(xht h, const char *key, void *val, void *arg);
void xhash_walk(xht h, xhash_walker w, void *arg);
int xhash_dirty(xht h);
int xhash_count(xht h);
pool xhash_pool(xht h);

/* --------------------------------------------------------- */
/*                                                           */
/* XML escaping utils                                        */
/*                                                           */
/* --------------------------------------------------------- */
char *strescape(pool p, char *buf, int len); /* Escape <>&'" chars */
char *strunescape(pool p, char *buf);


/* --------------------------------------------------------- */
/*                                                           */
/* String pools (spool) functions                            */
/*                                                           */
/* --------------------------------------------------------- */
struct spool_node
{
    char *c;
    struct spool_node *next;
};

typedef struct spool_struct
{
    pool p;
    int len;
    struct spool_node *last;
    struct spool_node *first;
} *spool;

spool spool_new(pool p); /* create a string pool */
void spooler(spool s, ...); /* append all the char * args to the pool, terminate args with s again */
char *spool_print(spool s); /* return a big string */
void spool_add(spool s, char *str); /* add a single string to the pool */
void spool_escape(spool s, char *raw, int len); /* add and xml escape a single string to the pool */
char *spools(pool p, ...); /* wrap all the spooler stuff in one function, the happy fun ball! */


/* --------------------------------------------------------- */
/*                                                           */
/* JID structures & constants                                */
/*                                                           */
/* --------------------------------------------------------- */
#define JID_RESOURCE 1
#define JID_USER     2
#define JID_SERVER   4

#ifdef LIBIDN

#  include <stringprep.h>

/**
 * @brief datastructure to hold the stringprep caches
 */
typedef struct _jid_prep_entry_st {
    char *preped;		/**< the result of the preparation, NULL if unchanged */
    time_t last_used;		/**< when this result has been used the last time */
    unsigned int used_count;	/**< how often this result has been used */
    int size;			/**< the min buffer size needed to hold the result (strlen+1) */
} *_jid_prep_entry_t;

/**
 * @brief string preparation cache
 */
typedef struct _jid_prep_cache_st {
    xht hashtable;		/**< the hash table containing the preped strings */
    const Stringprep_profile *profile;
    				/**< the stringprep profile used for this cache */
} *_jid_prep_cache_t;

/**
 * @brief environment for JID preparation
 *
 * This data structure holds the three used caches for JID preparation
 */
typedef struct _jid_environment {
    _jid_prep_cache_t nodes;	/* prepared nodes */
    _jid_prep_cache_t domains;	/* prepared domains */
    _jid_prep_cache_t resources;/* prepared resources */
} *jid_environment_t;
#endif

typedef struct jid_struct
{ 
    pool               p;
    char*              resource;
    char*              user;
    char*              server;
    char*              full;
#ifdef LIBIDN
    jid_environment_t  environment;	/**< used stringprep caches */
#endif
    struct jid_struct *next; /* for lists of jids */
} *jid;
  
void	jid_clean_cache(jid_environment_t environment); /* cleanup the stringprep caches */
void	jid_free_environment(jid_environment_t environment); /* free a jid preparation environment */
jid_environment_t jid_new_environment();       /* Create a jid preparation environment */
jid     jid_new(pool p, jid_environment_t environment, char *idstr); /* Creates a jabber id from the idstr */
jid     jid_newx(pool p, jid_environment_t environment, char *idstr, int len); /* same but with given len */
void    jid_set(jid id, const char *str, int item); /* Individually sets jid components */
char*   jid_full(jid id);		       /* Builds a string type=user/resource@server from the jid data */
int     jid_cmp(jid a, jid b);		       /* Compares two jid's, returns 0 for perfect match */
int     jid_cmpx(jid a, jid b, int parts);     /* Compares just the parts specified as JID_|JID_ */
jid     jid_append(jid a, jid b);	       /* Appending b to a (list), no dups */
jid     jid_user(jid a);                       /* returns the same jid but just of the user@host part */


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

# define MAX_LOG_LINE        (1024)
#endif

typedef void *log_t;

extern log_t    log_new(char *);
extern void     log_write(log_t, int, const char *, ...);
extern void     log_free(log_t);
#ifdef USE_SSL
void log_ssl_errors(log_t l, int level);
#endif

/* config files */
struct config_elem_st
{
    char **values;
    int nvalues;
    char ***attrs;
};
typedef struct config_elem_st *config_elem_t;

/* pretend to be an actual type */
typedef xht config_t;

extern config_t         config_new(void);
extern int              config_load(config_t, char *);
extern config_elem_t    config_get(config_t, char *);
extern char             *config_get_one(config_t, char *, int);
extern int              config_count(config_t, char *);
extern char             *config_get_attr(config_t, char *, int, char *);
extern void             config_free(config_t);


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

/* copy a nad */
nad_t nad_copy(nad_t nad);

/* free that nad */
void nad_free(nad_t nad);

/* find the next element with this name/depth */
/* 0 for siblings, 1 for children and so on */
int nad_find_elem(nad_t nad, int elem, char *name, int depth);

/* find the first matching attribute (and optionally value) */
int nad_find_attr(nad_t nad, int elem, char *name, char *val);

/* reset or store the given attribute */
void nad_set_attr(nad_t nad, int elem, char *name, char *val);

/* insert and return a new element as a child of this one */
int nad_insert_elem(nad_t nad, int elem, char *name, char *cdata);

/* wrap an element with another element */
void nad_wrap_elem(nad_t nad, int elem, char *name);

/* append and return a new element */
int nad_append_elem(nad_t nad, char *name, int depth);

/* append attribs to the last element */
int nad_append_attr(nad_t nad, char *name, char *val);

/* append more cdata to the last element */
void nad_append_cdata(nad_t nad, const char *cdata, int len, int depth);

/* create a string representation of the given element (and children), point references to it */
void nad_print(nad_t nad, int elem, char **xml, int *len);

/* serialize and deserialize a nad */
void nad_serialize(nad_t nad, char **buf, int *len);
nad_t nad_deserialize(nad_cache_t cache, char *buf);

/* these are some helpful macros */
#define NAD_ENAME(N,E) (N->cdata + N->elems[E].iname)
#define NAD_ENAME_L(N,E) (N->elems[E].lname)
#define NAD_CDATA(N,E) (N->cdata + N->elems[E].icdata)
#define NAD_CDATA_L(N,E) (N->elems[E].lcdata)
#define NAD_ANAME(N,A) (N->cdata + N->attrs[A].iname)
#define NAD_ANAME_L(N,A) (N->attrs[A].lname)
#define NAD_AVAL(N,A) (N->cdata + N->attrs[A].ival)
#define NAD_AVAL_L(N,A) (N->attrs[A].lval)


#ifdef __cplusplus
}
#endif

#endif	/* INCL_UTIL_H */


