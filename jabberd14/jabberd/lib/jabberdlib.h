/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

/**
 * @file jabberdlib.h
 * @brief Header file for the files in jabberd/lib
 */

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#ifndef JABBERDLIB_H
#define JABBERDLIB_H

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <stdio.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <strings.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <pth.h>

#include <expat.h>

#ifdef __cplusplus
extern "C" {
#endif

/*******************************
 * functions defined in pool.c *
 *******************************/

/**
 * function type for functions, that can be registered to be called if a pool is freed
 *
 * @param arg an argument is passed, that as defined by the user when registering the callback
 */
typedef void (*pool_cleaner)(void *arg);

/**
 * a single allocation of memory
 */
struct pheap {
    void *block;	/**< pointer to the memory */
    int size;		/**< size of the memory */
    int used;		/**< if the block is used */
};

struct pfree {
    pool_cleaner f;
    void *arg;
    struct pheap *heap;
    struct pfree *next;		/**< pointer to the next list entry, NULL for last */
};

typedef struct pool_struct {
    int size;
    struct pfree *cleanup;
    struct pheap *heap;
    /* well very bad that our interface/structure size changes if we define POOL_DEBUG */
#ifdef POOL_DEBUG
    char name[8];
    char zone[32];
    int lsize;
#endif
} _pool, *pool;

#ifdef POOL_DEBUG
# define pool_new()	_pool_new(__FILE__, __LINE__)
# define pool_heap(i)	_pool_new_heap(i, __FILE__, __LINE__)
#else
# define pool_new()	_pool_new(NULL, 0)
# define pool_heap(i)	_pool_new_heap(i, NULL, 0)
#endif

inline void *_retried__malloc(size_t size);
pool _pool_new(char *zone, int line);
pool _pool_new_heap(int size, char *zone, int line);
void *pmalloc(pool p, int size);
void *pmalloc_x(pool p, int size, char c);
void *pmalloco(pool p, int size);
char *pstrdup(pool p, const char *src);
char *pstrdupx(pool p, const char *src);
int pool_size(pool p);
void pool_free(pool p);
void pool_cleanup(pool p, pool_cleaner f, void *arg);
void pool_stat(int full);

/**********************************
 * functions defined in xmlnode.c *
 **********************************/

#define NTYPE_TAG    0	/**< type of a DOM object containing a tag element */
#define NTYPE_ATTRIB 1	/**< type of a DOM object containing an attribute element */
#define NTYPE_CDATA  2	/**< type of a DOM object containing a CDATA element */

#define NTYPE_LAST   2	/**< has to be the max(NTYPE_*) */
#define NTYPE_UNDEF  -1	/**< return value for "no type" */

/**
 * type containing a node in a xmlnode dom
 *
 * never access the field directly, use the accessor methods
 */
typedef struct xmlnode_t {
    char		*name;		/**< name of the node */
    unsigned short	type;		/**< type of a node, one of NTYPE_TAG, NTYPE_ATTRIB, or NTYPE_CDATA */
    char		*data;		/**< data of a node */
    int			data_sz;	/**< size of the data */
    int			complete;
    pool		p;		/**< memory pool */
    struct xmlnode_t	*parent;	/**< parent node */
    struct xmlnode_t	*firstchild;	/**< first child node */
    struct xmlnode_t	*lastchild;	/**< last child node */
    struct xmlnode_t	*prev;		/**< previous node */
    struct xmlnode_t	*next;		/**< next node */
    struct xmlnode_t	*firstattrib;	/**< first attribute node */
    struct xmlnode_t	*lastattrib;	/**< last attribute node */
} *xmlnode, _xmlnode;

xmlnode xmlnode_new_tag(const char* name);
xmlnode xmlnode_new_tag_pool(pool p, const char* name);
xmlnode xmlnode_insert_tag(xmlnode parent, const char* name);
xmlnode xmlnode_insert_cdata(xmlnode parent, const char* CDATA, unsigned int size);
xmlnode xmlnode_get_tag(xmlnode parent, const char* name);
char *xmlnode_get_tag_data(xmlnode parent, const char *name);
void xmlnode_put_attrib(xmlnode owner, const char* name, const char* value);
char* xmlnode_get_attrib(xmlnode owner, const char* name);
void xmlnode_put_vattrib(xmlnode owner, const char* name, void *value);
void* xmlnode_get_vattrib(xmlnode owner, const char* name);
xmlnode xmlnode_get_firstattrib(xmlnode parent);
xmlnode xmlnode_get_firstchild(xmlnode parent);
xmlnode xmlnode_get_lastchild(xmlnode parent);
xmlnode xmlnode_get_nextsibling(xmlnode sibling);
xmlnode xmlnode_get_prevsibling(xmlnode sibling);
xmlnode xmlnode_get_parent(xmlnode node);
char* xmlnode_get_name(xmlnode node);
char* xmlnode_get_data(xmlnode node);
int xmlnode_get_datasz(xmlnode node);
int xmlnode_get_type(xmlnode node);
int xmlnode_has_children(xmlnode node);
int xmlnode_has_attribs(xmlnode node);
pool xmlnode_pool(xmlnode node);
void xmlnode_hide(xmlnode child);
void xmlnode_hide_attrib(xmlnode parent, const char *name);
char *xmlnode2str(xmlnode node);
char* xmlnode2tstr(xmlnode node);
int xmlnode_cmp(xmlnode a, xmlnode b);
xmlnode xmlnode_insert_tag_node(xmlnode parent, xmlnode node);
void xmlnode_insert_node(xmlnode parent, xmlnode node);
xmlnode xmlnode_dup(xmlnode x);
xmlnode xmlnode_dup_pool(pool p, xmlnode x);
xmlnode xmlnode_wrap(xmlnode x,const char *wrapper);
void xmlnode_free(xmlnode node);

/*********************************
 * functions defined in base64.c *
 *********************************/
    
int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);
void str_b64decode(char* str);
size_t base64_decode(char *source, unsigned char *target, size_t targetlen);

/********************************
 * functions defined in crc32.c *
 ********************************/

void crc32_r(const char *str, char crc32buf[9]);

/********************************
 * functions defined in expat.c *
 ********************************/

/*
void expat_startElement(void* userdata, const char* name, const char** atts);
void expat_endElement(void* userdata, const char* name);
void expat_charData(void* userdata, const char* s, int len);
*/
xmlnode xmlnode_str(char *str, int len);
xmlnode xmlnode_file(char *file);
char* xmlnode_file_borked(char *file);
int xmlnode2file(char *file, xmlnode node);
int xmlnode2file_limited(char *file, xmlnode node, size_t sizelimit);
xmlnode _xmlnode_new(pool p, const char* name, unsigned int type);
/*
void xmlnode_put_expat_attribs(xmlnode owner, const char** atts);
*/

/**********************************
 * functions defined in genhash.c *
 **********************************/

#ifdef INCLUDE_LEGACY
typedef void *KEYHASHFUNC;
typedef void *KEYCOMPAREFUNC;
typedef int (*TABLEWALKFUNC)(void *user_data, const void *key, void *data);
typedef void *HASHTABLE;

HASHTABLE ghash_create(int buckets, KEYHASHFUNC hash, KEYCOMPAREFUNC cmp);
HASHTABLE ghash_create_pool(pool p, int buckets, KEYHASHFUNC hash, KEYCOMPAREFUNC cmp);
void ghash_destroy(HASHTABLE tbl);
void *ghash_get(HASHTABLE tbl, const void *key);
int ghash_put(HASHTABLE tbl, const void *key, void *value);
int ghash_remove(HASHTABLE tbl, const void *key);
int ghash_walk(HASHTABLE tbl, TABLEWALKFUNC func, void *user_data);
/*
int str_hash_code(const char *s);
*/
#endif

/******************************
 * functions defined in jid.c *
 ******************************/

/* for comparing JIDs with jid_cmpx() */
#define JID_RESOURCE	1	/**< compare the resource in jid_cmpx() */
#define JID_USER	2	/**< compare the user part in jid_cmpx() */
#define JID_SERVER	4	/**< compare the domain part in jid_cmpx() */

typedef struct jid_struct {
    pool	p;		/**< memory pool */
    char	*resource;	/**< the resource of the JID */
    char	*user;		/**< the user part in a JID */
    char	*server;	/**< the domain part in a JID */
    char	*full;		/**< cache for generated printed version of the full JID */
    struct jid_struct *next;	/**< to build lists of JIDs: pointer to the next list element */
} *jid, _jid;

#ifdef LIBIDN
void jid_clean_cache();
void jid_stop_caching();
void jid_init_cache();
#endif

jid jid_safe(jid id);
jid jid_new(pool p, char *idstr);
void jid_set(jid id, char *str, int item);
char *jid_full(jid id);
xmlnode jid_xres(jid id);
int jid_cmp(jid a, jid b);
int jid_cmpx(jid a, jid b, int parts);
jid jid_append(jid a, jid b);
xmlnode jid_nodescan(jid id, xmlnode x);
jid jid_user(jid a);

/**********************************
 * functions defined in jpacket.c *
 **********************************/

#define JPACKET_UNKNOWN		0x00
#define JPACKET_MESSAGE		0x01
#define JPACKET_PRESENCE	0x02
#define JPACKET_IQ		0x04
#define JPACKET_S10N		0x08

#define JPACKET__UNKNOWN	0
#define JPACKET__NONE		1
#define JPACKET__ERROR		2
#define JPACKET__CHAT		3
#define JPACKET__GROUPCHAT	4
#define JPACKET__GET		5
#define JPACKET__SET		6
#define JPACKET__RESULT		7
#define JPACKET__SUBSCRIBE	8
#define JPACKET__SUBSCRIBED	9
#define JPACKET__UNSUBSCRIBE	10
#define JPACKET__UNSUBSCRIBED	11
#define JPACKET__AVAILABLE	12
#define JPACKET__UNAVAILABLE	13
#define JPACKET__PROBE		14
#define JPACKET__HEADLINE	15
#define JPACKET__INVISIBLE	16

/** structure holding a jpacket */
typedef struct jpacket_struct {
    unsigned char	type;	/**< stanza type (JPACKET_*) */
    int			subtype;/**< subtype of a stanza (JPACKET__*) */
    int			flag;	/**< used by the session manager to flag messages, that are read from offline storage */
    void		*aux1;	/**< pointer to data passed around with a jpacket, multiple use inside jsm */
    xmlnode		x;	/**< the xmlnode that is contained in this jpacket */
    jid			to;	/**< the destination of the jpacket */
    jid			from;	/**< the source of the jpacket */
    char		*iqns;	/**< the primary namespace of a query in an iq stanza */
    xmlnode		iq;	/**< the content of an iq stanza */
    pool		p;	/**< the memory pool used for this jpacket */
} *jpacket, _jpacket;

jpacket jpacket_new(xmlnode x);
jpacket jpacket_reset(jpacket p);
int jpacket_subtype(jpacket p);

/********************************
 * functions defined in jutil.c *
 ********************************/

/** structure containing legacy errors */
typedef struct terror_struct {
    int		code;		/**< numerical error code */
    char	msg[64];	/**< textual error message */
} terror;

/** structure containing XMPP errors */
typedef struct xterror_struct {
    int		code;		/**< numerical error code (for legacy systems) */
    char	msg[256];	/**< textual error message */
    char	type[9];	/**< type of error */
    char	condition[64];	/**< condition of the error */
} xterror;

/* predefined legacy errors */
#define TERROR_AUTH		(terror){401, "Unauthorized"}
#define TERROR_BAD		(terror){400, "Bad Request"}
#define TERROR_CONFLICT		(terror){409, "Conflict"}
#define TERROR_DISCONNECTED	(terror){510, "Disconnected"}
#define TERROR_EXTERNAL		(terror){502, "Remote Server Error"}
#define TERROR_EXTTIMEOUT	(terror){504, "Remote Server Timeout"}
#define TERROR_FORBIDDEN	(terror){403, "Forbidden"}
#define TERROR_INTERNAL		(terror){500, "Internal Server Error"}
#define TERROR_NOTACCEPTABLE	(terror){406, "Not Acceptable"}
#define TERROR_NOTALLOWED	(terror){405, "Not Allowed"}
#define TERROR_NOTFOUND		(terror){404, "Not Found"}
#define TERROR_NOTIMPL		(terror){501, "Not Implemented"}
#define TERROR_PAY		(terror){402, "Payment Required"}
#define TERROR_REGISTER		(terror){407, "Registration Required"}
#define TERROR_REQTIMEOUT	(terror){408, "Request Timeout"}
#define TERROR_UNAVAIL		(terror){503, "Service Unavailable"}

/** flag that we have xterror_struct */
#define HAS_XTERROR

/* predefined XMPP errors */
#define XTERROR_BAD             (xterror){400,"Bad Request","modify","bad-request"}
#define XTERROR_CONFLICT        (xterror){409,"Conflict","cancel","conflict"}
#define XTERROR_NOTIMPL         (xterror){501,"Not Implemented","cancel","feature-not-implemented"}
#define XTERROR_FORBIDDEN       (xterror){403,"Forbidden","auth","forbidden"}
#define XTERROR_GONE            (xterror){302,"Gone","modify","gone"}
#define XTERROR_INTERNAL        (xterror){500,"Internal Server Error","wait","internal-server-error"}
#define XTERROR_NOTFOUND        (xterror){404,"Not Found","cancel","item-not-found"}
#define XTERROR_JIDMALFORMED    (xterror){400,"Bad Request","modify","jid-malformed"}
#define XTERROR_NOTACCEPTABLE   (xterror){406,"Not Acceptable","modify","not-acceptable"}
#define XTERROR_NOTALLOWED      (xterror){405,"Not Allowed","cancel","not-allowed"}
#define XTERROR_AUTH            (xterror){401,"Unauthorized","auth","not-authorized"}
#define XTERROR_PAY             (xterror){402,"Payment Required","auth","payment-required"}
#define XTERROR_RECIPIENTUNAVAIL (xterror){404,"Receipient Is Unavailable","wait","recipient-unavailable"}
#define XTERROR_REDIRECT        (xterror){302,"Redirect","modify","redirect"}
#define XTERROR_REGISTER        (xterror){407,"Registration Required","auth","registration-required"}
#define XTERROR_REMOTENOTFOUND  (xterror){404,"Remote Server Not Found","cancel","remote-server-not-found"}
#define XTERROR_REMOTETIMEOUT   (xterror){504,"Remote Server Timeout","wait","remote-server-timeout"}
#define XTERROR_RESCONSTRAINT   (xterror){500,"Resource Constraint","wait","resource-constraint"}
#define XTERROR_UNAVAIL         (xterror){503,"Service Unavailable","cancel","service-unavailable"}
#define XTERROR_SUBSCRIPTIONREQ (xterror){407,"Subscription Required","auth","subscription-required"}
#define XTERROR_UNDEF_CANCEL    (xterror){500,NULL,"cancel","undefined-condition"}
#define XTERROR_UNDEF_CONTINUE  (xterror){500,NULL,"continue","undefined-condition"}
#define XTERROR_UNDEF_MODIFY    (xterror){500,NULL,"modify","undefined-condition"}
#define XTERROR_UNDEF_AUTH      (xterror){500,NULL,"auth","undefined-condition"}
#define XTERROR_UNDEF_WAIT      (xterror){500,NULL,"wait","undefined-condition"}
#define XTERROR_UNEXPECTED      (xterror){400,"Unexpected Request","wait","unexpected-request"}

#define XTERROR_REQTIMEOUT      (xterror){408,"Request Timeout","wait","remote-server-timeout"}
#define XTERROR_EXTERNAL        (xterror){502,"Remote Server Error","wait","service-unavailable"}
#define XTERROR_EXTTIMEOUT      (xterror){504,"Remote Server Timeout","wait","remote-server-timeout"}
#define XTERROR_DISCONNECTED    (xterror){510,"Disconnected","cancel","service-unavailable"}


xmlnode jutil_presnew(int type, char *to, char *status);
xmlnode jutil_iqnew(int type, char *ns);
xmlnode jutil_msgnew(char *type, char *to, char *subj, char *body);
xmlnode jutil_header(char* xmlns, char* server);
int jutil_priority(xmlnode x);
void jutil_tofrom(xmlnode x);
xmlnode jutil_iqresult(xmlnode x);
char *jutil_timestamp(void);
void jutil_error_map(terror old, xterror *mapped);
void jutil_error_xmpp(xmlnode x, xterror E);
void jutil_error(xmlnode x, terror E);
void jutil_delay(xmlnode msg, char *reason);
char *jutil_regkey(char *key, char *seed);	/* XXX ??? */

/********************************
 * functions defined in karma.c *
 ********************************/

/* karma defaults */
#define KARMA_READ_MAX(k)	(abs(k)*100)
#define KARMA_INIT		5
#define KARMA_HEARTBEAT		2
#define KARMA_MAX		10
#define KARMA_INC		1
#define KARMA_DEC		0

#define KARMA_PENALTY		-5
#define KARMA_RESTORE		5
#define KARMA_RESETMETER	0

/** structure holding a karma state */
struct karma {
    int		init;
    int		reset_meter;
    int		val;
    long	bytes;
    int		max;
    int		inc;
    int		dec;
    int		penalty;
    int		restore;
    time_t	last_update;
};

void karma_copy(struct karma *new, struct karma *old);
struct karma *karma_new(pool p);
void karma_increment(struct karma *k);
void karma_decrement(struct karma *k, long bytes_read);
int karma_check(struct karma *k,long bytes_read);

/*********************************
 * functions defined in pproxy.c *
 *********************************/

#ifdef INCLUDE_LEGACY

typedef struct ppdb_struct {
    jid			id;
    int			pri;
    xmlnode		x;
    struct ppdb_struct	*user;
    pool		p;
    struct ppdb_struct	*next;
} *ppdb, _ppdb;

ppdb _ppdb_new(pool p, jid id);
ppdb _ppdb_get(ppdb db, jid id);
ppdb ppdb_insert(ppdb db, jid id, xmlnode x);
xmlnode ppdb_primary(ppdb db, jid id);
xmlnode ppdb_get(ppdb db, jid id);
void ppdb_free(ppdb db);
#endif

/*******************************
 * functions defined in rate.c *
 *******************************/

/** structure holding data for rate limiting */
typedef struct jlimit_struct {
    char	*key;
    int		start;
    int		points;
    int		maxt;
    int		maxp;
    pool	p;
} *jlimit, _jlimit;

jlimit jlimit_new(int maxt, int maxp);
void jlimit_free(jlimit r);
int jlimit_check(jlimit r, char *key, int points);

/******************************
 * functions defined in sha.c *
 ******************************/

char *shahash(char *str);
void shahash_r(const char* str, char hashbuf[41]);

/*********************************
 * functions defined in socket.c *
 *********************************/

#define NETSOCKET_SERVER 0 	/**< type of a local listening socket */
#define NETSOCKET_CLIENT 1 	/**< type of a connection socket */
#define NETSOCKET_UDP 2    	/**< type of a UDP connection socket */

int make_netsocket(u_short port, char *host, int type);
struct in_addr *make_addr(char *host);
#ifdef WITH_IPV6
struct in6_addr *make_addr_ipv6(char *host);
#endif

#ifdef INCLUDE_LEGACY
int set_fd_close_on_exec(int fd, int flag);
#endif

/******************************
 * functions defined in str.c *
 ******************************/

/** entry in a spool (this is just a list) */
struct spool_node {
    char *c;			/**< the entry */
    struct spool_node *next;	/**< pointer to the next element in the list */
};

/** type for a spool */
typedef struct spool_struct {
    pool p;			/**< memory pool used */
    int len;			/**< length of the content in bytes of characters */
    struct spool_node *last;	/**< pointer to the end of the list */
    struct spool_node *first;	/**< pointer to the head of the list */
} *spool, _spool;

char *j_strdup(const char *str);
char *j_strcat(char *dest, char *txt);
int j_strcmp(const char *a, const char *b);
int j_strcasecmp(const char *a, const char *b);
int j_strncmp(const char *a, const char *b, int i);
int j_strncasecmp(const char *a, const char *b, int i);
int j_strlen(const char *a);
int j_atoi(const char *a, int def);
spool spool_new(pool p);
void spool_add(spool s, char *str);
void spooler(spool s, ...);
char *spool_print(spool s);
char *spools(pool p, ...);
char *strunescape(pool p, char *buf);
char *strescape(pool p, char *buf);
char *zonestr(char *file, int line);

/** get filename and line number in the sourcecode for logging */
#define ZONE zonestr(__FILE__,__LINE__)

/********************************
 * functions defined in xhash.c *
 ********************************/

/** structure holding a list of nodes in a hash */
typedef struct xhn_struct {
    struct xhn_struct *next;	/**< next list element (another value for the same hash value) */
    const char *key;		/**< key for this element */
    void *val;			/**< the element/value */
} *xhn, _xhn;

/** structure representing a hashtable */
typedef struct xht_struct {
    pool p;			/**< memory pool used for this hash table */
    int prime;			/**< prime used for hashing keys */
    struct xhn_struct *zen;	/**< array (!) of xhn_struct elements, one for each hash value */
} *xht, _xht;

/** function type for a hash walker function (used to iterate over the data in an xhash)
 *
 * @param h the xhash that is walked
 * @param key the key for which the xhash_walker() function is called
 * @param val the value asocciated with this key
 * @param arg argument provieded by the caller when iteration was requested
 */
typedef void (*xhash_walker)(xht h, const char *key, void *val, void *arg);

xht xhash_new(int prime);
void xhash_put(xht h, const char *key, void *val);
void *xhash_get(xht h, const char *key);
void xhash_zap(xht h, const char *key);
void xhash_free(xht h);
void xhash_walk(xht h, xhash_walker w, void *arg);

/**********************************
 * functions defined in xstream.c *
 **********************************/

#define XSTREAM_MAXNODE 1000000
#define XSTREAM_MAXDEPTH 100

#define XSTREAM_ROOT 0 /**< event: root element read */
#define XSTREAM_NODE 1 /**< event: stanza read */
#define XSTREAM_CLOSE 2 /**< event: stream closed */
#define XSTREAM_ERR 4 /**< event: error occured */

/**
 * callback function for xstream events
 *
 * @param type type of event (XSTREAM_ROOT, XSTREAM_NODE, XSTREAM_CLOSE, or XSTREAM_ERR)
 * @param x the read node (if any)
 * @param arg user provieded argument when registering the callback
 */
typedef void (*xstream_onNode)(int type, xmlnode x, void *arg);

/**
 * structure holding the data for an xstream
 */
typedef struct xstream_struct {
    XML_Parser		parser;		/**< expat parser instance for this stream */
    xmlnode		node;		/**< stanza being parsed or handled at present */
    char		*cdata;
    int			cdata_len;
    pool		p;		/**< memory pool */
    xstream_onNode	f;		/**< registered event callback function */
    void		*arg;		/**< argument for the callback function */
    int			status;
    int			depth;		/**< XML element nesting depth while parsing XML (to detect stanza end) */
} *xstream, _xstream;

/** error cause types for streams, see section 4.7.3 of RFC 3920 */
typedef enum {
    unknown_error_type,         /**< no errror type found, especially legacy stream errors */
    bad_format,                 /**< XML cannot be processed */
    bad_namespace_prefix,       /**< unsupported namespace prefix */
    conflict,                   /**< new stream has been initiated, that conflicts */
    connection_timeout,         /**< no traffic on the stream for some time */
    host_gone,                  /**< hostname is no longer hosted on this server */
    host_unknown,               /**< hostname is not known by this server */
    improper_addressing,        /**< missing to or from attribute */
    internal_server_error,      /**< missconfiguration or something like that */
    invalid_from,               /**< from address is not authorzed */
    invalid_id,                 /**< invalid stream id */
    invalid_namespace,          /**< wrong namespace for stream or dialback */
    invalid_xml,                /**< invalid XML was found */
    not_authorized,             /**< session not authorized */
    policy_violation,           /**< local service policy violated */
    remote_connection_failed,   /**< could not connect to a required remote entity for auth */
    resource_constraint,        /**< server lacks system resources */
    restricted_xml,             /**< received restricted XML features */
    see_other_host,             /**< redirection to another host */
    system_shutdown,            /**< server is being shut down */
    undefined_condition,        /**< something else ... */
    unsupported_encoding,       /**< stream is coded in an unsupported encoding */
    unsupported_stanza_type,    /**< stanza is not supported */
    unsupported_version,        /**< XMPP version requested is not supported */
    xml_not_well_formed         /**< received XML, that is not well formed */
} streamerr_reason;

/** severity of stream error (well all stream errors are unrecoverable, but we might log them different */
typedef enum {
    normal,                     /**< something that is just normal to happen (e.g. connection timeout) */
    configuration,              /**< something that seems to be caused by configuration errors (e.g. host gone) */
    feature_lack,               /**< something caused by features not supported by the other end (e.g. unsupported version) */
    unknown,                    /**< absolutely no clue */
    error                       /**< something that shut not happen in any case and seems to be an implementation error (e.g. xml_not_well_formed) */
} streamerr_severity;

/** structure that contains information about a stream error */
typedef struct streamerr_struct {
    char *text;                 /**< the error message */
    char *lang;                 /**< language of the error message */
    streamerr_reason reason;    /**< a generic cause type */
    streamerr_severity severity;/**< something that admin needs to care about? */
} *streamerr, _streamerr;

xstream xstream_new(pool p, xstream_onNode f, void *arg);
int xstream_eat(xstream xs, char *buff, int len);
xmlnode xstream_header(char *namespace, char *to, char *from);
char *xstream_header_char(xmlnode x);
void xstream_format_error(spool s, streamerr errstruct);
streamerr_severity xstream_parse_error(pool p, xmlnode errnode, streamerr errstruct);

/*************************
 * namespace definitions *
 *************************/

#define NSCHECK(x,n) (j_strcmp(xmlnode_get_attrib(x,"xmlns"),n) == 0)

#define NS_CLIENT	"jabber:client"
#define NS_SERVER	"jabber:server"
#define NS_DIALBACK	"jabber:server:dialback"
#define NS_AUTH		"jabber:iq:auth"
#define NS_AUTH_CRYPT	"jabber:iq:auth:crypt"
#define NS_REGISTER	"jabber:iq:register"
#define NS_ROSTER	"jabber:iq:roster"
#define NS_OFFLINE	"jabber:x:offline"
#define NS_AGENT	"jabber:iq:agent"
#define NS_AGENTS	"jabber:iq:agents"
#define NS_DELAY	"jabber:x:delay"
#define NS_VERSION	"jabber:iq:version"
#define NS_TIME		"jabber:iq:time"
#define NS_VCARD	"vcard-temp"
#define NS_PRIVATE	"jabber:iq:private"
#define NS_SEARCH	"jabber:iq:search"
#define NS_OOB		"jabber:iq:oob"
#define NS_XOOB		"jabber:x:oob"
#define NS_ADMIN	"jabber:iq:admin"
#define NS_FILTER	"jabber:iq:filter"
#define NS_AUTH_0K	"jabber:iq:auth:0k"
#define NS_BROWSE	"jabber:iq:browse"
#define NS_EVENT	"jabber:x:event"
#define NS_CONFERENCE	"jabber:iq:conference"
#define NS_SIGNED	"jabber:x:signed"
#define NS_ENCRYPTED	"jabber:x:encrypted"
#define NS_GATEWAY	"jabber:iq:gateway"
#define NS_LAST		"jabber:iq:last"
#define NS_ENVELOPE	"jabber:x:envelope"
#define NS_EXPIRE	"jabber:x:expire"
#define NS_XHTML	"http://www.w3.org/1999/xhtml"
#define NS_DISCO_INFO	"http://jabber.org/protocol/disco#info"
#define NS_DISCO_ITEMS	"http://jabber.org/protocol/disco#items"
#define NS_IQ_AUTH	"http://jabber.org/features/iq-auth"
#define NS_REGISTER_FEATURE "http://jabber.org/features/iq-register"

#define NS_XDBGINSERT	"jabber:xdb:ginsert"
#define NS_XDBNSLIST	"jabber:xdb:nslist"

#define NS_XMPP_STANZAS	"urn:ietf:params:xml:ns:xmpp-stanzas"
#define NS_XMPP_TLS	"urn:ietf:params:xml:ns:xmpp-tls"
#define NS_XMPP_STREAMS	"urn:ietf:params:xml:ns:xmpp-streams"

#define NS_JABBERD_STOREDPRESENCE "http://jabberd.org/ns/storedpresence"
#define NS_JABBERD_HISTORY "http://jabberd.org/ns/history"



#ifdef __cplusplus
}
#endif

#endif	/* JABBERDLIB_H */
