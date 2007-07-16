/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @dir lib
 * @brief Contains basic functionality, that is needed to form the server and its components
 *
 * In this directory there is the basic functionality on which the jabber server is build.
 *
 * Maybe the most basic file in here is pool.cc which contains the memory management of
 * jabberd14. Memory in jabberd14 is managed in this pools, which means, that all memory allocated
 * on a pool gets freed together when this pool is freed. This allows, that we do not need
 * that many single memory freeings, and therefore the risk that freeing memory is forgotten gets
 * reduced.
 *
 * Another basic module is in jid.cc which contains the functionality to manage XMPP addresses
 * (JIDs). It can be used to modify and compare JIDs as well as to get them normalized.
 *
 * The third most basic module is in xmlnode.cc which contains a DOM-like interface to XML
 * trees. Based on this XML interface jabberd14 builds the jpacket_struct which combines an
 * XML document (a stanza) with fields of relevant information about this stanza (stanza
 * type, sender and receipient, ...) jpackets are implemented in jpacket.cc.
 */

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#ifndef N_
#   define N_(n) (n)
#endif

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

#include <utility>
#include <list>

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


#ifndef INCL_LIB_H
#define INCL_LIB_H

#include <string>
#include <vector>
#include <sstream>
#include <stdexcept>

namespace xmppd {

    /**
     * generic base class for a hash function
     */
    class hash {
	public:
	    virtual void update(const std::string& data) =0;
	    virtual std::vector<uint8_t> final() =0;
	    std::string final_hex();
    };

    /**
     * the SHA-1 hashing algorithm
     */
    class sha1 : public hash {
	public:
	    /**
	     * construct a SHA-1 hashing instance
	     */
	    sha1();

	    /**
	     * add data to what the hash should be calculated for
	     *
	     * @param data the data that should get added
	     */
	    void update(const std::string& data);

	    /**
	     * add data to what the hash should be calculated for
	     *
	     * @param data the data that should get added
	     */
	    void update(const std::vector<uint8_t> data);

	    /**
	     * signal that all data has been added and request the hash
	     *
	     * @note use final_hex() to do the same but get a string result (hex version of the result)
	     *
	     * @return the hash value (binary)
	     */
	    std::vector<uint8_t> final();
	private:
	    /**
	     * if set to true, the hash has been padded and no more data can be added
	     */
	    bool padded;

	    /**
	     * temporarily storage for blocks that have not yet been completed
	     */
	    std::vector<uint8_t> current_block;

	    /**
	     * W[0] to W[79] as defined in the SHA-1 standard
	     */
	    std::vector<uint32_t> W;

	    /**
	     * which byte of a block we are currently adding
	     *
	     * W_pos because this defines where in W where are adding the byte
	     */
	    unsigned W_pos;

	    /**
	     * H0 to H4 as defined in the SHA-1 standard
	     */
	    std::vector<uint32_t> H;

	    /**
	     * do the hashing calculations on a complete block, that is now in W[]
	     */
	    void hash_block();

	    /**
	     * the function S^n as defined in the SHA-1 standard
	     */
	    inline static uint32_t circular_shift(uint32_t X, int n);

	    /**
	     * the function f(t;B,C,D) for 0 <= t <= 19 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_0_19(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the function f(t;B,C,D) for 20 <= t <= 39 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_20_39(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the function f(t;B,C,D) for 40 <= t <= 59 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_40_59(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the function f(t;B,C,D) for 60 <= t <= 79 as defined in the SHA-1 standard
	     */
	    inline static uint32_t f_60_79(uint32_t B, uint32_t C, uint32_t D);

	    /**
	     * the length of the message (l in the SHA-1 standard as well)
	     */
	    uint64_t l;
    };
}

#define ZONE zonestr(__FILE__,__LINE__)
char *zonestr(const char *file, int line);

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
#define pool_heap(i) _pool_new_heap(i, NULL, 0) 
#define pool_new() _pool_new(NULL, 0) 
#endif

pool _pool_new(char *zone, int line); /* new pool :) */
pool _pool_new_heap(int size, char *zone, int line); /* creates a new memory pool with an initial heap size */
void *pmalloc(pool p, int size); /* wrapper around malloc, takes from the pool, cleaned up automatically */
void *pmalloc_x(pool p, int size, char c); /* Wrapper around pmalloc which prefils buffer with c */
void *pmalloco(pool p, int size); /* YAPW for zeroing the block */
char *pstrdup(pool p, const char *src); /* wrapper around strdup, gains mem from pool */
void pool_stat(int full); /* print to stderr the changed pools and reset */
char *pstrdupx(pool p, const char *src); /* temp stub */
void pool_cleanup(pool p, pool_cleaner f, void *arg); /* calls f(arg) before the pool is freed during cleanup */
void pool_free(pool p); /* calls the cleanup functions, frees all the data on the pool, and deletes the pool itself */
int pool_size(pool p); /* returns total bytes allocated in this pool */




/* --------------------------------------------------------- */
/*                                                           */
/* Socket helper stuff                                       */
/*                                                           */
/* --------------------------------------------------------- */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define NETSOCKET_SERVER 0 /**< type of a local listening socket */
#define NETSOCKET_CLIENT 1 /**< type of a connection socket */
#define NETSOCKET_UDP 2    /**< type of a UDP connection socket */

#ifndef WIN32
int make_netsocket(u_short port, const char *host, int type);
struct in_addr *make_addr(const char *host);
#ifdef WITH_IPV6
struct in6_addr *make_addr_ipv6(const char *host);
#endif
#endif


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


/* --------------------------------------------------------- */
/*                                                           */
/* Base64 routines                                           */
/*                                                           */
/* --------------------------------------------------------- */
int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen);
size_t base64_decode(const char *source, unsigned char *target, size_t targetlen);


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
void shahash_r(const char* str, char hashbuf[41]); /* USE ME */
void shaBlock(unsigned char *dataIn, int len, unsigned char hashout[20]);

/* --------------------------------------------------------- */
/*                                                           */
/* SHA calculations                                          */
/*                                                           */
/* --------------------------------------------------------- */

void crc32_r(const char *str, char crc32buf[9]);

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
    xhn *zen;
} *xht, _xht;

xht xhash_new(int prime);
void xhash_put(xht h, const char *key, void *val);
void *xhash_get(xht h, const char *key);
void *xhash_get_by_domain(xht h, const char *domain);
void xhash_zap(xht h, const char *key);
void xhash_free(xht h);
typedef void (*xhash_walker)(xht h, const char *key, void *val, void *arg);
void xhash_walk(xht h, xhash_walker w, void *arg);

/* --------------------------------------------------------- */
/*                                                           */
/* XML escaping utils                                        */
/*                                                           */
/* --------------------------------------------------------- */
char *strescape(pool p, char *buf); /* Escape <>&'" chars */
char *strunescape(pool p, char *buf);
std::string strescape(std::string s);


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
void spool_add(spool s, const char *str); /* add a single char to the pool */
char *spools(pool p, ...); /* wrap all the spooler stuff in one function, the happy fun ball! */


/* --------------------------------------------------------- */
/*                                                           */
/* xmlnodes - Document Object Model                          */
/*                                                           */
/* --------------------------------------------------------- */
#define NTYPE_TAG    0	/**< xmlnode is an element (tag) */
#define NTYPE_ATTRIB 1	/**< xmlnode is an attribute node */
#define NTYPE_CDATA  2	/**< xmlnode is a text node (!) */

#define NTYPE_LAST   2	/**< highest possible value of xmlnode types */
#define NTYPE_UNDEF  -1	/**< xmlnode has no defined type */

#define XMLNS_SEPARATOR ' '	/**< character used to separate NS IRI from local name in expat callbacks */

/* -------------------------------------------------------------------------- 
   Node structure. Do not use directly! Always use accessor macros 
   and methods!
   -------------------------------------------------------------------------- */
typedef struct xmlnode_t {
     char*              name;		/**< local name of the xmlnode */
     char*		prefix;		/**< namespace prefix for this xmlnode */
     char*		ns_iri;		/**< namespace IRI for this xmlnode */
     unsigned short     type;		/**< type of the xmlnode, one of ::NTYPE_TAG, ::NTYPE_ATTRIB, ::NTYPE_CDATA, or ::NTYPE_UNDEF */
     char*              data;		/**< data of the xmlnode, for attributes this is the value, for text nodes this is the text */
     int                data_sz;	/**< length of the data in the xmlnode */
/*     int                 complete; */
     pool               p;		/**< memory pool used by this xmlnode (the same as for all other xmlnode in a tree) */
     struct xmlnode_t*  parent;		/**< parent node for this node, or NULL for the root element */
     struct xmlnode_t*  firstchild; 	/**< first child element of this node, or NULL for no child elements */
     struct xmlnode_t*  lastchild;	/**< last child element of this node, or NULL for no child elements */
     struct xmlnode_t*  prev; 		/**< previous sibling */
     struct xmlnode_t*  next;		/**< next sibling */
     struct xmlnode_t*  firstattrib;	/**< first attribute node of this node */
     struct xmlnode_t*  lastattrib;	/**< last attribute node of this node */
} _xmlnode, *xmlnode;

namespace xmppd {

    /**
     * This class represents and manages a list of bindings from namespace prefixes to namespace IRIs
     */
    class ns_decl_list : private std::list<std::pair<std::string, std::string> > {
	public:
	    ns_decl_list();
	    ns_decl_list(const xmlnode node);
	    void update(const std::string& prefix, const std::string& ns_iri);
	    void delete_last(const std::string& prefix);
	    char const* get_nsprefix(const std::string& iri) const;
	    char const* get_nsprefix(const std::string& iri, bool accept_default_prefix) const;
	    char const* get_nsiri(const std::string& prefix) const;
	    bool check_prefix(const std::string& prefix, const std::string& ns_iri) const;
	private:
    };

}


/**
 * item in a list of xmlnodes
 */
typedef struct xmlnode_list_item_t {
    xmlnode			node;	/**< the node contained in this list item */
    struct xmlnode_list_item_t *next;	/**< next item in the list */
} _xmlnode_list_item, *xmlnode_list_item;

/* Node creation routines */
xmlnode  xmlnode_wrap(xmlnode x,const char* wrapper);
xmlnode  xmlnode_wrap_ns(xmlnode x,const char* name, const char *prefix, const char *ns_iri);
xmlnode  xmlnode_new_tag(const char* name);
xmlnode  xmlnode_new_tag_ns(const char* name, const char* prefix, const char *ns_iri);
xmlnode  xmlnode_new_tag_pool(pool p, const char* name);
xmlnode  xmlnode_new_tag_pool_ns(pool p, const char* name, const char* prefix, const char *ns_iri);
xmlnode  xmlnode_insert_tag(xmlnode parent, const char* name); 
xmlnode  xmlnode_insert_tag_ns(xmlnode parent, const char* name, const char *prefix, const char *ns_iri); 
xmlnode  xmlnode_insert_cdata(xmlnode parent, const char* CDATA, unsigned int size);
xmlnode  xmlnode_insert_tag_node(xmlnode parent, xmlnode node);
void     xmlnode_insert_node(xmlnode parent, xmlnode node);
xmlnode  xmlnode_str(const char *str, int len);
xmlnode  xmlnode_file(const char *file);
const char* xmlnode_file_borked(const char *file); /* same as _file but returns the parsing error */
xmlnode  xmlnode_dup(xmlnode x); /* duplicate x */
xmlnode  xmlnode_dup_pool(pool p, xmlnode x);

/* Node Memory Pool */
pool xmlnode_pool(xmlnode node);

/* Node editing */
void xmlnode_hide(xmlnode child);
void xmlnode_hide_attrib(xmlnode parent, const char *name);
void xmlnode_hide_attrib_ns(xmlnode parent, const char *name, const char *ns_iri);

/* Node deletion routine, also frees the node pool! */
void xmlnode_free(xmlnode node);

/* Locates a child tag by name and returns it */
xmlnode  xmlnode_get_tag(xmlnode parent, const char* name);
char* xmlnode_get_tag_data(xmlnode parent, const char* name);
xmlnode_list_item xmlnode_get_tags(xmlnode context_node, const char *path, xht namespaces, pool p = NULL);
xmlnode xmlnode_get_list_item(xmlnode_list_item first, unsigned int i);
char* xmlnode_get_list_item_data(xmlnode_list_item first, unsigned int i);
xmlnode xmlnode_select_by_lang(xmlnode_list_item nodes, const char* lang);

/* Attribute accessors */
void     xmlnode_put_attrib(xmlnode owner, const char* name, const char* value);
void     xmlnode_put_attrib_ns(xmlnode owner, const char* name, const char* prefix, const char *ns_iri, const char* value);
char*    xmlnode_get_attrib(xmlnode owner, const char* name);
char*    xmlnode_get_attrib_ns(xmlnode owner, const char* name, const char *ns_iri);
void     xmlnode_put_expat_attribs(xmlnode owner, const char** atts, xmppd::ns_decl_list& nslist);

const char* xmlnode_get_lang(xmlnode node);

/* Bastard am I, but these are fun for internal use ;-) */
void     xmlnode_put_vattrib(xmlnode owner, const char* name, void *value);
void*    xmlnode_get_vattrib(xmlnode owner, const char* name);

/* Node traversal routines */
xmlnode  xmlnode_get_firstattrib(xmlnode parent);
xmlnode  xmlnode_get_firstchild(xmlnode parent);
xmlnode  xmlnode_get_lastchild(xmlnode parent);
xmlnode  xmlnode_get_nextsibling(xmlnode sibling);
xmlnode  xmlnode_get_prevsibling(xmlnode sibling);
xmlnode  xmlnode_get_parent(xmlnode node);

/* Node information routines */
char*    xmlnode_get_name(xmlnode node);
char*    xmlnode_get_data(xmlnode node);
int      xmlnode_get_type(xmlnode node);
const char* xmlnode_get_localname(xmlnode node);
const char* xmlnode_get_namespace(xmlnode node);
const char* xmlnode_get_nsprefix(xmlnode node);
void	 xmlnode_change_namespace(xmlnode node, const char *ns_iri);

int      xmlnode_has_children(xmlnode node);

/* Node-to-string translation */
char*	 xmlnode_serialize_string(xmlnode_t const* node, const xmppd::ns_decl_list& nslist, int stream_type);

int      xmlnode2file(char *file, xmlnode node); /* writes node to file */
int	 xmlnode2file_limited(char *file, xmlnode node, size_t sizelimit);

/* Expat callbacks */
void expat_startElement(void* userdata, const char* name, const char** atts);
void expat_endElement(void* userdata, const char* name);
void expat_charData(void* userdata, const char* s, int len);

/* conversion between xhash to xml */
xmlnode xhash_to_xml(xht h);
xht xhash_from_xml(xmlnode hash);

/***********************
 * XSTREAM Section
 ***********************/

#define XSTREAM_MAXNODE 1000000
#define XSTREAM_MAXDEPTH 100

#define XSTREAM_ROOT        0 /* root element */
#define XSTREAM_NODE        1 /* normal node */
#define XSTREAM_CLOSE       2 /* closed </stream:stream> */
#define XSTREAM_ERR         4 /* parser error */

typedef void (*xstream_onNode)(int type, xmlnode x, void *arg); /* xstream event handler */

typedef struct xstream_struct {
    XML_Parser parser;
    xmlnode node;
    char *cdata;
    int cdata_len;
    pool p;
    xstream_onNode f;
    void *arg;
    int status;
    int depth;

    const char *root_lang;		/**< declared language on the root element */

    xmppd::ns_decl_list *ns_root;	/**< list of declared namespaces for the root element */
    xmppd::ns_decl_list *ns_stanza;	/**< list of declared namespaces for the current stanza */
} *xstream, _xstream;

xstream xstream_new(pool p, xstream_onNode f, void *arg); /* create a new xstream */
int xstream_eat(xstream xs, char *buff, int len); /* parse new data for this xstream, returns last XSTREAM_* status */

/* convience functions */
xmlnode xstream_header(const char *to, const char *from);
char *xstream_header_char(xmlnode x, int stream_type);

/** error cause types for streams, see section 4.7.3 of RFC 3920 */
typedef enum {
    unknown_error_type,		/**< no errror type found, especially legacy stream errors */
    bad_format,			/**< XML cannot be processed */
    bad_namespace_prefix,	/**< unsupported namespace prefix */
    conflict,			/**< new stream has been initiated, that conflicts */
    connection_timeout,		/**< no traffic on the stream for some time */
    host_gone,			/**< hostname is no longer hosted on this server */
    host_unknown,		/**< hostname is not known by this server */
    improper_addressing,	/**< missing to or from attribute */
    internal_server_error,	/**< missconfiguration or something like that */
    invalid_from,		/**< from address is not authorzed */
    invalid_id,			/**< invalid stream id */
    invalid_namespace,		/**< wrong namespace for stream or dialback */
    invalid_xml,		/**< invalid XML was found */
    not_authorized,		/**< session not authorized */
    policy_violation,		/**< local service policy violated */
    remote_connection_failed,	/**< could not connect to a required remote entity for auth */
    resource_constraint,	/**< server lacks system resources */
    restricted_xml,		/**< received restricted XML features */
    see_other_host,		/**< redirection to another host */
    system_shutdown,		/**< server is being shut down */
    undefined_condition,	/**< something else ... */
    unsupported_encoding,	/**< stream is coded in an unsupported encoding */
    unsupported_stanza_type,	/**< stanza is not supported */
    unsupported_version,	/**< XMPP version requested is not supported */
    xml_not_well_formed		/**< received XML, that is not well formed */
} streamerr_reason;

/** severity of stream error (well all stream errors are unrecoverable, but we might log them different */
typedef enum {
    normal,			/**< something that is just normal to happen (e.g. connection timeout) */
    configuration,		/**< something that seems to be caused by configuration errors (e.g. host gone) */
    feature_lack,		/**< something caused by features not supported by the other end (e.g. unsupported version) */
    unknown,			/**< absolutely no clue */
    error			/**< something that shut not happen in any case and seems to be an implementation error (e.g. xml_not_well_formed) */
} streamerr_severity;

/** structure that contains information about a stream error */
typedef struct streamerr_struct {
    char *text;			/**< the error message */
    char *lang;			/**< language of the error message */
    streamerr_reason reason;	/**< a generic cause type */
    streamerr_severity severity;/**< something that admin needs to care about? */
} *streamerr, _streamerr;

void xstream_format_error(spool s, streamerr errstruct);
streamerr_severity xstream_parse_error(pool p, xmlnode errnode, streamerr errstruct);

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


/* message authentication code */
void hmac_sha1_ascii_r(char *secret, unsigned char *message, size_t len, char hmac[41]);

/********** END OLD libxode.h BEGIN OLD jabber.h *************/

/* --------------------------------------------------------- */
/*                                                           */
/* JID structures & constants                                */
/*                                                           */
/* --------------------------------------------------------- */
#define JID_RESOURCE 1
#define JID_USER     2
#define JID_SERVER   4

typedef struct jid_struct
{ 
    pool               p;
    char*              resource;
    char*              user;
    char*              server;
    char*              full;
    struct jid_struct *next; /* for lists of jids */
} *jid;
  
jid     jid_new(pool p, const char *idstr);	       /* Creates a jabber id from the idstr */
void    jid_set(jid id, const char *str, int item);  /* Individually sets jid components */
char*   jid_full(jid id);		       /* Builds a string type=user/resource@server from the jid data */
int     jid_cmp(jid a, jid b);		       /* Compares two jid's, returns 0 for perfect match */
int     jid_cmpx(jid a, jid b, int parts);     /* Compares just the parts specified as JID_|JID_ */
jid     jid_append(jid a, jid b);	       /* Appending b to a (list), no dups */
/* xmlnode jid_xres(jid id); */		       /* Returns xmlnode representation of the resource?query=string */
xmlnode jid_nodescan(jid id, xmlnode x);       /* Scans the children of the node for a matching jid attribute */
jid     jid_user(jid a);                       /* returns the same jid but just of the user@host part */
jid	jid_user_pool(jid a, pool p);	       /* returns the same jid, but just the user@host part */
void	jid_init_cache();		       /**< initialize the stringprep caches */
void	jid_stop_caching();		       /**< free all caches that have been initialized */
void	jid_clean_cache();		       /**< check the stringprep caches for expired entries */


/* --------------------------------------------------------- */
/*                                                           */
/* JPacket structures & constants                            */
/*                                                           */
/* --------------------------------------------------------- */
#define JPACKET_UNKNOWN   0x00
#define JPACKET_MESSAGE   0x01
#define JPACKET_PRESENCE  0x02
#define JPACKET_IQ        0x04
#define JPACKET_S10N      0x08

#define JPACKET__UNKNOWN      0
#define JPACKET__NONE         1
#define JPACKET__ERROR        2
#define JPACKET__CHAT         3
#define JPACKET__GROUPCHAT    4
#define JPACKET__GET          5
#define JPACKET__SET          6
#define JPACKET__RESULT       7
#define JPACKET__SUBSCRIBE    8
#define JPACKET__SUBSCRIBED   9
#define JPACKET__UNSUBSCRIBE  10
#define JPACKET__UNSUBSCRIBED 11
#define JPACKET__AVAILABLE    12
#define JPACKET__UNAVAILABLE  13
#define JPACKET__PROBE        14
#define JPACKET__HEADLINE     15
#define JPACKET__INVISIBLE    16

typedef struct jpacket_struct
{
    unsigned char type;		    /**< stanza type (JPACKET_*) */
    int           subtype;	    /**< subtype of a stanza */
    int           flag;		    /**< used by the session manager to flag messages, that are read from offline storage */
    void*         aux1;		    /**< pointer to data passed around with a jpacket, multiple use inside jsm */
    xmlnode       x;		    /**< xmlnode containing the stanza inside the jpacket */
    jid           to;		    /**< destination of the stanza */
    jid           from;		    /**< source address for the stanza */
    char*         iqns;		    /**< pointer to the namespace inside an IQ stanza */
    xmlnode       iq;		    /**< "content" of an iq stanza, pointer to the element in its own namespace */
    pool          p;		    /**< memory pool used for this stanza */
} *jpacket, _jpacket;
 
jpacket jpacket_new(xmlnode x);	    /* Creates a jabber packet from the xmlnode */
jpacket jpacket_reset(jpacket p);   /* Resets the jpacket values based on the xmlnode */
int     jpacket_subtype(jpacket p); /* Returns the subtype value (looks at xmlnode for it) */


/* --------------------------------------------------------- */
/*                                                           */
/* Simple Jabber Rate limit functions                        */
/*                                                           */
/* --------------------------------------------------------- */
typedef struct jlimit_struct
{
    char *key;
    int start;
    int points;
    int maxt, maxp;
    pool p;
} *jlimit, _jlimit;
 
jlimit jlimit_new(int maxt, int maxp);
void jlimit_free(jlimit r);
int jlimit_check(jlimit r, char *key, int points);


/* #define KARMA_DEBUG */
/* default to disable karma */
#define KARMA_READ_MAX(k) (abs(k)*100) /* how much you are allowed to read off the sock */
#define KARMA_INIT 5   /* internal "init" value */
#define KARMA_HEARTBEAT 2 /* seconds to register for heartbeat */
#define KARMA_MAX 10     /* total max karma you can have */
#define KARMA_INC 1      /* how much to increment every KARMA_HEARTBEAT seconds */
#define KARMA_DEC 0      /* how much to penalize for reading KARMA_READ_MAX in
                            KARMA_HEARTBEAT seconds */
#define KARMA_PENALTY -5 /* where you go when you hit 0 karma */
#define KARMA_RESTORE 5  /* where you go when you payed your penelty or INIT */
#define KARMA_RESETMETER 0 /* Reset byte meter on restore default is falst */

struct karma {
    int reset_meter; /* reset the byte meter on restore */
    int val; /* current karma value */
    long bytes; /* total bytes read (in that time period) */
    int max;  /* max karma you can have */
    int inc,dec; /* how much to increment/decrement */
    int penalty,restore; /* what penalty (<0) or restore (>0) */
    time_t last_update; /* time this was last incremented */
};

struct karma *karma_new(pool p); /* creates a new karma object, with default values */
void karma_copy(struct karma *new_instance, struct karma *old); /* makes a copy of old in new */
void karma_increment(struct karma *k);          /* inteligently increments karma */
void karma_decrement(struct karma *k, long bytes_read); /* inteligently decrements karma */
int karma_check(struct karma *k,long bytes_read); /* checks to see if we have good karma */



/* --------------------------------------------------------- */
/*                                                           */
/* Error structures & constants                              */
/*                                                           */
/* --------------------------------------------------------- */
typedef struct terror_struct
{
    int  code;
    char msg[64];
} terror;

#define TERROR_BAD           (terror){400,"Bad Request"}
#define TERROR_AUTH          (terror){401,"Unauthorized"}
#define TERROR_PAY           (terror){402,"Payment Required"}
#define TERROR_FORBIDDEN     (terror){403,"Forbidden"}
#define TERROR_NOTFOUND      (terror){404,"Not Found"}
#define TERROR_NOTALLOWED    (terror){405,"Not Allowed"}
#define TERROR_NOTACCEPTABLE (terror){406,"Not Acceptable"}
#define TERROR_REGISTER      (terror){407,"Registration Required"}
#define TERROR_REQTIMEOUT    (terror){408,"Request Timeout"}
#define TERROR_CONFLICT      (terror){409,"Conflict"}

#define TERROR_INTERNAL   (terror){500,"Internal Server Error"}
#define TERROR_NOTIMPL    (terror){501,"Not Implemented"}
#define TERROR_EXTERNAL   (terror){502,"Remote Server Error"}
#define TERROR_UNAVAIL    (terror){503,"Service Unavailable"}
#define TERROR_EXTTIMEOUT (terror){504,"Remote Server Timeout"}
#define TERROR_DISCONNECTED (terror){510,"Disconnected"}

/* we define this to signal that we support xterror */
#define HAS_XTERROR

typedef struct xterror_struct
{
    int  code;
    char msg[256];
    char type[9];
    char condition[64];
} xterror;

#define XTERROR_BAD		(xterror){400, N_("Bad Request"),"modify","bad-request"}
#define XTERROR_CONFLICT	(xterror){409, N_("Conflict"), "cancel", "conflict"}
#define XTERROR_NOTIMPL		(xterror){501, N_("Not Implemented"), "cancel", "feature-not-implemented"}
#define XTERROR_FORBIDDEN	(xterror){403, N_("Forbidden"), "auth", "forbidden"}
#define XTERROR_GONE		(xterror){302, N_("Gone"), "modify", "gone"}
#define XTERROR_INTERNAL	(xterror){500, N_("Internal Server Error"), "wait", "internal-server-error"}
#define XTERROR_NOTFOUND	(xterror){404, N_("Not Found"), "cancel", "item-not-found"}
#define XTERROR_JIDMALFORMED	(xterror){400, N_("Bad Request"), "modify", "jid-malformed"}
#define XTERROR_NOTACCEPTABLE	(xterror){406, N_("Not Acceptable"), "modify", "not-acceptable"}
#define XTERROR_NOTALLOWED	(xterror){405, N_("Not Allowed"), "cancel", "not-allowed"}
#define XTERROR_AUTH		(xterror){401, N_("Unauthorized"), "auth", "not-authorized"}
#define XTERROR_PAY		(xterror){402, N_("Payment Required"), "auth", "payment-required"}
#define XTERROR_RECIPIENTUNAVAIL (xterror){404, N_("Recipient Is Unavailable"), "wait", "recipient-unavailable"}
#define XTERROR_REDIRECT	(xterror){302, N_("Redirect"), "modify", "redirect"}
#define XTERROR_REGISTER	(xterror){407, N_("Registration Required"), "auth", "registration-required"}
#define XTERROR_REMOTENOTFOUND	(xterror){404, N_("Remote Server Not Found"), "cancel", "remote-server-not-found"}
#define XTERROR_REMOTETIMEOUT	(xterror){504, N_("Remote Server Timeout"), "wait", "remote-server-timeout"}
#define XTERROR_RESCONSTRAINT	(xterror){500, N_("Resource Constraint"), "wait", "resource-constraint"}
#define XTERROR_UNAVAIL		(xterror){503, N_("Service Unavailable"), "cancel", "service-unavailable"}
#define XTERROR_SUBSCRIPTIONREQ	(xterror){407, N_("Subscription Required"), "auth", "subscription-required"}
#define XTERROR_UNDEF_CANCEL	(xterror){500, NULL, "cancel", "undefined-condition"}
#define XTERROR_UNDEF_CONTINUE	(xterror){500, NULL, "continue", "undefined-condition"}
#define XTERROR_UNDEF_MODIFY	(xterror){500, NULL, "modify", "undefined-condition"}
#define XTERROR_UNDEF_AUTH	(xterror){500, NULL, "auth", "undefined-condition"}
#define XTERROR_UNDEF_WAIT	(xterror){500, NULL, "wait", "undefined-condition"}
#define XTERROR_UNEXPECTED	(xterror){400, N_("Unexpected Request"), "wait", "unexpected-request"}

#define XTERROR_REQTIMEOUT	(xterror){408, N_("Request Timeout"), "wait", "remote-server-timeout"}
#define XTERROR_EXTERNAL	(xterror){502, N_("Remote Server Error"), "wait", "service-unavailable"}
#define XTERROR_EXTTIMEOUT	(xterror){504, N_("Remote Server Timeout"), "wait", "remote-server-timeout"}
#define XTERROR_DISCONNECTED	(xterror){510, N_("Disconnected"), "cancel", "service-unavailable"}
#define XTERROR_STORAGE_FAILED	(xterror){500, N_("Storage Failed"), "wait", "internal-server-error"}

/* --------------------------------------------------------- */
/*                                                           */
/* Namespace constants                                       */
/*                                                           */
/* --------------------------------------------------------- */
#define NSCHECK(x,n) (j_strcmp(xmlnode_get_namespace(x), n) == 0)

#define NS_STREAM    "http://etherx.jabber.org/streams"
#define NS_FLASHSTREAM "http://www.jabber.com/streams/flash"
#define NS_CLIENT    "jabber:client"
#define NS_SERVER    "jabber:server"
#define NS_DIALBACK  "jabber:server:dialback"
#define NS_COMPONENT_ACCEPT "jabber:component:accept"
#define NS_AUTH      "jabber:iq:auth"
#define NS_AUTH_CRYPT "jabber:iq:auth:crypt"
#define NS_REGISTER  "jabber:iq:register"
#define NS_ROSTER    "jabber:iq:roster"
#define NS_OFFLINE   "jabber:x:offline"
#define NS_AGENT     "jabber:iq:agent"
#define NS_AGENTS    "jabber:iq:agents"
#define NS_DELAY     "jabber:x:delay"
#define NS_VERSION   "jabber:iq:version"
#define NS_TIME      "jabber:iq:time"
#define NS_VCARD     "vcard-temp"
#define NS_PRIVATE   "jabber:iq:private"
#define NS_SEARCH    "jabber:iq:search"
#define NS_OOB       "jabber:iq:oob"
#define NS_XOOB      "jabber:x:oob"
#define NS_FILTER    "jabber:iq:filter"
#define NS_AUTH_0K   "jabber:iq:auth:0k"
#define NS_BROWSE    "jabber:iq:browse"
#define NS_EVENT     "jabber:x:event"
#define NS_CONFERENCE "jabber:iq:conference"
#define NS_SIGNED    "jabber:x:signed"
#define NS_ENCRYPTED "jabber:x:encrypted"
#define NS_GATEWAY   "jabber:iq:gateway"
#define NS_LAST      "jabber:iq:last"
#define NS_ENVELOPE  "jabber:x:envelope"
#define NS_EXPIRE    "jabber:x:expire"
#define NS_PRIVACY   "jabber:iq:privacy"
#define NS_XHTML     "http://www.w3.org/1999/xhtml"
#define NS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define NS_DATA	     "jabber:x:data"
#define NS_FLEXIBLE_OFFLINE "http://jabber.org/protocol/offline"
#define NS_IQ_AUTH    "http://jabber.org/features/iq-auth"
#define NS_REGISTER_FEATURE "http://jabber.org/features/iq-register"
#define NS_MSGOFFLINE "msgoffline"

/* #define NS_XDBGINSERT "jabber:xdb:ginsert" XXX: I guess this it not used ANYWHERE and can be deleted */
#define NS_XDBNSLIST  "jabber:xdb:nslist"

#define NS_XMPP_STANZAS "urn:ietf:params:xml:ns:xmpp-stanzas"
#define NS_XMPP_TLS  "urn:ietf:params:xml:ns:xmpp-tls"
#define NS_XMPP_STREAMS "urn:ietf:params:xml:ns:xmpp-streams"
#define NS_XMPP_SASL "urn:ietf:params:xml:ns:xmpp-sasl"

#define NS_XMPP_PING "urn:xmpp:ping"

#define NS_JABBERD_STOREDPRESENCE "http://jabberd.org/ns/storedpresence"
#define NS_JABBERD_STOREDREQUEST "http://jabberd.org/ns/storedsubscriptionrequest"
#define NS_JABBERD_STOREDSTATE "http://jabberd.org/ns/storedstate"	/**< namespace to store internal state of jabberd */
#define NS_JABBERD_HISTORY "http://jabberd.org/ns/history"
#define NS_JABBERD_HASH "http://jabberd.org/ns/hash"			/**< namespace for storing xhash data */
#define NS_JABBERD_XDB "http://jabberd.org/ns/xdb"			/**< namespace for the root element used by xdb_file to store data in files */
#define NS_JABBERD_WRAPPER "http://jabberd.org/ns/wrapper"		/**< namespace used to wrap various internal data */
#define NS_JABBERD_XDBSQL "http://jabberd.org/ns/xdbsql"		/**< namespace for substitution in xdb_sql configuration */
#define NS_JABBERD_ACL "http://jabberd.org/ns/acl"			/**< namespace for access control lists */
#define NS_JABBERD_LOOPCHECK "http://jabberd.org/ns/loopcheck"		/**< namespace for loopchecking of s2s connections */

#define NS_SESSION "http://jabberd.jabberstudio.org/ns/session/1.0"	/**< namespace of the jabberd2 session control protocol (http://jabberd.jabberstudio.org/dev/docs/session.shtml) */

#define NS_XMLNS "http://www.w3.org/2000/xmlns/"	/**< namespace of xml namespace declarations, defined by 'Namespaces in XML' (W3C) */
#define NS_XML "http://www.w3.org/XML/1998/namespace"	/**< namespace declared by the xml prefix, defined by 'Namespaces in XML' (W3C) */

#define NS_JABBERD_CONFIGFILE "http://jabberd.org/ns/configfile" /**< namespace of the root element in the config file */
#define NS_JABBERD_CONFIGFILE_REPLACE "http://jabberd.org/ns/configfile/replace" /**< namespace of replace and include commands */
#define NS_JABBERD_CONFIG_XDBFILE "jabber:config:xdb_file" /**< namespace of xdb_file component configuration */
#define NS_JABBERD_CONFIG_DIALBACK "jabber:config:dialback" /**< namespace of dialback component configuration */
#define NS_JABBERD_CONFIG_DNSRV "jabber:config:dnsrv" /**< namespace of the dnsrv component configuration */
#define NS_JABBERD_CONFIG_JSM "jabber:config:jsm" /**< namespace of the jsm component configuration */
#define NS_JABBERD_CONFIG_PTHCSOCK "jabber:config:pth-csock" /**< namespace of the pthsock_client component configuration */
#define NS_JABBERD_CONFIG_XDBSQL "jabber:config:xdb_sql" /**< namepace of the xdb_sql component configuration */

/* --------------------------------------------------------- */
/*                                                           */
/* JUtil functions                                           */
/*                                                           */
/* --------------------------------------------------------- */
xmlnode jutil_presnew(int type, const char *to, const char *status); /* Create a skeleton presence packet */
xmlnode jutil_iqnew(int type, const char *ns);		 /* Create a skeleton iq packet */
xmlnode jutil_msgnew(const char *type, const char *to, const char *subj, const char *body);
							 /* Create a skeleton message packet */
int     jutil_priority(xmlnode x);			 /* Determine priority of this packet */
void    jutil_tofrom(xmlnode x);			 /* Swaps to/from fields on a packet */
xmlnode jutil_iqresult(xmlnode x);			 /* Generate a skeleton iq/result, given a iq/query */
char*   jutil_timestamp(void);				 /* Get stringified timestamp */
char*   jutil_timestamp_ms(char *buffer);		 /* Get stringified timestamp including milliseconds */
void    jutil_error(xmlnode x, terror E);		 /* Append an <error> node to x */
void    jutil_error_xmpp(xmlnode x, xterror E);		 /* Append an <error> node to x using XMPP syntax */
void	jutil_error_map(terror old, xterror *mapped);	 /* map an old terror structure to a new xterror structure */
void    jutil_delay(xmlnode msg, const char *reason);		 /* Append a delay packet to msg */
char*   jutil_regkey(char *key, char *seed);		 /* pass a seed to generate a key, pass the key again to validate (returns it) */

/* --------------------------------------------------------- */
/*                                                           */
/* Functions to access localized messages                    */
/*                                                           */
/* --------------------------------------------------------- */
void messages_set_mapping(const char* lang, const char* locale_name);
const char* messages_get(const char* lang, const char* message);

#endif	/* INCL_LIB_H */
