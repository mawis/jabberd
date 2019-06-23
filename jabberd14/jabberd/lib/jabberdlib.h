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
 * @brief Contains basic functionality, that is needed to form the server and
 * its components
 *
 * In this directory there is the basic functionality on which the jabber server
 * is build.
 *
 * Maybe the most basic file in here is pool.cc which contains the memory
 * management of jabberd14. Memory in jabberd14 is managed in this pools, which
 * means, that all memory allocated on a pool gets freed together when this pool
 * is freed. This allows, that we do not need that many single memory freeings,
 * and therefore the risk that freeing memory is forgotten gets reduced.
 *
 * Another basic module is in jid.cc which contains the functionality to manage
 * XMPP addresses (JIDs). It can be used to modify and compare JIDs as well as
 * to get them normalized.
 *
 * The third most basic module is in xmlnode.cc which contains a DOM-like
 * interface to XML trees. Based on this XML interface jabberd14 builds the
 * jpacket_struct which combines an XML document (a stanza) with fields of
 * relevant information about this stanza (stanza type, sender and receipient,
 * ...) jpackets are implemented in jpacket.cc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef N_
#define N_(n) (n)
#endif

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pth.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <expat.h>

#include <list>
#include <utility>

#ifdef HAS_TR1_UNORDERED_MAP
#include <tr1/unordered_map>
#else
#include <map>
#endif

#include <glibmm.h>

/*
**  Arrange to use either varargs or stdargs
*/

#define MAXSHORTSTR 203 /* max short string length */
#define QUAD_T unsigned long long

#ifdef __STDC__

#include <stdarg.h>

#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap, f)
#define VA_END va_end(ap)

#else /* __STDC__ */

#include <varargs.h>

#define VA_LOCAL_DECL va_list ap;
#define VA_START(f) va_start(ap)
#define VA_END va_end(ap)

#endif /* __STDC__ */

#ifndef INCL_LIB_H
#define INCL_LIB_H

#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "hash.hh"

#define ZONE zonestr(__FILE__, __LINE__)
char *zonestr(char const *file, int line);

#include "pool.hh"

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
int make_netsocket(uint16_t const port, char const *host, int type);
int make_netsocket2(Glib::ustring const servname, Glib::ustring const nodename,
                    int type);
struct in_addr *make_addr(char const *host);
struct in6_addr *make_addr_ipv6(char const *host);
#endif

/* --------------------------------------------------------- */
/*                                                           */
/* String management routines                                */
/*                                                           */
/* --------------------------------------------------------- */
char *j_strdup(char const *str);
char *j_strcat(char *dest, char const *txt);
int j_strcmp(char const *a, char const *b);
int j_strcasecmp(char const *a, char const *b);
int j_strncmp(char const *a, char const *b, int i);
int j_strncasecmp(char const *a, char const *b, int i);
int j_strlen(char const *a);
int j_atoi(char const *a, int def);

namespace xmppd {
class to_lower {
  public:
    to_lower(std::locale const &l) : loc(l) {}
    char operator()(char c) const { return std::tolower(c, loc); }

  private:
    std::locale const &loc;
};
} // namespace xmppd

#include "base64.hh"

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

char *shahash(char const *str);                    /* NOT THREAD SAFE */
void shahash_r(const char *str, char hashbuf[41]); /* USE ME */
void shaBlock(unsigned char *dataIn, int len, unsigned char hashout[20]);

/* --------------------------------------------------------- */
/*                                                           */
/* SHA calculations                                          */
/*                                                           */
/* --------------------------------------------------------- */

#include "crc32.hh"

/* --------------------------------------------------------- */
/*                                                           */
/* Hashtable functions                                       */
/*                                                           */
/* --------------------------------------------------------- */
namespace xmppd {

/**
 * a class implementing a hash with std::string as key and void* as value
 *
 * This is a replacement for the xht structure in older versions of jabberd14
 * and the xhash_...() functions are mapped to method calls on this object.
 *
 * @todo This dynamically maps to either a map or an unordered_map if available.
 * This depends on a test made in the configure script. But we should not depend
 * on definitions in config.h (i.e. definitions made by the configure script) in
 * files we do install. This should be fixed before this code gets released.
 */
template <class value_type>
class xhash :
#ifdef HAS_TR1_UNORDERED_MAP
    public std::tr1::unordered_map<std::string, value_type>
#else
    public std::map<std::string, value_type>
#endif
{
  public:
    /**
     * get an entry from the hash but consider the key to be a domain
     *
     * This accesor function also matches if the domainkey is a 'subdomain' for
     * a domain in the map. If there are multiple matches, the most specific one
     * is returned. If no match can be found,
     * "*" is tried as a default key.
     *
     * @param domainkey the key that should be considered as a domain
     * @return iterator to the found value
     */
    typename xhash<value_type>::iterator get_by_domain(std::string domainkey);
};
} // namespace xmppd

typedef xmppd::xhash<void *> *xht;

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
/* xmlnodes - Document Object Model                          */
/*                                                           */
/* --------------------------------------------------------- */
#define NTYPE_TAG 0    /**< xmlnode is an element (tag) */
#define NTYPE_ATTRIB 1 /**< xmlnode is an attribute node */
#define NTYPE_CDATA 2  /**< xmlnode is a text node (!) */

#define NTYPE_LAST 2   /**< highest possible value of xmlnode types */
#define NTYPE_UNDEF -1 /**< xmlnode has no defined type */

#define XMLNS_SEPARATOR                                                        \
    ' ' /**< character used to separate NS IRI from local name in expat        \
           callbacks */

/* --------------------------------------------------------------------------
   Node structure. Do not use directly! Always use accessor macros
   and methods!
   -------------------------------------------------------------------------- */
typedef struct xmlnode_t {
    char *name;          /**< local name of the xmlnode */
    char *prefix;        /**< namespace prefix for this xmlnode */
    char *ns_iri;        /**< namespace IRI for this xmlnode */
    unsigned short type; /**< type of the xmlnode, one of ::NTYPE_TAG,
                            ::NTYPE_ATTRIB, ::NTYPE_CDATA, or ::NTYPE_UNDEF */
    char *data;  /**< data of the xmlnode, for attributes this is the value, for
                    text nodes this is the text */
    int data_sz; /**< length of the data in the xmlnode */
                 /*     int                 complete; */
    pool p; /**< memory pool used by this xmlnode (the same as for all other
               xmlnode in a tree) */
    struct xmlnode_t
        *parent; /**< parent node for this node, or NULL for the root element */
    struct xmlnode_t *firstchild; /**< first child element of this node, or NULL
                                     for no child elements */
    struct xmlnode_t *lastchild;  /**< last child element of this node, or NULL
                                     for no child elements */
    struct xmlnode_t *prev;       /**< previous sibling */
    struct xmlnode_t *next;       /**< next sibling */
    struct xmlnode_t *firstattrib; /**< first attribute node of this node */
    struct xmlnode_t *lastattrib;  /**< last attribute node of this node */
} _xmlnode, *xmlnode;

namespace xmppd {

/**
 * This class represents and manages a list of bindings from namespace prefixes
 * to namespace IRIs
 */
class ns_decl_list : private std::list<std::pair<std::string, std::string>> {
  public:
    ns_decl_list();
    ns_decl_list(const xmlnode node);
    void update(const std::string &prefix, const std::string &ns_iri);
    void delete_last(const std::string &prefix);
    char const *get_nsprefix(const std::string &iri) const;
    char const *get_nsprefix(const std::string &iri,
                             bool accept_default_prefix) const;
    char const *get_nsiri(const std::string &prefix) const;
    bool check_prefix(const std::string &prefix,
                      const std::string &ns_iri) const;

  private:
};

} // namespace xmppd

/**
 * container, that contains a vector of xmlnodes
 *
 * This has been a pointer to a special struct in former versions of jabberd14,
 * but we are now using a standard container. Declaring this type to keep the
 * syntax of the interface. So don't be confused by the name of this type, it
 * is not a single item but the complete vector.
 */
typedef std::vector<xmlnode> xmlnode_vector;

/* Node creation routines */
xmlnode xmlnode_wrap(xmlnode x, const char *wrapper);
xmlnode xmlnode_wrap_ns(xmlnode x, const char *name, const char *prefix,
                        const char *ns_iri);
xmlnode xmlnode_new_tag(const char *name);
xmlnode xmlnode_new_tag_ns(const char *name, const char *prefix,
                           const char *ns_iri);
xmlnode xmlnode_new_tag_pool(pool p, const char *name);
xmlnode xmlnode_new_tag_pool_ns(pool p, const char *name, const char *prefix,
                                const char *ns_iri);
xmlnode xmlnode_insert_tag(xmlnode parent, const char *name);
xmlnode xmlnode_insert_tag_ns(xmlnode parent, const char *name,
                              const char *prefix, const char *ns_iri);
xmlnode xmlnode_insert_cdata(xmlnode parent, const char *CDATA, ssize_t size);
xmlnode xmlnode_insert_tag_node(xmlnode parent, xmlnode node);
void xmlnode_insert_node(xmlnode parent, xmlnode node);
xmlnode xmlnode_dup(xmlnode x); /* duplicate x */
xmlnode xmlnode_dup_pool(pool p, xmlnode x);

/* Node Memory Pool */
pool xmlnode_pool(xmlnode node);

/* Node editing */
void xmlnode_hide(xmlnode child);
void xmlnode_hide_attrib(xmlnode parent, char const *name);
void xmlnode_hide_attrib_ns(xmlnode parent, char const *name,
                            char const *ns_iri);

/* Node deletion routine, also frees the node pool! */
void xmlnode_free(xmlnode node);

/* Locates a child tag by name and returns it */
xmlnode xmlnode_get_tag(xmlnode parent, char const *name);
char *xmlnode_get_tag_data(xmlnode parent, char const *name);
xmlnode_vector xmlnode_get_tags(xmlnode context_node, char const *path,
                                xht namespaces);
xmlnode xmlnode_get_list_item(const xmlnode_vector &first, unsigned int i);
char *xmlnode_get_list_item_data(const xmlnode_vector &first, unsigned int i);
xmlnode xmlnode_select_by_lang(const xmlnode_vector &nodes, const char *lang);

/* Attribute accessors */
void xmlnode_put_attrib(xmlnode owner, const char *name, const char *value);
void xmlnode_put_attrib_ns(xmlnode owner, const char *name, const char *prefix,
                           const char *ns_iri, const char *value);
char *xmlnode_get_attrib(xmlnode owner, const char *name);
char *xmlnode_get_attrib_ns(xmlnode owner, const char *name,
                            const char *ns_iri);
const char *xmlnode_get_lang(xmlnode node);

/* Node traversal routines */
xmlnode xmlnode_get_firstattrib(xmlnode parent);
xmlnode xmlnode_get_firstchild(xmlnode parent);
xmlnode xmlnode_get_lastchild(xmlnode parent);
xmlnode xmlnode_get_nextsibling(xmlnode sibling);
xmlnode xmlnode_get_prevsibling(xmlnode sibling);
xmlnode xmlnode_get_parent(xmlnode node);

/* Node information routines */
char *xmlnode_get_name(xmlnode node);
char *xmlnode_get_data(xmlnode node);
int xmlnode_get_type(xmlnode node);
const char *xmlnode_get_localname(xmlnode node);
const char *xmlnode_get_namespace(xmlnode node);
const char *xmlnode_get_nsprefix(xmlnode node);
void xmlnode_change_namespace(xmlnode node, const char *ns_iri);

int xmlnode_has_children(xmlnode node);

/* Node-to-string translation */
char *xmlnode_serialize_string(xmlnode_t const *node,
                               const xmppd::ns_decl_list &nslist,
                               int stream_type);

/* conversion between xhash to xml */
xmlnode xhash_to_xml(xht h);
xht xhash_from_xml(xmlnode hash, pool p);

#include "expat.hh"

/***********************
 * XSTREAM Section
 ***********************/

#define XSTREAM_MAXNODE 1000000
#define XSTREAM_MAXDEPTH 100

#define XSTREAM_ROOT 0  /* root element */
#define XSTREAM_NODE 1  /* normal node */
#define XSTREAM_CLOSE 2 /* closed </stream:stream> */
#define XSTREAM_ERR 4   /* parser error */

typedef void (*xstream_onNode)(int type, xmlnode x,
                               void *arg); /* xstream event handler */

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

    const char *root_lang; /**< declared language on the root element */

    xmppd::ns_decl_list
        *ns_root; /**< list of declared namespaces for the root element */
    xmppd::ns_decl_list
        *ns_stanza; /**< list of declared namespaces for the current stanza */
} * xstream, _xstream;

xstream xstream_new(pool p, xstream_onNode f,
                    void *arg); /* create a new xstream */
int xstream_eat(xstream xs, char *buff,
                int len); /* parse new data for this xstream, returns last
                             XSTREAM_* status */

/* convience functions */
xmlnode xstream_header(const char *to, const char *from);
char *xstream_header_char(xmlnode x, int stream_type);

/** error cause types for streams, see section 4.7.3 of RFC 3920 */
typedef enum {
    unknown_error_type,    /**< no errror type found, especially legacy stream
                              errors */
    bad_format,            /**< XML cannot be processed */
    bad_namespace_prefix,  /**< unsupported namespace prefix */
    conflict,              /**< new stream has been initiated, that conflicts */
    connection_timeout,    /**< no traffic on the stream for some time */
    host_gone,             /**< hostname is no longer hosted on this server */
    host_unknown,          /**< hostname is not known by this server */
    improper_addressing,   /**< missing to or from attribute */
    internal_server_error, /**< missconfiguration or something like that */
    invalid_from,          /**< from address is not authorzed */
    invalid_id,            /**< invalid stream id */
    invalid_namespace,     /**< wrong namespace for stream or dialback */
    invalid_xml,           /**< invalid XML was found */
    not_authorized,        /**< session not authorized */
    policy_violation,      /**< local service policy violated */
    remote_connection_failed, /**< could not connect to a required remote entity
                                 for auth */
    resource_constraint,      /**< server lacks system resources */
    restricted_xml,           /**< received restricted XML features */
    see_other_host,           /**< redirection to another host */
    system_shutdown,          /**< server is being shut down */
    undefined_condition,      /**< something else ... */
    unsupported_encoding,     /**< stream is coded in an unsupported encoding */
    unsupported_stanza_type,  /**< stanza is not supported */
    unsupported_version,      /**< XMPP version requested is not supported */
    xml_not_well_formed       /**< received XML, that is not well formed */
} streamerr_reason;

/** severity of stream error (well all stream errors are unrecoverable, but we
 * might log them different */
typedef enum {
    normal,        /**< something that is just normal to happen (e.g. connection
                      timeout) */
    configuration, /**< something that seems to be caused by configuration
                      errors (e.g. host gone) */
    feature_lack,  /**< something caused by features not supported by the other
                      end (e.g. unsupported version) */
    unknown,       /**< absolutely no clue */
    error /**< something that shut not happen in any case and seems to be an
             implementation error (e.g. xml_not_well_formed) */
} streamerr_severity;

/** structure that contains information about a stream error */
typedef struct streamerr_struct {
    char *text;              /**< the error message */
    char *lang;              /**< language of the error message */
    streamerr_reason reason; /**< a generic cause type */
    streamerr_severity
        severity; /**< something that admin needs to care about? */
} * streamerr, _streamerr;

void xstream_format_error(std::ostream &out, streamerr errstruct);
streamerr_severity xstream_parse_error(pool p, xmlnode errnode,
                                       streamerr errstruct);

typedef struct {
    unsigned long H[5];
    unsigned long W[80];
    int lenW;
    unsigned long sizeHi, sizeLo;
} j_SHA_CTX;

void shaInit(j_SHA_CTX *ctx);
void shaUpdate(j_SHA_CTX *ctx, unsigned char *dataIn, int len);
void shaFinal(j_SHA_CTX *ctx, unsigned char hashout[20]);
void shaBlock(unsigned char *dataIn, int len, unsigned char hashout[20]);


#include "hmac.hh"

/********** END OLD libxode.h BEGIN OLD jabber.h *************/

#include "jabberid.hh"

/* --------------------------------------------------------- */
/*                                                           */
/* JID structures & constants                                */
/*                                                           */
/* --------------------------------------------------------- */
#define JID_RESOURCE 1
#define JID_USER 2
#define JID_SERVER 4

typedef xmppd::jabberid_pool *jid;

#include "jid.hh"

/* --------------------------------------------------------- */
/*                                                           */
/* JPacket structures & constants                            */
/*                                                           */
/* --------------------------------------------------------- */

#include "jpacket.hh"

/* --------------------------------------------------------- */
/*                                                           */
/* Simple Jabber Rate limit functions                        */
/*                                                           */
/* --------------------------------------------------------- */
typedef struct jlimit_struct {
    char *key;
    int start;
    int points;
    int maxt, maxp;
    pool p;
} * jlimit, _jlimit;

jlimit jlimit_new(int maxt, int maxp);
void jlimit_free(jlimit r);
int jlimit_check(jlimit r, char *key, int points);

#include "karma.hh"

/* --------------------------------------------------------- */
/*                                                           */
/* Error structures & constants                              */
/*                                                           */
/* --------------------------------------------------------- */
typedef struct terror_struct {
    int code;
    char msg[64];
} terror;

#define TERROR_BAD                                                             \
    (terror) { 400, "Bad Request" }
#define TERROR_AUTH                                                            \
    (terror) { 401, "Unauthorized" }
#define TERROR_PAY                                                             \
    (terror) { 402, "Payment Required" }
#define TERROR_FORBIDDEN                                                       \
    (terror) { 403, "Forbidden" }
#define TERROR_NOTFOUND                                                        \
    (terror) { 404, "Not Found" }
#define TERROR_NOTALLOWED                                                      \
    (terror) { 405, "Not Allowed" }
#define TERROR_NOTACCEPTABLE                                                   \
    (terror) { 406, "Not Acceptable" }
#define TERROR_REGISTER                                                        \
    (terror) { 407, "Registration Required" }
#define TERROR_REQTIMEOUT                                                      \
    (terror) { 408, "Request Timeout" }
#define TERROR_CONFLICT                                                        \
    (terror) { 409, "Conflict" }

#define TERROR_INTERNAL                                                        \
    (terror) { 500, "Internal Server Error" }
#define TERROR_NOTIMPL                                                         \
    (terror) { 501, "Not Implemented" }
#define TERROR_EXTERNAL                                                        \
    (terror) { 502, "Remote Server Error" }
#define TERROR_UNAVAIL                                                         \
    (terror) { 503, "Service Unavailable" }
#define TERROR_EXTTIMEOUT                                                      \
    (terror) { 504, "Remote Server Timeout" }
#define TERROR_DISCONNECTED                                                    \
    (terror) { 510, "Disconnected" }

/* we define this to signal that we support xterror */
#define HAS_XTERROR

typedef struct xterror_struct {
    int code;
    char msg[256];
    char type[9];
    char condition[64];
} xterror;

#define XTERROR_BAD                                                            \
    (xterror) { 400, N_("Bad Request"), "modify", "bad-request" }
#define XTERROR_CONFLICT                                                       \
    (xterror) { 409, N_("Conflict"), "cancel", "conflict" }
#define XTERROR_NOTIMPL                                                        \
    (xterror) {                                                                \
        501, N_("Not Implemented"), "cancel", "feature-not-implemented"        \
    }
#define XTERROR_FORBIDDEN                                                      \
    (xterror) { 403, N_("Forbidden"), "auth", "forbidden" }
#define XTERROR_GONE                                                           \
    (xterror) { 302, N_("Gone"), "modify", "gone" }
#define XTERROR_INTERNAL                                                       \
    (xterror) {                                                                \
        500, N_("Internal Server Error"), "wait", "internal-server-error"      \
    }
#define XTERROR_NOTFOUND                                                       \
    (xterror) { 404, N_("Not Found"), "cancel", "item-not-found" }
#define XTERROR_JIDMALFORMED                                                   \
    (xterror) { 400, N_("Bad Request"), "modify", "jid-malformed" }
#define XTERROR_NOTACCEPTABLE                                                  \
    (xterror) { 406, N_("Not Acceptable"), "modify", "not-acceptable" }
#define XTERROR_NOTALLOWED                                                     \
    (xterror) { 405, N_("Not Allowed"), "cancel", "not-allowed" }
#define XTERROR_AUTH                                                           \
    (xterror) { 401, N_("Unauthorized"), "auth", "not-authorized" }
#define XTERROR_PAY                                                            \
    (xterror) { 402, N_("Payment Required"), "auth", "payment-required" }
#define XTERROR_RECIPIENTUNAVAIL                                               \
    (xterror) {                                                                \
        404, N_("Recipient Is Unavailable"), "wait", "recipient-unavailable"   \
    }
#define XTERROR_REDIRECT                                                       \
    (xterror) { 302, N_("Redirect"), "modify", "redirect" }
#define XTERROR_REGISTER                                                       \
    (xterror) {                                                                \
        407, N_("Registration Required"), "auth", "registration-required"      \
    }
#define XTERROR_REMOTENOTFOUND                                                 \
    (xterror) {                                                                \
        404, N_("Remote Server Not Found"), "cancel",                          \
            "remote-server-not-found"                                          \
    }
#define XTERROR_REMOTETIMEOUT                                                  \
    (xterror) {                                                                \
        504, N_("Remote Server Timeout"), "wait", "remote-server-timeout"      \
    }
#define XTERROR_RESCONSTRAINT                                                  \
    (xterror) { 500, N_("Resource Constraint"), "wait", "resource-constraint" }
#define XTERROR_UNAVAIL                                                        \
    (xterror) {                                                                \
        503, N_("Service Unavailable"), "cancel", "service-unavailable"        \
    }
#define XTERROR_SUBSCRIPTIONREQ                                                \
    (xterror) {                                                                \
        407, N_("Subscription Required"), "auth", "subscription-required"      \
    }
#define XTERROR_UNDEF_CANCEL                                                   \
    (xterror) { 500, NULL, "cancel", "undefined-condition" }
#define XTERROR_UNDEF_CONTINUE                                                 \
    (xterror) { 500, NULL, "continue", "undefined-condition" }
#define XTERROR_UNDEF_MODIFY                                                   \
    (xterror) { 500, NULL, "modify", "undefined-condition" }
#define XTERROR_UNDEF_AUTH                                                     \
    (xterror) { 500, NULL, "auth", "undefined-condition" }
#define XTERROR_UNDEF_WAIT                                                     \
    (xterror) { 500, NULL, "wait", "undefined-condition" }
#define XTERROR_UNEXPECTED                                                     \
    (xterror) { 400, N_("Unexpected Request"), "wait", "unexpected-request" }

#define XTERROR_REQTIMEOUT                                                     \
    (xterror) { 408, N_("Request Timeout"), "wait", "remote-server-timeout" }
#define XTERROR_EXTERNAL                                                       \
    (xterror) { 502, N_("Remote Server Error"), "wait", "service-unavailable" }
#define XTERROR_EXTTIMEOUT                                                     \
    (xterror) {                                                                \
        504, N_("Remote Server Timeout"), "wait", "remote-server-timeout"      \
    }
#define XTERROR_DISCONNECTED                                                   \
    (xterror) { 510, N_("Disconnected"), "cancel", "service-unavailable" }
#define XTERROR_STORAGE_FAILED                                                 \
    (xterror) { 500, N_("Storage Failed"), "wait", "internal-server-error" }

/* --------------------------------------------------------- */
/*                                                           */
/* Namespace constants                                       */
/*                                                           */
/* --------------------------------------------------------- */
#define NSCHECK(x, n) (j_strcmp(xmlnode_get_namespace(x), n) == 0)

#define NS_STREAM "http://etherx.jabber.org/streams"
#define NS_FLASHSTREAM "http://www.jabber.com/streams/flash"
#define NS_CLIENT "jabber:client"
#define NS_SERVER "jabber:server"
#define NS_DIALBACK "jabber:server:dialback"
#define NS_COMPONENT_ACCEPT "jabber:component:accept"
#define NS_AUTH "jabber:iq:auth"
#define NS_AUTH_CRYPT "jabber:iq:auth:crypt"
#define NS_REGISTER "jabber:iq:register"
#define NS_ROSTER "jabber:iq:roster"
#define NS_OFFLINE "jabber:x:offline"
#define NS_AGENT "jabber:iq:agent"
#define NS_AGENTS "jabber:iq:agents"
#define NS_DELAY "jabber:x:delay"
#define NS_VERSION "jabber:iq:version"
#define NS_TIME "jabber:iq:time"
#define NS_VCARD "vcard-temp"
#define NS_PRIVATE "jabber:iq:private"
#define NS_SEARCH "jabber:iq:search"
#define NS_OOB "jabber:iq:oob"
#define NS_XOOB "jabber:x:oob"
#define NS_FILTER "jabber:iq:filter"
#define NS_AUTH_0K "jabber:iq:auth:0k"
#define NS_BROWSE "jabber:iq:browse"
#define NS_EVENT "jabber:x:event"
#define NS_CONFERENCE "jabber:iq:conference"
#define NS_SIGNED "jabber:x:signed"
#define NS_ENCRYPTED "jabber:x:encrypted"
#define NS_GATEWAY "jabber:iq:gateway"
#define NS_LAST "jabber:iq:last"
#define NS_ENVELOPE "jabber:x:envelope"
#define NS_EXPIRE "jabber:x:expire"
#define NS_PRIVACY "jabber:iq:privacy"
#define NS_XHTML "http://www.w3.org/1999/xhtml"
#define NS_DISCO_INFO "http://jabber.org/protocol/disco#info"
#define NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define NS_DATA "jabber:x:data"
#define NS_FLEXIBLE_OFFLINE "http://jabber.org/protocol/offline"
#define NS_IQ_AUTH "http://jabber.org/features/iq-auth"
#define NS_REGISTER_FEATURE "http://jabber.org/features/iq-register"
#define NS_MSGOFFLINE "msgoffline"
#define NS_BYTESTREAMS "http://jabber.org/protocol/bytestreams"
#define NS_COMMAND "http://jabber.org/protocol/commands"

/* #define NS_XDBGINSERT "jabber:xdb:ginsert" XXX: I guess this it not used
 * ANYWHERE and can be deleted */
#define NS_XDBNSLIST "jabber:xdb:nslist"

#define NS_XMPP_STANZAS "urn:ietf:params:xml:ns:xmpp-stanzas"
#define NS_XMPP_TLS "urn:ietf:params:xml:ns:xmpp-tls"
#define NS_XMPP_STREAMS "urn:ietf:params:xml:ns:xmpp-streams"
#define NS_XMPP_SASL "urn:ietf:params:xml:ns:xmpp-sasl"

#define NS_XMPP_PING "urn:xmpp:ping"

#define NS_JABBERD_STOREDPRESENCE "http://jabberd.org/ns/storedpresence"
#define NS_JABBERD_STOREDPEERPRESENCE "http://jabberd.org/ns/storedpeerpresence"
#define NS_JABBERD_STOREDREQUEST                                               \
    "http://jabberd.org/ns/storedsubscriptionrequest"
#define NS_JABBERD_STOREDSTATE                                                 \
    "http://jabberd.org/ns/storedstate" /**< namespace to store internal state \
                                           of jabberd */
#define NS_JABBERD_HISTORY "http://jabberd.org/ns/history"
#define NS_JABBERD_HASH                                                        \
    "http://jabberd.org/ns/hash" /**< namespace for storing xhash data */
#define NS_JABBERD_XDB                                                         \
    "http://jabberd.org/ns/xdb" /**< namespace for the root element used by    \
                                   xdb_file to store data in files */
#define NS_JABBERD_WRAPPER                                                     \
    "http://jabberd.org/ns/wrapper" /**< namespace used to wrap various        \
                                       internal data */
#define NS_JABBERD_XDBSQL                                                      \
    "http://jabberd.org/ns/xdbsql" /**< namespace for substitution in xdb_sql  \
                                      configuration */
#define NS_JABBERD_ACL                                                         \
    "http://jabberd.org/ns/acl" /**< namespace for access control lists */
#define NS_JABBERD_LOOPCHECK                                                   \
    "http://jabberd.org/ns/loopcheck" /**< namespace for loopchecking of s2s   \
                                         connections */
#define NS_JABBERD_ERRMSG                                                      \
    "http://jabberd.org/ns/errmsg" /**< namespace for session control error    \
                                      messages */

#define NS_SESSION                                                                                               \
    "http://jabberd.jabberstudio.org/ns/session/1.0" /**< namespace of the                                       \
                                                        jabberd2 session                                         \
                                                        control protocol                                         \
                                                        (http://jabberd.jabberstudio.org/dev/docs/session.shtml) \
                                                      */

#define NS_XMLNS                                                               \
    "http://www.w3.org/2000/xmlns/" /**< namespace of xml namespace            \
                                       declarations, defined by 'Namespaces in \
                                       XML' (W3C) */
#define NS_XML                                                                 \
    "http://www.w3.org/XML/1998/namespace" /**< namespace declared by the xml  \
                                              prefix, defined by 'Namespaces   \
                                              in XML' (W3C) */

#define NS_JABBERD_CONFIGFILE                                                  \
    "http://jabberd.org/ns/configfile" /**< namespace of the root element in   \
                                          the config file */
#define NS_JABBERD_CONFIGFILE_REPLACE                                          \
    "http://jabberd.org/ns/configfile/replace" /**< namespace of replace and   \
                                                  include commands */
#define NS_JABBERD_CONFIGFILE_ROUTER                                           \
    "http://xmppd.org/ns/configfile/router" /**< namespace for global router   \
                                               configuration */
#define NS_JABBERD_CONFIG_XDBFILE                                              \
    "jabber:config:xdb_file" /**< namespace of xdb_file component              \
                                configuration */
#define NS_JABBERD_CONFIG_DIALBACK                                             \
    "jabber:config:dialback" /**< namespace of dialback component              \
                                configuration */
#define NS_JABBERD_CONFIG_DNSRV                                                \
    "jabber:config:dnsrv" /**< namespace of the dnsrv component configuration  \
                           */
#define NS_JABBERD_CONFIG_JSM                                                  \
    "jabber:config:jsm" /**< namespace of the jsm component configuration */
#define NS_JABBERD_CONFIG_PTHCSOCK                                             \
    "jabber:config:pth-csock" /**< namespace of the pthsock_client component   \
                                 configuration */
#define NS_JABBERD_CONFIG_XDBSQL                                               \
    "jabber:config:xdb_sql" /**< namepace of the xdb_sql component             \
                               configuration */
#define NS_JABBERD_CONFIG_DYNAMICHOST                                          \
    "http://xmppd.org/ns/dynamichost" /**< namespace of the dynamic            \
                                         configuration of additional hosts for \
                                         components */

/* --------------------------------------------------------- */
/*                                                           */
/* JUtil functions                                           */
/*                                                           */
/* --------------------------------------------------------- */

#include "jutil.hh"

/* --------------------------------------------------------- */
/*                                                           */
/* Functions to access localized messages                    */
/*                                                           */
/* --------------------------------------------------------- */
void messages_set_mapping(const char *lang, const char *locale_name);
const char *messages_get(const char *lang, const char *message);

/* --------------------------------------------------------- */
/*                                                           */
/* Objects to access a lwresd                                */
/*                                                           */
/* --------------------------------------------------------- */

#include "lwresc.hh"

#endif /* INCL_LIB_H */
