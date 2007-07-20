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
 * @mainpage jabberd14 - implementation of an instant messaging server using the Jabber/XMPP protocols in C
 *
 * @section BigPicture The big picture
 *
 * jabberd14 consists of a base executable (the jabberd binary) implemented inside in the directory @link jabberd jabberd.@endlink
 * This base executable implements a router for XML fragments (called packets or stanzas). The routing at this level is in general
 * not visible to the user of the Jabber server, but used by the components, that form the Jabber server to exchange such
 * XML fragments with each other.
 *
 * The other parts of jabberd14 are the components, which are all implemented in their own directories. These components are:
 * - The client connection manager, which task is to accept incoming TCP/IP connections from clients and forwards incoming
 *   stanzas from the client to an other component called session manager (JSM) and forwards packets from the session manager
 *   back to the client on the TCP/IP connection. The exchange of the stanzas between the client connection manager and
 *   the session manager is done using the routing functionallity provided by the jabberd executable. The client connection
 *   manager (historically sometimes called pthsock_client) is implemented inside the directory @link pthsock pthsock.@endlink
 * - The Jabber session manager, which task is to implement the visible business logic. It implements what is afterwards
 *   seen as the Jabber server and addressed by the domain used by this server. It maintains presence subscriptions,
 *   the presence of the current sessions of a user and forwards messages or stores them offline. The session manager is
 *   implemented inside the directory @link jsm jsm.@endlink
 * - The DNS resolver (@link dnsrv dnsrv@endlink) typically handles all packets on the XML router that have no configured destination on
 *   the router (which is as you remember implemented by the jabberd binary). It will try to resolve the destination domain
 *   using DNS and if a DNS entry is found, it tags the XML fragment with a list of resolved IP addresses and resends
 *   the XML fragment using the XML router to one (or many in case of clustering) component, that is then responsible for
 *   sending the XML fragment to another host. This other component is the dialback component as described below.
 * - The dialback component implements the interconnection between the local Jabber server and other Jabber servers using
 *   the server to server protocol of XMPP/Jabber. It establishes connections to other servers and accepts incoming
 *   connections from them. This component is implemented inside the directory @link dialback dialback.@endlink
 * - There is typically at least one other component plugged into the XML router which is responsible for the persistant
 *   storing of data. This component handles special XML fragments router on the XML router. This special fragments are
 *   instructions for such storrage components and their replies to the requestor. There are two implementations of
 *   such a component inside the base package of jabberd14. The one implementation implements storing data to
 *   XML files and is implemented inside the directory @link xdb_file xdb_file,@endlink the other implementation
 *   uses SQL databases to store data and is implemented inside the directory @link xdb_sql xdb_sql.@endlink
 *
 * The components are compiled as shared objects (*.so files) and are loaded by the jabberd base executable on startup as
 * configured inside the configuration file using the &lt;load/&gt; element inside &lt;section/&gt;s. Each section inside the
 * configuration file defines one component.
 */

/**
 * @dir jabberd
 * @brief Containing the base executable (the jabberd binary) implementing an XML router and helpers
 *
 * In this directory you find the implementation of the jabberd executable, which is just something, that is able to
 * route XML fragments between the base handlers (they are implemented in files in the directory
 * @link jabberd/base jabberd/base@endlink.)
 * The base handlers (which are a part of the jabberd binary) are then able to connect targets and sources to this
 * XML routing. The most known base handler might be the handler for the &lt;load/&gt; target in the configuration
 * file. This handler loads a shared object file containing a component and connects this component to the
 * XML routing.
 * Other important base handlers are the handlers implemented in base_accept.cc and base_connect.cc, which implement
 * the &lt;accept/&gt; and &lt;connect/&gt; targets used to connect two (or more) instances of jabberd running to build
 * a single server.
 *
 * In addition to the XML routing, you find the implementation of the managed threads (mtq.cc), a scedular to invoke
 * regularly tasks (heartbeat.cc), logging services (log.cc), the handling of the configuration file (config.cc),
 * the handling of network sockets (mio.cc, mio_raw.cc, mio_tls.cc, mio_xml.cc), the XML database interface (xdb.cc),
 * and access control lists (acl.cc).
 *
 * The XML routing itself is implemented in the file deliver.cc. Routines used for the startup of the server can
 * be found in jabberd.cc.
 *
 * The jabberd executable also contains a library of functions used either by the base executable itself or
 * that are of general use for components (which are implemented as loadable objects). This jabberd library
 * is implemented in @link jabberd/lib jabberd/lib.@endlink
 */

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <jabberdlib.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#ifdef HAVE_GNUTLS_EXTRA
#  include <gnutls/extra.h>
#  include <gnutls/openpgp.h>
#endif

/** Packet types */
typedef enum { p_NONE, p_NORM, p_XDB, p_LOG, p_ROUTE } ptype;

/**
 * the stages of packet delivery - the order in which packet handlers gets called.
 *
 * Delivery starts with o_PRECOND handlers, then o_COND handlers, then o_PREDELIVER handlers, and o_DELIVER handlers last
 */
typedef enum {
    o_PRECOND,		/**< o_PRECOND handlers always get called first - used by xdb.cc to filter out xdb results */
    o_COND,		/**< currently not used by jabberd14 */
    o_PREDELIVER,	/**< handlers that should get called before o_DELIVER handlers - used by base_format.cc to reformat messages */
    o_DELIVER		/**< normal deliveries */
} order;

/**
 * Result types, unregister me, I pass, I should be last, I suck, I rock
 *
 * In case of r_DONE or r_LAST the passed data is consumed (i.e. freed), if
 * of the other values is returned, the data has not been consumed and the caller must
 * free it if necessary.
 */
typedef enum {
    r_UNREG,		/**< unregister the packet handler and keep delivering the packet */
    r_NONE,		/**< unused value ... might get removed */
    r_PASS,		/**< packet has not been handled nor did it cause an error, keep delivering the packet to later handlers */
    r_LAST,		/**< can only be returned by o_COND handlers in which case delivery is not continued with later handlers -- currently not used by jabberd14 */
    r_ERR,		/**< final delivery error, create error bounce and do not call later handlers */
    r_DONE		/**< packet has been handled, if o_DELIVER handler other handlers are called as well, else delivery is stopped */
} result;

typedef struct instance_struct *instance, _instance;

/** Packet wrapper, d as in delivery or daemon, whichever pleases you */
typedef struct dpacket_struct
{
    char *host;
    jid id;
    ptype type;
    pool p;
    xmlnode x;
} *dpacket, _dpacket;

/** Delivery handler function callback definition */
typedef result (*phandler)(instance id, dpacket p, void *arg);

/** Delivery handler list. See register_phandler(). */
typedef struct handel_struct
{
    pool p;
    phandler f;  /**< pointer to delivery handler callback */
    void *arg;
    order o;     /**< for sorting new handlers as they're inserted */
    struct handel_struct *next;
} *handel, _handel;

/** Callback function that gets notified of registering/unregistering hosts for an instance */
typedef void (*register_notify)(instance i, const char *destination, int is_register, void *arg);

/** List of functions, that get notified of registering/unregistering hosts */
typedef struct register_notifier_struct {
    register_notify callback;	/**< function that gets called */
    void *arg;			/**< argument that gets passed to the function */
    struct register_notifier_struct *next;	/**< pointer to further functions, that want to get the notify */
} *register_notifier, _register_notifier;

/** Wrapper around top-level config file sections (xdb, log, service) */
struct instance_struct
{
    char *id;   /**< the id of the instance */
    pool p;
    xmlnode x;  /**< the instance's configuration */
    ptype type; /**< the type of the instance (xdb/log/service) */
    handel hds; /**< delivery handler */
    register_notifier routing_update_callbacks; /**< list of callback functions, that should be called on a routing update */
};

/** Config file handler function callback definition */
typedef result (*cfhandler)(instance id, xmlnode x, void *arg);

/** Heartbeat function callback definition */
typedef result (*beathandler)(void *arg);

/*** public functions for base modules ***/
void register_config(pool p, const char *node, cfhandler f, void *arg); /* register a function to handle that node in the config file */
void register_instance(instance i, char *host); /* associate an id with a hostname for that packet type */
void unregister_instance(instance i, char *host); /* disassociate an id with a hostname for that packet type */
void register_routing_update_callback(instance i, register_notify f, void *arg); /**< register a function that gets called on registering/unregistering a host for an instance */
void register_phandler(instance id, order o, phandler f, void *arg); /* register a function to handle delivery for this instance */
void register_beat(int freq, beathandler f, void *arg); /* register the function to be called from the heartbeat, freq is how often, <= 0 is ignored */
typedef void(*shutdown_func)(void*arg);
void register_shutdown(shutdown_func f,void *arg); /* register to be notified when the server is shutting down */

dpacket dpacket_new(xmlnode x); /* create a new delivery packet from source xml */
dpacket dpacket_copy(dpacket p); /* copy a packet (and it's flags) */
void deliver(dpacket p, instance i); /* deliver packet from sending instance */
void deliver_fail(dpacket p, const char *err); /* bounce a packet intelligently */
void deliver_instance(instance i, dpacket p); /* deliver packet TO the instance, if the result != r_DONE, you have to handle the packet! */
instance deliver_hostcheck(char *host); /* util that returns the instance handling this hostname for normal packets */

/*** global logging/signal symbols ***/
#define LOGT_LEGACY 1
#define LOGT_DELIVER 2
#define LOGT_REGISTER 4
#define LOGT_STATUS 8
#define LOGT_EVENT 16
#define LOGT_CONFIG 32
#define LOGT_DYNAMIC 64
#define LOGT_IO 128
#define LOGT_INIT 256
#define LOGT_EXECFLOW 512
#define LOGT_CLEANUP 1024
#define LOGT_STRANGE 2048
#define LOGT_XML 4096
#define LOGT_THREAD 8192
#define LOGT_STORAGE 16384
#define LOGT_AUTH 32768
#define LOGT_SESSION 65536
#define LOGT_ROSTER 131072
#define LOGT_BYTES 262144

int log_get_facility(const char *facility);
int log_get_level(const char *level);
#define MAX_LOG_SIZE 1024
extern int debug_flag;
inline int get_debug_flag(void);
void set_debug_flag(int v);
void set_cmdline_debug_flag(int v);
void set_debug_facility(int facility);
#ifdef __CYGWIN__
#define log_debug if(get_debug_flag()&1) debug_log
#define log_debug2 if(get_debug_flag()) debug_log2
#else
#define log_debug if(debug_flag&1) debug_log
#define log_debug2 if(debug_flag) debug_log2
#endif
void debug_log(char const* zone, char const* msgfmt, ...);
void debug_log2(char const* zone, int type, char const* msgfmt, ...);
void log_notice(char const* host, char const* msgfmt, ...);
void log_warn(char const* host, char const* msgfmt, ...);
void log_alert(char const* host, char const* msgfmt, ...);
#define log_error log_alert
void logger(char const* type, char const* host, char const* message); /* actually creates and delivers the log message */
void log_record(char const* id, char const* type, char const* action, char const* msgfmt, ...); /* for generic logging support, like log_record("jer@jabber.org","session","end","...") */
void log_generic(char const* logtype, char const* id, char const* type, char const* action, char const* msgfmt, ...);

/*** xdb utilities ***/

/** Ring for handling cached structures */
typedef struct xdbcache_struct {
    instance i;
    int id;
    const char *ns;
    int set; /**< flag that this is a set */
    char *act; /**< for set */
    char *match; /**< for set */
    char *matchpath; /**< for set, namespace aware version of match */
    xht namespaces; /**< for set, namespace prefix declarations for matchpath */
    xmlnode data; /**< for set */
    jid owner;
    int sent;
    int preblock;		/**< thread that created the query is waiting for a pth_cond_notify() on ::cond */
    pth_cond_t cond;
    pth_mutex_t mutex;
    struct xdbcache_struct *prev;
    struct xdbcache_struct *next;
} *xdbcache, _xdbcache;

xdbcache xdb_cache(instance i); /**< create a new xdb cache for this instance */
xmlnode xdb_get(xdbcache xc,  jid owner, const char *ns); /**< blocks until namespace is retrieved, returns xmlnode or NULL if failed */
int xdb_act(xdbcache xc, jid owner, const char *ns, char *act, char *match, xmlnode data); /**< sends new xml action, returns non-zero if failure */
int xdb_act_path(xdbcache xc, jid owner, const char *ns, char *act, char *matchpath, xht namespaces, xmlnode data); /**< sends new xml action, returns non-zero if failure */
int xdb_set(xdbcache xc, jid owner, const char *ns, xmlnode data); /**< sends new xml to replace old, returns non-zero if failure */

/* Error messages */
#define SERROR_NAMESPACE "<stream:error><invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Invalid namespace specified.</text></stream:error>"
#define SERROR_INVALIDHOST "<stream:error><invalid-from xmlns='urn:ietf:params:xml:ns:xmpp-streams'/><text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>Invalid hostname used.</text></stream:error>"

/* ------------------------------------
 * Managed Thread Queue (MTQ) utilities 
 * ------------------------------------*/

/* default waiting threads */
#define MTQ_THREADS 10

/** mtq callback simple function definition */
typedef void (*mtq_callback)(void *arg);

/** Managed thread queue. Has a pointer to the currently assigned thread for this queue. */
typedef struct mtqueue_struct
{
    struct mth_struct *t;
    pth_msgport_t mp;
    int routed;
} *mtq, _mtq;

/** Managed thread queue. Has the message port for the running thread, and the current queue it's processing. */
typedef struct mth_struct
{
    mtq q;
    pth_msgport_t mp;
    pool p;
    pth_t id;
    int busy;
} *mth, _mth;

mtq mtq_new(pool p); /**< Creates a new queue, is automatically cleaned up when p frees */

void mtq_send(mtq q, pool p, mtq_callback f, void *arg); /**< appends the arg to the queue to be run on a thread */

/* MIO - Managed I/O - TCP functions */

/** Struct to handle the write queue */
typedef enum { queue_XMLNODE, queue_CDATA } mio_queue_type;
typedef struct mio_wb_q_st
{
    pth_message_t head;  /* for compatibility */
    pool p;
    mio_queue_type type;
    xmlnode x;
    void *data;
    void *cur;
    int len;
    struct mio_wb_q_st *next;
} _mio_wbq,*mio_wbq;

struct mio_handlers_st;

/* the mio data type */
typedef enum { state_ACTIVE, state_CLOSE } mio_state;
typedef enum { type_LISTEN, type_NORMAL, type_NUL, type_HTTP } mio_type;

/* standard i/o callback function definition */
struct mio_st;
typedef void (*mio_std_cb)(mio_st* m, int state, void *arg, xmlnode x, char *buffer, int bufsz);

/**
 * Representation of a managed TCP socket
 */
typedef struct mio_st {
    pool p;				/**< memory pool for data with the same lifetime as the socket */
    int fd;				/**< file descriptor of the socket */
    mio_type type;			/**< listen (server) socket or normal (client) socket */
    mio_state state;			/**< state of this manages socket, used to flag a socket that it needs to be closed */

    mio_wbq queue;			/**< write buffer queue */
    mio_wbq tail;			/**< the last buffer queue item */

    struct mio_st *prev,*next;		/**< pointers to the previous and next item, if a list of mio_st elements is build */

    void *cb_arg;			/**< MIO event callback argument (do not modify directly) */
    mio_std_cb cb;			/**< MIO event callback (do not modify directly) */
    struct mio_handlers_st *mh;		/**< MIO internal handlers (for reading, writing, setting up TLS layers) */

    xstream    xs;   /* XXX kill me, I suck */
    XML_Parser parser;			/**< sax instance used for this mio socket if we layer an XML stream on top of it */
    xmlnode    stacknode;		/**< the stanza that is currently received */
    void       *ssl;			/**< TLS layer instance for this managed socket (either GNU TLS or OpenSSL) */
    struct {
	int	root:1;			/**< 0 = waiting for the stream root tag, 1 = stream root tag already received */
	int	rated:1;		/**< 0 = no rating for this socket, 1 = socket is rate limited (see ::rate) */
	int	reset_stream:1;		/**< set to 1, if stream has to be resetted */
	int	recall_read_when_readable:1;	/**< recall the read function, when the socket has data available for reading */
	int	recall_read_when_writeable:1;	/**< recall the read function, when the socket has data available for writing */
	int	recall_write_when_readable:1;	/**< recall the write function, when the socket has data available for reading */
	int	recall_write_when_writeable:1;	/**< recall the write function, when the socket allows writing again */
	int	recall_handshake_when_readable:1; /**< recall the handshake function, when the socket has data available for reading */
	int	recall_handshake_when_writeable:1; /**< recall the handshake function, when the socket allows writing again */
    } flags;

    struct karma k;			/**< karma for this socket, used to limit bandwidth of a connection */
    jlimit rate;			/**< what is the rate if ::flags.rated is set */
    char *peer_ip;			/**< IP address of the peer */
    uint16_t peer_port;			/**< port of the peer */
    char *our_ip;			/**< our own IP address */
    uint16_t our_port;			/**< port of us */
    char *connect_errmsg;		/**< error message on failed connects (don't free messages) */
    char *authed_other_side;		/**< if the other side of the stream is authenticated, the identity can be placed here */

    xmppd::ns_decl_list* out_ns;	/**< pointer to the namespaces declared on the outgoing stream root element */
    xmppd::ns_decl_list* in_root;	/**< pointer to the namespaces declared on the incoming root element */
    xmppd::ns_decl_list* in_stanza;	/**< pointer to the namespaces declared on the currently recevied stanza */
    const char *root_lang;		/**< declared language of the incoming stream root element */
} *mio, _mio;

/**
 * @brief structure that holds the global mio data
 *
 * MIO internal use only
 */
typedef struct mio_main_st {
    pool p;             /**< (memory-)pool to hold this data */
    mio master__list;   /**< a list of all the sockets */
    pth_t t;            /**< a pointer to thread for signaling */
    int shutdown;	/**< flag that the select loop can be left (if value is 1) */
    int zzz[2];		/**< pipe used to send signals to the select loop */
    int zzz_active;	/**< if set to something else then 1, there has been sent a signal already, that is not yet processed */
    struct karma *k;	/**< default karma */
    int rate_t, rate_p; /**< default rate, if any */
    char *bounce_uri;	/**< where to bounce HTTP requests to */
} _ios,*ios;

/* MIO SOCKET HANDLERS */
typedef ssize_t (*mio_read_func)	(mio m, void* buf, size_t count);
typedef ssize_t (*mio_write_func)	(mio m, void const* buf, size_t count); 
typedef void    (*mio_parser_func)	(mio m, void const* buf, size_t bufsz);
typedef int     (*mio_accepted_func)	(mio m);
typedef int	(*mio_handshake_func)	(mio m);
typedef void	(*mio_close_func)	(mio m, bool close_read);

/** The MIO handlers data type */
typedef struct mio_handlers_st {
    pool  p;
    mio_read_func	read;
    mio_write_func	write;
    mio_accepted_func	accepted;
    mio_parser_func	parser;
    mio_handshake_func	handshake;
    mio_close_func	close;
} _mio_handlers, *mio_handlers; 

/* standard read/write/accept/connect functions */
ssize_t _mio_raw_read(mio m, void *buf, size_t count);
ssize_t _mio_raw_write(mio m, void *buf, size_t count);
void _mio_raw_parser(mio m, const void *buf, size_t bufsz);
#define MIO_RAW_READ     (mio_read_func)&_mio_raw_read
#define MIO_RAW_WRITE    (mio_write_func)&_mio_raw_write
#define MIO_RAW_ACCEPTED (mio_accepted_func)NULL
#define MIO_RAW_PARSER   (mio_parser_func)&_mio_raw_parser

void mio_xml_reset(mio m);
int  mio_xml_starttls(mio m, int originator, const char *identity);
void _mio_xml_parser(mio m, const void *buf, size_t bufsz);
#define MIO_XML_PARSER  (mio_parser_func)&_mio_xml_parser

/* function helpers */
#define MIO_LISTEN_RAW mio_handlers_new(NULL, NULL, NULL)
#define MIO_CONNECT_RAW mio_handlers_new(NULL, NULL, NULL)
#define MIO_LISTEN_XML mio_handlers_new(NULL, NULL, MIO_XML_PARSER)
#define MIO_CONNECT_XML mio_handlers_new(NULL, NULL, MIO_XML_PARSER)

/* TLS functions */
void    mio_ssl_init     (xmlnode x);
bool	mio_tls_early_init();
int	mio_ssl_starttls (mio m, int originator, const char* identity);
int	mio_ssl_starttls_possible (mio m, const char* identity);
int	mio_ssl_verify(mio m, const char *id_on_xmppAddr);
ssize_t _mio_ssl_read    (mio m, void *buf, size_t count);
ssize_t _mio_ssl_write   (mio m, const void*      buf,       size_t     count);
int     _mio_ssl_accepted(mio m);
void	mio_tls_get_characteristics(mio m, char* buffer, size_t len);
void	mio_tls_get_certtype(mio m, char* buffer, size_t len);
void	mio_tls_get_compression(mio m, char* buffer, size_t len);
#define MIO_SSL_READ     _mio_ssl_read
#define MIO_SSL_WRITE    _mio_ssl_write
#define MIO_SSL_ACCEPTED _mio_ssl_accepted

int	mio_is_encrypted(mio m);

/* MIO handlers helper functions */
mio_handlers mio_handlers_new(mio_read_func rf, mio_write_func wf, mio_parser_func pf);
void         mio_handlers_free(mio_handlers mh);
void         mio_set_handlers(mio m, mio_handlers mh);

/* callback state flags */
#define MIO_NEW       0
#define MIO_BUFFER    1
#define MIO_XML_ROOT  2
#define MIO_XML_NODE  3 
#define MIO_CLOSED    4
#define MIO_ERROR     5

/* Initializes the MIO subsystem */
void mio_init(void);

/* Stops the MIO system */
void mio_stop(void);

/* Create a new mio object from a file descriptor */
mio mio_new(int fd, mio_std_cb cb, void *cb_arg, mio_handlers mh);

/* Reset the callback and argument for an mio object */
void mio_reset(mio m, mio_std_cb cb, void *arg);

/* Request the mio socket be closed */
void mio_close(mio m);

/* Writes an xmlnode to the socket */
void mio_write(mio m, xmlnode stanza, char *buffer, int len);

/* write the root element to a mio stream */
void mio_write_root(mio m, xmlnode root, int stream_type);

/* Sets the karma values for a socket */
void mio_karma(mio m, int val, int max, int inc, int dec, int penalty, int restore);
void mio_karma2(mio m, struct karma *k);

/* Sets connection based rate limits */
void mio_rate(mio m, int rate_time, int max_points);

/* Pops the next xmlnode from the queue, or NULL if no more nodes */
xmlnode mio_cleanup(mio m);

/* Connects to an ip */
void mio_connect(char *host, int port, mio_std_cb cb, void *cb_arg, int timeout, mio_handlers mh);

/* Starts listening on a port/ip, returns NULL if failed to listen */
mio mio_listen(int port, const char *sourceip, mio_std_cb cb, void *cb_arg, mio_handlers mh);

int _mio_write_dump(mio m);

/* some nice api utilities */
#define mio_pool(m) (m->p)
#define mio_ip(m) (m ? m->peer_ip : NULL)
#define mio_connect_errmsg(m) (m->connect_errmsg)

/*-----------------
 * Access controll 
 *-----------------*/

int acl_check_access(xdbcache xdb, const char *function, const jid user);
jid acl_get_users(xdbcache xdb, const char *function);
