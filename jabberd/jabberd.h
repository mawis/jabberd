/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <jabberdlib.h>
#ifdef HAVE_SSL
#include <openssl/ssl.h>
#endif /* HAVE_SSL */

/** Packet types */
typedef enum { p_NONE, p_NORM, p_XDB, p_LOG, p_ROUTE } ptype;

/** Ordering types, me first me first, managerial, engineer, grunt */
typedef enum { o_PRECOND, o_COND, o_PREDELIVER, o_DELIVER } order;

/** Result types, unregister me, I pass, I should be last, I suck, I rock */
typedef enum { r_UNREG, r_NONE, r_PASS, r_LAST, r_ERR, r_DONE } result;

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

/** Wrapper around top-level config file sections (xdb, log, service) */
struct instance_struct
{
    char *id;   /**< the id of the instance */
    pool p;
    xmlnode x;  /**< the instance's configuration */
    ptype type; /**< the type of the instance (xdb/log/service) */
    handel hds; /**< delivery handler */
};

/** Config file handler function callback definition */
typedef result (*cfhandler)(instance id, xmlnode x, void *arg);

/** Heartbeat function callback definition */
typedef result (*beathandler)(void *arg);

/*** public functions for base modules ***/
void register_config(char *node, cfhandler f, void *arg); /* register a function to handle that node in the config file */
void register_instance(instance i, char *host); /* associate an id with a hostname for that packet type */
void unregister_instance(instance i, char *host); /* disassociate an id with a hostname for that packet type */
void register_phandler(instance id, order o, phandler f, void *arg); /* register a function to handle delivery for this instance */
void register_beat(int freq, beathandler f, void *arg); /* register the function to be called from the heartbeat, freq is how often, <= 0 is ignored */
typedef void(*shutdown_func)(void*arg);
void register_shutdown(shutdown_func f,void *arg); /* register to be notified when the server is shutting down */

dpacket dpacket_new(xmlnode x); /* create a new delivery packet from source xml */
dpacket dpacket_copy(dpacket p); /* copy a packet (and it's flags) */
void deliver(dpacket p, instance i); /* deliver packet from sending instance */
void deliver_fail(dpacket p, char *err); /* bounce a packet intelligently */
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
void debug_log(char *zone, const char *msgfmt, ...);
void debug_log2(char *zone, const int type, const char *msgfmt, ...);
void log_notice(char *host, const char *msgfmt, ...);
void log_warn(char *host, const char *msgfmt, ...);
void log_alert(char *host, const char *msgfmt, ...);
#define log_error log_alert
void logger(char *type, char *host, char *message); /* actually creates and delivers the log message */
void log_record(char *id, char *type, char *action, const char *msgfmt, ...); /* for generic logging support, like log_record("jer@jabber.org","session","end","...") */
extern int jabberd__signalflag; /* set to the last signal to be processed */
void jabberd_signal(void); /* process the signal, called from the heartbeat thread */

/*** xdb utilities ***/

/** Ring for handling cached structures */
typedef struct xdbcache_struct
{
    instance i;
    int id;
    char *ns;
    int set; /**< flag that this is a set */
    char *act; /**< for set */
    char *match; /**< for set */
    xmlnode data; /**< for set */
    jid owner;
    int sent;
    int preblock;
    pth_cond_t cond;
    pth_mutex_t mutex;
    struct xdbcache_struct *prev;
    struct xdbcache_struct *next;
} *xdbcache, _xdbcache;

xdbcache xdb_cache(instance i); /**< create a new xdb cache for this instance */
xmlnode xdb_get(xdbcache xc,  jid owner, char *ns); /**< blocks until namespace is retrieved, returns xmlnode or NULL if failed */
int xdb_act(xdbcache xc, jid owner, char *ns, char *act, char *match, xmlnode data); /**< sends new xml action, returns non-zero if failure */
int xdb_set(xdbcache xc, jid owner, char *ns, xmlnode data); /**< sends new xml to replace old, returns non-zero if failure */

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

void _mtq_send(mtq q, pool p, mtq_callback f, void *arg); /**< appends the arg to the queue to be run on a thread */

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

struct mio_handlers_st; /* grr.. stupid fsking chicken and egg C definitions */

/* the mio data type */
typedef enum { state_ACTIVE, state_CLOSE } mio_state;
typedef enum { type_LISTEN, type_NORMAL, type_NUL, type_HTTP } mio_type;

/** Managed I/O. TCP socket management. */
typedef struct mio_st
{
    pool p;
    int fd;
    mio_type type; /* listen (server) socket or normal (client) socket */
    mio_state state;

    mio_wbq queue; /* write buffer queue */
    mio_wbq tail;  /* the last buffer queue item */

    struct mio_st *prev,*next;

    void *cb_arg;    /* do not modify directly */
    void *cb;     /* do not modify directly */
    struct mio_handlers_st *mh;

    xstream    xs;   /* XXX kill me, I suck */
    XML_Parser parser;
    int        root;
    xmlnode    stacknode;
    void       *ssl;
    int	       reset_stream; /**< set to 1, if stream has to be resetted */

    struct karma k;
    int rated;   /* is this socket rate limted? */
    jlimit rate; /* if so, what is the rate?    */
    char *ip;
    char *connect_errmsg; /**< error message on failed connects (don't free messages) */
} *mio, _mio;

/* MIO SOCKET HANDLERS */
typedef ssize_t (*mio_read_func)    (mio m, void*            buf,       size_t     count);
typedef ssize_t (*mio_write_func)   (mio m, const void*      buf,       size_t     count); 
typedef void    (*mio_parser_func)  (mio m,  const void*      buf,       size_t     bufsz);
typedef int     (*mio_accept_func)  (mio m, struct sockaddr* serv_addr, socklen_t* addrlen);
typedef int     (*mio_connect_func) (mio m, struct sockaddr* serv_addr, socklen_t  addrlen);

/** The MIO handlers data type */
typedef struct mio_handlers_st
{
    pool  p;
    mio_read_func   read;
    mio_write_func  write;
    mio_accept_func accept;
    mio_parser_func parser;
} _mio_handlers, *mio_handlers; 

/* standard read/write/accept/connect functions */
#define MIO_READ_FUNC    pth_read 
#define MIO_WRITE_FUNC   pth_write
#define MIO_ACCEPT_FUNC  pth_accept
#define MIO_CONNECT_FUNC pth_connect

ssize_t _mio_raw_read(mio m, void *buf, size_t count);
ssize_t _mio_raw_write(mio m, void *buf, size_t count);
int _mio_raw_accept(mio m, struct sockaddr* serv_addr, socklen_t* addrlen);
void _mio_raw_parser(mio m, const void *buf, size_t bufsz);
int _mio_raw_connect(mio m, struct sockaddr* serv_addr, socklen_t  addrlen);
#define MIO_RAW_READ    (mio_read_func)&_mio_raw_read
#define MIO_RAW_WRITE   (mio_write_func)&_mio_raw_write
#define MIO_RAW_ACCEPT  (mio_accept_func)&_mio_raw_accept
#define MIO_RAW_CONNECT (mio_connect_func)&_mio_raw_connect
#define MIO_RAW_PARSER  (mio_parser_func)&_mio_raw_parser

int  mio_xml_starttls(mio m, int originator, const char *identity);
void _mio_xml_parser(mio m, const void *buf, size_t bufsz);
#define MIO_XML_PARSER  (mio_parser_func)&_mio_xml_parser

/* function helpers */
#define MIO_LISTEN_RAW NULL, mio_handlers_new(NULL, NULL, NULL)
#define MIO_CONNECT_RAW  NULL, mio_handlers_new(NULL, NULL, NULL)
#define MIO_LISTEN_XML NULL, mio_handlers_new(NULL, NULL, MIO_XML_PARSER)
#define MIO_CONNECT_XML  NULL, mio_handlers_new(NULL, NULL, MIO_XML_PARSER)

/* SSL functions */
void    mio_ssl_init     (xmlnode x);
int	mio_ssl_starttls (mio m, int originator, const char* identity);
int	mio_ssl_starttls_possible (mio m, const char* identity);
void    _mio_ssl_cleanup (void *arg);
ssize_t _mio_ssl_read    (mio m, void *buf, size_t count);
ssize_t _mio_ssl_write   (mio m, const void*      buf,       size_t     count);
int     _mio_ssl_accept  (mio m, struct sockaddr* serv_addr, socklen_t* addrlen);
int     _mio_ssl_connect (mio m, struct sockaddr* serv_addr, socklen_t  addrlen);
#define MIO_SSL_READ    _mio_ssl_read
#define MIO_SSL_WRITE   _mio_ssl_write
#define MIO_SSL_ACCEPT  _mio_ssl_accept
#define MIO_SSL_CONNECT _mio_ssl_connect

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

/* standard i/o callback function definition */
typedef void (*mio_std_cb)(mio m, int state, void *arg);
typedef void (*mio_xml_cb)(mio m, int state, void *arg, xmlnode x);
typedef void (*mio_raw_cb)(mio m, int state, void *arg, char *buffer,int bufsz);
typedef void (*mio_ssl_cb)(mio m, int state, void *arg, char *buffer,int bufsz);

/** Initializes the MIO subsystem */
void mio_init(void);

/** Stops the MIO system */
void mio_stop(void);

/** Create a new mio object from a file descriptor */
mio mio_new(int fd, void *cb, void *cb_arg, mio_handlers mh);

/** Reset the callback and argument for an mio object */
mio mio_reset(mio m, void *cb, void *arg);

/** Request the mio socket be closed */
void mio_close(mio m);

/** Writes an xmlnode to the socket */
void mio_write(mio m,xmlnode x, char *buffer, int len);

/** Sets the karma values for a socket */
void mio_karma(mio m, int val, int max, int inc, int dec, int penalty, int restore);
void mio_karma2(mio m, struct karma *k);

/** Sets connection based rate limits */
void mio_rate(mio m, int rate_time, int max_points);

/** Pops the next xmlnode from the queue, or NULL if no more nodes */
xmlnode mio_cleanup(mio m);

/** Connects to an ip */
void mio_connect(char *host, int port, void *cb, void *cb_arg, int timeout, mio_connect_func f, mio_handlers mh);

/** Starts listening on a port/ip, returns NULL if failed to listen */
mio mio_listen(int port, char *sourceip, void *cb, void *cb_arg, mio_accept_func f, mio_handlers mh);

/* some nice api utilities */
#define mio_pool(m) (m->p)
#define mio_ip(m) (m->ip)
#define mio_connect_errmsg(m) (m->connect_errmsg)

