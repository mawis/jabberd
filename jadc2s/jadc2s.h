#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <string>
#include <map>

#include "mio/mio.h"
#include <expat.h>
#include "util/util.h"

#ifdef USE_SSL
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

#ifdef WITH_SASL
# include <sasl/sasl.h>
# include <sasl/saslutil.h>
#endif

/**
 * @file jadc2s.h
 * @brief the main header file of jadc2s, mainly defining data structures
 */

/**
 * @mainpage
 *
 * @section jer_comments First notes by jer on 2002-03-17
 *
 * This is jadc2s, the jabberd14 client-to-server socket manager.
 *
 * Ultimately we only have one task here, to multiplex incoming connections
 * from clients and relay their packets to a session manager (sm).  Due to
 * the less-than-perfect protocol (see PROTO) used to talk to a session
 * manager a bit more work is required: watching authentication transactions
 * between the client and sm and starting sessions for the client with the sm.
 *
 * All of the system I/O event handling is in mio/, and the rest of the common
 * utilities (from 1.4) are in util/.
 *
 * To accomplish our goals, we have two basic data types, a conn(ection) and a
 * chunk.  The connection wraps the data we need for every client.  The chunk
 * wraps the xml as it's being parsed from or written to a connection.  The
 * common conn/chunk utilities are in conn.c.
 *
 * There is one connection back to the sm at all times, all of it's processing
 * logic is in connection.c.  All of the incoming client connection processing
 * logic is in clients.c.
 *
 * Each of these two files consists of an I/O event callback (*_io) where the
 * data is read/written, and the expat callbacks for that conn where the conn
 * state is updated based on the incoming xml and chunks are created/routed.
 *
 * All clients are hashed based on their unique id in a master hash table.
 */

/* stream error conditions */
#define STREAM_ERR_BAD_FORMAT		 "bad-format"
#define STREAM_ERR_CONFLICT		 "conflict"
#define STREAM_ERR_HOST_UNKNOWN		 "host-unknown"
#define STREAM_ERR_INTERNAL_SERVER_ERROR "internal-server-error"
#define STREAM_ERR_INVALID_NAMESPACE	 "invalid-namespace"
#define STREAM_ERR_INVALID_XML		 "invalid-xml"
#define STREAM_ERR_NOT_AUTHORIZED	 "not-authorized"
#define STREAM_ERR_REMOTE_CONNECTION_FAILED "remote-connection-failed"
#define STREAM_ERR_SYSTEM_SHUTDOWN	 "system-shutdown"
#define STREAM_ERR_TIMEOUT		 "connection-timeout"

/* forward decls */
typedef struct conn_st *conn_t;
typedef struct c2s_st *c2s_t;

/**
 * chunk definition
 *
 * A chunk wraps the xml as it's being parsed from or written to a connection.
 */
typedef struct chunk_st
{
    nad_t nad;		/**< the xml itself */
    int packet_elem;    /**< actual packet start element */

    /* and the char representation, for writing */
    char *wcur;		/**< the char representation for writing */
    int wlen;		/**< length of the char representation */

    void *to_free;	/**< pointer to memory, that should be freed on chunk_free() */

    struct chunk_st *next;	/**< for linking chunks together */
} *chunk_t;

/* connection data */

/**
 * at which state this connection is
 */
typedef enum {
    state_NONE,	/**< no connection on this socket yet, or waiting for client auth */
    state_NEGO, /**< we have to determine what sort of connection we accepted */
    state_SASL, /**< currently in SASL handshake */
    state_AUTH, /**< we are waiting for the session manager to accept the authentication */
    state_SESS, /**< we are waiting for the session manager to start the session */
    state_OPEN	/**< the session has been started, normal operation */
} conn_state_t;

/**
 * at which state in authenticating, resource binding and session starting the connection is
 */
typedef enum {
    state_auth_NONE,		/**< SASL has not yet been finished */
    state_auth_SASL_DONE,	/**< SASL has been finished */
    state_auth_BOUND_RESOURCE,	/**< a resource has been bound to the session */
    state_auth_SESSION_STARTED	/**< the session has been started */
} auth_state_t;

/**
 * protocol variant we are using on this socket
 */
typedef enum {
    type_NORMAL,/**< stone age Jabber protocol connection */
    type_XMPP,  /**< XMPP1.0 connection */
    type_HTTP,	/**< stone age Jabber packet in a single HTTP request */
    type_FLASH	/**< stone age Jabber using the flash hack */
} conn_type_t;

/**
 * possible states of the Jabber over SSL/TLS autodetection
 */
typedef enum {
    autodetect_NONE,	/**< we don't have to autodetect SSL/TLS */
    autodetect_READY,	/**< we now have to autodetect if SSL/TLS is used */
    autodetect_PLAIN,	/**< we detected that there is no SSL/TLS (or STARTTLS is used later) */
    autodetect_TLS	/**< we detected that SSL/TLS is used (no STARTTLS)*/
} autodetect_state_t;

/**
 * which element name has been used for the root element
 */
typedef enum {
    root_element_NONE,		/**< no root element has been sent yet */
    root_element_NORMAL,	/**< a normal stream:stream element has been sent */
    root_element_FLASH		/**< a flash:stream element has been sent */
} root_element_t;

/**
 * The conn(ection) wraps the data we need for every client
 */
struct conn_st {
    c2s_t c2s;			/**< the jadc2s instance we are running in */

    /* vars for this conn */
    int fd;			/**< file descriptor of this connection */
    char *ip;			/**< other end's IP address for this conn */
    int port;			/**< other end's port address for this conn */
    int read_bytes;		/**< bytes read within the present 'karma
				     interval' */
    time_t last_read;		/**< last time something has been read
				     (for karma calculations) */
    conn_state_t state;		/**< which of several states have been reached
				     on the way to establish a session */
    conn_type_t type;		/**< type of this connection
				     (normal conn , flash-hack conn, ...) */ 
    time_t start;		/**< when the client started to establish
				     a session */
    root_element_t root_element;/**< root element used on the connection */
    char *local_id;		/**< domain of the session manager the
				     client connected to */

#ifdef USE_SSL    
    SSL *ssl;			/**< openssl's data for this connection */
    autodetect_state_t autodetect_tls;
    				/**< SSL/TLS autodetection state */
#endif

    /* tracking the id for the conn or chunk */
    pool idp;			/**< memory pool for JIDs in this structure */
    char *sid;			/**< session id (used for some auth schemes */
    char *sc_sm;		/**< session manager id for this conn in new session protocol, NULL for old protocol */
    char *id_session_start;	/**< id of the iq packet of the client, that requested session start, NULL else */
    jid myid;			/**< the source-JID used to send messages to
				     the session manager */
    jid smid;			/**< the dest-JID used to send messages to the
				     session manager */
    jid userid;                 /**< the JabberID of the user (only used for
				     generating connect/disconnect reports) */
    jid authzid;		/**< the JabberID the user authorized as (in SASL mode) */


    /* chunks being written */
    chunk_t writeq;		/**< queue of chunks that have to be send to
				     the client */
    chunk_t qtail;		/**< end of the writeq queue (to speed up
				     adding elements to the end of it) */

    /* parser stuff */
    XML_Parser expat;		/**< parser used for parsing XML on this conn */
    int depth;			/**< the element nesting level on this conn */
    nad_t nad;			/**< the nad currently being build */

#ifdef FLASH_HACK
    /* Flash Hack */
    int flash_hack;		/**< true if we are _currently_ replacing expat,
				     see type to see if it is a flash
				     connection! */
#endif

    /* Traffic counting */
    unsigned long int in_bytes;	/**< how many bytes have been read */
    unsigned long int out_bytes;/**< how many bytes have been written */
    unsigned int in_stanzas;	/**< how many stanzas have been read */
    unsigned int out_stanzas;	/**< how many stanzas have been written */

    /* reset stream */
    int reset_stream;		/**< if set to 1 the stream will be reset (restarted) */

    /* SASL */
#ifdef WITH_SASL
    sasl_conn_t *sasl_conn;	/**< connection object used by the sasl library */
    unsigned	*sasl_outbuf_size; /**< maximum size of data we can pass to sasl_encode() */
#endif
    auth_state_t sasl_state;	/**< if SASL, resource binding, and session starting has been done */
};

/* conn happy/sad */
conn_t conn_new(c2s_t c2s, int fd);
void conn_free(conn_t c);

/** send a stream error */
void conn_error(conn_t c, const char *condition, const char *err);

/** close a conn with error (conn_t becomes invalid after this is called!) */
void conn_close(conn_t c, const char *condition, const char *err);

/** create a new chunk */
chunk_t chunk_new(conn_t c);
chunk_t chunk_new_packet(conn_t c, int packet_elem);
chunk_t chunk_new_free(nad_cache_t nads);

/** and free one */
void chunk_free(chunk_t chunk);

/** write a chunk to a conn, optinally wrap with route */
typedef enum {
    chunk_NORMAL,		/**< write chunk as normal chunk */
    chunk_OPEN,			/**< write only the open tag of the chunk */
    chunk_CLOSE			/**< write only the close tag of the chunk */
} chunk_type_enum;
void chunk_write(conn_t c, chunk_t chunk, const char *to, const char *from, const char *rtype);
void chunk_write_typed(conn_t c, chunk_t chunk, const char *to, const char *from, const char *rtype, chunk_type_enum chunk_type);

/**
 * transfer rate limitting, returns the max number of elements that can be read
 */
int conn_max_read_len(conn_t c);

/* read/write wrappers for a conn */
int conn_read(conn_t c, char *buf, int len);
int conn_write(conn_t c);

/* fill a nad with information about a user's connection */
void connectionstate_fillnad(nad_t nad, char *from, char *to, char *user, int is_login, char *ip, const char *ssl_version, const char *ssl_cipher, const char *ssl_size_secret, const char *ssl_size_algorithm);
void connectionstate_send(config_t config, conn_t c, conn_t client, int is_login);

/** maximum number of xml children in a chunk (checked by conn_read) */
#define MAXDEPTH 10000
#define MAXDEPTH_ERR "maximum node depth reached" /**< error to generate if MAXDEPTH reached */

/** maximum number of fd for daemonize */
#define MAXFD 255

/** IP Connection Rate Limit Functions **/
int connection_rate_check(c2s_t c2s, const char* ip);
void connection_rate_cleanup(c2s_t c2s);

typedef struct bad_conn_st* bad_conn_t;
struct bad_conn_st
{
    conn_t c;
    time_t last;
    bad_conn_t next;
};

/* IP connection rate info */
typedef struct connection_rate_st
{
    char* ip; /* need a copy of the ip */
    int count; /* How many have connected */
    time_t first_time; /* The time of the first conn */
} *connection_rate_t;

/** c2s master data type */
struct c2s_st
{
    /* globals */
    mio_t mio;
    int shutting_down;
    jid_environment_t jid_environment;

    /* setup */
    config_elem_t local_id;
    config_elem_t local_alias;
    config_elem_t local_noregister;
    config_elem_t local_nolegacyauth;	/**< hosts for which legacy authentication is not advertized */
    char *local_ip;
    int local_port;
    char *local_statfile;
    char *http_forward;
#ifdef USE_SSL
    int local_sslport;
    char *pemfile;
    char *ciphers;
    int ssl_no_ssl_v2;
    int ssl_no_ssl_v3;
    int ssl_no_tls_v1;
    int ssl_enable_workarounds;
    int ssl_enable_autodetect;

    SSL_CTX *ssl_ctx;

    int tls_required;
#endif

    config_t config;		/**< our configuration */

    nad_cache_t nads;		/**< nad cache */

    /* client conn stuff */
    std::map<std::string, connection_rate_t> *connection_rates; /**< our current rate limit checks */
    int connection_rate_times;
    int connection_rate_seconds;
    std::map<std::string, conn_t> *pending; /**< waiting for auth/session */
    struct conn_st *conns; /**< all connected conns */
    bad_conn_t bad_conns; /**< Karma controlled conns */
    bad_conn_t bad_conns_tail;
    int timeout; /**< how long to process mio */
    int default_timeout; /**< configured default timeout */

    int max_fds;

    int num_clients;

    /* session manager stuff */
    conn_t sm;
    char *sm_host, *sm_id, *sm_secret;
    int sm_port;

    /* logging */
    xmppd::logging *log;	/**< logging instance to use */
    int iplog;

    /* SASL */
    int sasl_enabled;		/**< 0 = only legacy auth by session manager, 1 = auth by jadc2s */
    int sasl_jep0078;		/**< 0 = legacy authentication not supported, 1 = JEP-0078 supported */
    char *sasl_appname;		/**< application name passed to SASL library (to generate SASL conf file name) */
    char *sasl_service;		/**< registered service name, should always be 'xmpp' */
    char *sasl_fqdn;		/**< FQDN passed to sasl library */
    char *sasl_defaultrealm;	/**< default realm passed to sasl library */
    unsigned sasl_min_ssf;	/**< minimum security strength factor for SASL */
    unsigned sasl_max_ssf;	/**< maximum security strength factor for SASL */
    int sasl_noseclayer;	/**< 0 = allow SASL security layer, 1 = do not allow SASL security layer */
    unsigned sasl_sec_flags;	/**< SASL security flags to set */
    config_elem_t sasl_admin;	/**< accounts, that are allowed to authorize as other users */
};

/** the handler for client mio events */
int client_io(mio_t m, mio_action_t a, int fd, const void *data, void *arg);
void client_send_sc_command(conn_t sm_conn, const char *to, const char *from, const char *action, const jid target, const char *id, const char *sc_sm, const char *sc_c2s);

/** create a sm connection (block until it's connected) */
int connect_new(c2s_t c2s);

/* wrappers around read() and write(), with ssl support */
int _read_actual(conn_t c, int fd, char *buf, size_t count);
int _peek_actual(conn_t c, int fd, char *buf, size_t count);

/** debug logging */
void debug_log(char *file, int line, const char *msgfmt, ...);
#define ZONE __FILE__,__LINE__
#define MAX_DEBUG 1024

/* if no debug, basically compile it out */
#ifdef DEBUG
#define log_debug debug_log
#else
#define log_debug if(0) debug_log
#endif

