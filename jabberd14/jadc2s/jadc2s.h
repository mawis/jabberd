#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "mio/mio.h"
#include <expat.h>
#include "util/util.h"

#ifdef USE_SSL
# include <openssl/ssl.h>
# include <openssl/err.h>
#endif

/****** First notes by jer on 2002/03/17: ******

This is jadc2s, the jabberd client-to-server socket manager.

Ultimately we only have one task here, to multiplex incoming connections from clients
and relay their packets to a session manager (sm).  Due to the less-than-perfect protocol (see PROTO)
used to talk to a session manager a bit more work is required: watching authentication transactions
between the client and sm and starting sessions for the client with the sm.

All of the system I/O event handling is in mio/, all XML parsing (expat) in xml/, and the rest
of the common utilities (from 1.4) are in util/.

To accomplish our goals, we have two basic data types, a conn(ection) and a chunk.
The connection wraps the data we need for every client.  The chunk wraps the xml as 
it's being parsed from or written to a connection.  The common conn/chunk utilities
are in conn.c.

There is one connection back to the sm at all times, all of it's processing logic is in
connection.c.  All of the incoming client connection processing logic is in clients.c.

Each of these two files consists of an I/O event callback (*_io) where the data is
read/written, and the expat callbacks for that conn where the conn state is updated
based on the incoming xml and chunks are created/routed.

All clients are hashed based on their unique id in a master hash table.

*/

/* stream error conditions */
#define STREAM_ERR_BAD_FORMAT		 "<bad-format xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_CONFLICT		 "<conflict xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_HOST_UNKNOWN		 "<host-unknown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_INTERNAL_SERVER_ERROR "<internal-server-error xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_INVALID_NAMESPACE	 "<invalid-namespace xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_INVALID_XML		 "<invalid-xml xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_NOT_AUTHORIZED	 "<not-authorized xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_REMOTE_CONNECTION_FAILED "<remote-connection-failed xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_SYSTEM_SHUTDOWN	 "<system-shutdown xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
#define STREAM_ERR_TIMEOUT		 "<connection-timeout xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"

/* forward decls */
typedef struct conn_st *conn_t;
typedef struct c2s_st *c2s_t;

/* chunk definition */
typedef struct chunk_st
{
    /* the xml itself */
    nad_t nad;
    int packet_elem;    /* actual packet start element */

    /* and the char representation, for writing */
    char *wcur;
    int wlen;

    /* for linking chunks together */
    struct chunk_st *next;
} *chunk_t;

/* connection data */

/**
 * at which state this connection is
 */
typedef enum {
    state_NONE,	/**< no connection on this socket yet, or waiting for client auth */
    state_NEGO, /**< we have to determine what sort of connection we accepted */
    state_AUTH, /**< we are waiting for the session manager to accept the authentication */
    state_SESS, /**< we are waiting for the session manager to start the session */
    state_OPEN	/**< the session has been started, normal operation */
} conn_state_t;

/**
 * protocol variant we are using on this socket
 */
typedef enum {
    type_NORMAL,/**< stone age Jabber protocol connection */
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

struct conn_st
{
    c2s_t c2s;			/**< the jadc2s instance we are running in */

    /* vars for this conn */
    int fd;			/**< file descriptor of this connection */
    char *ip;			/**< other end's IP address for this conn */
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
    jid myid;			/**< the source-JID used to send messages to
				     the session manager */
    jid smid;			/**< the dest-JID used to send messages to the
				     session manager */
    jid userid;			/**< the JabberID of the user (only used for
				     generating connect/disconnect reports) */

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
};

/* conn happy/sad */
conn_t conn_new(c2s_t c2s, int fd);
void conn_free(conn_t c);

/* send a stream error */
void conn_error(conn_t c, char *condition, char *err);

/* close a conn with error (conn_t becomes invalid after this is called!) */
void conn_close(conn_t c, char *condition, char *err);

/* create a new chunk */
chunk_t chunk_new(conn_t c);

/* and free one */
void chunk_free(chunk_t chunk);

/* write a chunk to a conn, optinally wrap with route */
void chunk_write(conn_t c, chunk_t chunk, char *to, char *from, char *rtype);

/* transfer rate limitting, returns the max number of 
 * elements that can be read
 */
int conn_max_read_len(conn_t c);

/* read/write wrappers for a conn */
int conn_read(conn_t c, char *buf, int len);
int conn_write(conn_t c);

/* fill a nad with information about a user's connection */
void connectionstate_fillnad(nad_t nad, char *from, char *to, char *user, int is_login, char *ip, const char *ssl_version, const char *ssl_cipher, char *ssl_size_secret, char *ssl_size_algorithm);
void connectionstate_send(config_t config, conn_t c, conn_t client, int is_login);

/* maximum number of xml children in a chunk (checked by conn_read) */
#define MAXDEPTH 10000
#define MAXDEPTH_ERR "maximum node depth reached"

/* maximum number of fd for daemonize */
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

/* c2s master data type */
struct c2s_st
{
    /* globals */
    mio_t mio;
    int shutting_down;
    jid_environment_t jid_environment;

    /* setup */
    config_elem_t local_id;
    config_elem_t local_alias;
    char *local_ip;
    int local_port;
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
#endif

    /* our config */
    xht config;

    /* nad cache */
    nad_cache_t nads;

    /* client conn stuff */
    xht connection_rates; /* our current rate limit checks */
    int connection_rate_times;
    int connection_rate_seconds;
    xht pending; /* waiting for auth/session */
    struct conn_st *conns; /* all connected conns */
    bad_conn_t bad_conns; /* Karma controlled conns */
    bad_conn_t bad_conns_tail;
    int timeout; /* how long to process mio */

    int max_fds;

    int num_clients;

    /* session manager stuff */
    conn_t sm;
    char *sm_host, *sm_id, *sm_secret;
    int sm_port;

    /* logging */
    log_t log;
    int iplog;
};

/* the handler for client mio events */
int client_io(mio_t m, mio_action_t a, int fd, void *data, void *arg);

/* create a sm connection (block until it's connected) */
int connect_new(c2s_t c2s);

/* run in daemon mode */ 
int daemonize(void);
int ignore_term_signals(void);

/* wrappers around read() and write(), with ssl support */
int _read_actual(conn_t c, int fd, char *buf, size_t count);
int _peek_actual(conn_t c, int fd, char *buf, size_t count);
int _write_actual(conn_t c, int fd, const char *buf, size_t count);

/* debug logging */
void debug_log(char *file, int line, const char *msgfmt, ...);
#define ZONE __FILE__,__LINE__
#define MAX_DEBUG 1024

/* if no debug, basically compile it out */
#ifdef DEBUG
#define log_debug debug_log
#else
#define log_debug if(0) debug_log
#endif

