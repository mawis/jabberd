#include "mio/mio.h"
#include "xmlparse/xmlparse.h"
#include "util/util.h"

#ifdef USE_SSL
# include <openssl/ssl.h>
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

/* forward decls */
typedef struct conn_st *conn_t;
typedef struct c2s_st *c2s_t;

/* chunk definition */
typedef struct chunk_st
{
    /* vars used for creating the chunk on the fly */
    char *to, *from;

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
typedef enum { state_NONE, state_NEGO, state_AUTH, state_SESS, state_OPEN } conn_state_t;
typedef enum { type_NORMAL, type_HTTP, type_FLASH } conn_type_t;
struct conn_st
{
    c2s_t c2s;

    /* vars for this conn */
    int fd;
    int read_bytes;
    time_t last_read;
    conn_state_t state;
    conn_type_t type;
    time_t start;
    char *root_name;
    char *local_id;

#ifdef USE_SSL    
    SSL *ssl;
#endif

    /* tracking the id for the conn or chunk */
    pool idp;
    char *sid;
    jid myid, smid;

    /* chunks being written */
    chunk_t writeq, qtail;

    /* parser stuff */
    XML_Parser expat;
    int depth;

    /* the nad currently being built */
    nad_t nad;

    /* Flash Hack */
    int flash_hack;
};

/* conn happy/sad */
conn_t conn_new(c2s_t c2s, int fd);
void conn_free(conn_t c);

/* close a conn with error (conn_t becomes invalid after this is called!) */
void conn_close(conn_t c, char *err);

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

    /* setup */
    config_elem_t local_id;
    char *local_ip;
    int local_port;
#ifdef USE_SSL
    int local_sslport;
    char *pemfile;

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

