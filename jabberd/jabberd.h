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
#include <jabber/jabber.h>
#include <pth.h>

/* packet types */
typedef enum { p_NONE, p_NORM, p_XDB, p_LOG, p_ROUTE } ptype;

/* ordering types, me first me first, managerial, engineer, grunt */
typedef enum { o_PRECOND, o_COND, o_PREDELIVER, o_DELIVER } order;

/* result types, unregister me, I pass, I should be last, I suck, I rock */
typedef enum { r_UNREG, r_NONE, r_PASS, r_LAST, r_ERR, r_DONE } result;

typedef struct instance_struct *instance, _instance;

/* packet wrapper, d as in delivery or daemon, whichever pleases you */
typedef struct dpacket_struct
{
    char *host;
    jid id;
    ptype type;
    pool p;
    xmlnode x;
} *dpacket, _dpacket;

/* delivery handler function callback definition */
typedef result (*phandler)(instance id, dpacket p, void *arg);

/* delivery handler list */
typedef struct handel_struct
{
    pool p;
    phandler f;
    void *arg;
    order o; /* for sorting new handlers as they're inserted */
    struct handel_struct *next;
} *handel, _handel;

/* wrapper around top-level config file sections */
struct instance_struct
{
    char *id;
    pool p;
    xmlnode x;
    ptype type;
    handel hds;
    int flag_used;
};

/* config file handler function callback definition */
typedef result (*cfhandler)(instance id, xmlnode x, void *arg);

/* heartbeat function callback definition */
typedef result (*beathandler)(void *arg);

/*** public functions for base modules ***/
void register_config(char *node, cfhandler f, void *arg); /* register a function to handle that node in the config file */
void register_phandler(instance id, order o, phandler f, void *arg); /* register a function to handle delivery for this instance */
void register_instance(instance id, char *host); /* associate an id with a hostname for that packet type */
void unregister_instance(instance id, char *host); /* disassociate an id with a hostname for that packet type */
void register_beat(int freq, beathandler f, void *arg); /* register the function to be called from the heartbeat, freq is how often, 0 is always */
typedef void(*shutdown_func)(void*arg);
void register_shutdown(shutdown_func f,void *arg); /* register to be notified when the server is shutting down */

dpacket dpacket_new(xmlnode x); /* create a new delivery packet from source xml */
dpacket dpacket_copy(dpacket p); /* copy a packet (and it's flags) */
void deliver_fail(dpacket p, char *err); /* bounce a packet intelligently */
void deliver(dpacket p, instance i); /* deliver packet from sending instance */
result deliver_instance(instance i, dpacket p); /* deliver packet TO the instance, if the result != r_DONE, you have to handle the packet! */

/*** global logging symbols ***/
#define MAX_LOG_SIZE 1024
extern int debug_flag;
void debug_log(char *zone, const char *msgfmt, ...);
#define log_debug if(debug_flag) debug_log
void log_notice(char *host, const char *msgfmt, ...);
void log_warn(char *host, const char *msgfmt, ...);
void log_alert(char *host, const char *msgfmt, ...);
#define log_error log_alert
void logger(char *type, char *host, char *message); /* actually creates and delivers the log message */

/*** xdb utilities, only used by base_load'd extensions and only available when base_load is used :) ***/

/* ring for handling cached structures */
typedef struct xdbcache_struct
{
    instance i;
    int id;
    char *host;
    char *ns; /* for get */
    xmlnode data; /* for set */
    jid owner;
    int sent;
    int preblock;
    pth_cond_t *cond;
    struct xdbcache_struct *prev;
    struct xdbcache_struct *next;
} *xdbcache, _xdbcache;

xdbcache xdb_cache(instance i); /* create a new xdb cache for this instance */
xmlnode xdb_get(xdbcache xc, char *host, jid owner, char *ns); /* blocks until namespace is retrieved, host must map back to this service! returns xmlnode or NULL if failed */
int xdb_set(xdbcache xc, char *host, jid owner, char *ns, xmlnode data); /* sends new xml to replace old, returns non-zero if failure */

/* base_load initialization function definition */
typedef void (*base_load_init)(instance id, xmlnode x);

/* Error messages */
#define SERROR_NAMESPACE "<stream:error>Invalid namespace specified.</stream:error>"
#define SERROR_INVALIDHOST "<stream:error>Invalid hostname used.</stream:error>"

/* ------------------------------------
 * Managed Thread Queue (MTQ) utilities 
 *   used only by base_load'd extensions 
 *   and only available when base_load is 
 *   used.
 * ------------------------------------*/

/* default waiting threads */
#define MTQ_THREADS 10

/* mtq callback simple function definition */
typedef void (*mtq_callback)(void *arg);

/* has a pointer to the currently assigned thread for this queue */
typedef struct mtqueue_struct
{
    struct mth_struct *t;
    mtq_callback f;
    pth_msgport_t mp;
    int routed;
} *mtq, _mtq;

/* has the message port for the running thread, and the current queue it's processing */
typedef struct mth_struct
{
    mtq q;
    pth_msgport_t mp;
    pool p;
    pth_t id;
    int busy;
} *mth, _mth;

mtq mtq_new(pool p); /* creates a new queue, is automatically cleaned up when p frees */
void mtq_send(mtq q, pool p, mtq_callback f, void *arg); /* appends the arg to the queue to be run on a thread */

/* MIO */

/* struct to handle the write queue */
typedef enum { queue_XMLNODE, queue_CDATA } queue_type;
typedef struct mio_wb_q_st
{
    pth_message_t head;  /* for compatibility */
    pool p;
    queue_type type;
    xmlnode x;
    void *data;
    void *cur;
    int len;
    struct mio_wb_q_st *next;
} _mio_wbq,*mio_wbq;

/* the mio data type */

typedef enum { state_ACTIVE, state_CLOSE } mio_state;
typedef enum { type_LISTEN, type_NORMAL } mio_type;
typedef struct mio_st
{
    pool p;
    mio_type type;
    int rated;   /* is this socket rate limted? */
    jlimit rate; /* if so, what is the rate?    */
    mio_state state;
    xstream xs;
    int fd;
    mio_wbq queue; /* write buffer queue */
    struct mio_st *prev,*next;
    void *arg;    /* do not modify directly */
    void *cb;     /* do not modify directly */
    struct karma k;
    char *ip;
} *mio, _mio;

/* callback flags */
#define MIO_NEW    0
#define MIO_NORMAL 1
#define MIO_CLOSED 2
#define MIO_ERROR  3

/* i/o callback function definition */
typedef void (*mio_cb)(mio c,char *buffer,int bufsz,int flag,void *arg);

/* create a new mio object from a file descriptor */
mio mio_new(int fd, mio_cb cb, void *arg);

/* reset the callback and argument for an mio object */
mio mio_reset(mio m, mio_cb cb, void *arg);

/* request the mio socket be closed */
void mio_close(mio m);

/* writes an xmlnode to the socket */
void mio_write(mio m,xmlnode x, char *buffer, int len);

/* sets the karma values for a socket */
void mio_karma(mio m, int val, int max, int inc, int dec, int penalty, int restore);
void mio_karma2(mio m, struct karma *k);

/* sets connection based rate limits */
void mio_rate(mio m, int rate_time, int max_points);

/* pops the next xmlnode from the queue, or NULL if no more nodes */
xmlnode mio_cleanup(mio m);

/* connects to an ip */
mio mio_connect(char *host, int port, mio_cb cb, void *arg);

/* starts listening on a port/ip, returns NULL if failed to listen */
mio mio_listen(int port, char *sourceip, mio_cb cb, void *arg);
