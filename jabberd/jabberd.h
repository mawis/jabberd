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

/* ------------------------------------
/* Managed Thread Queue (MTQ) utilities 
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
} *mtq, _mtq;

/* has the message port for the running thread, and the current queue it's processing */
typedef struct mth_struct
{
    pth_msgport_t mp;
    mtq q;
    pool p;
} *mth, _mth;

mtq mtq_new(pool p); /* creates a new queue, is automatically cleaned up when p frees */
void mtq_send(mtq q, pool p, mtq_callback f, void *arg); /* appends the arg to the queue to be run on a thread */
