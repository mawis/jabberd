#include <jabber/jabber.h>
#include <pth.h>

/* packet types */
typedef enum { p_NONE, p_NORM, p_XDB, p_LOG } ptype;

/* ordering types */
typedef enum { o_FIRST, o_ANY, o_LAST } order;

/* result types */
typedef enum { r_PASS, r_ERR, r_OK } result;

typedef struct instance_struct *instance, _instance;

/* packet wrapper, d as in delivery or daemon, whichever pleases you */
typedef struct dpacket_struct
{
    char *host;
    jid id;
    ptype type;
    pool p;
    xmlnode x;
    result flag_best; /* the best result type for this packet, to know if it was actually handled */
    int flag_used; /* number of instances that have handled it */
} *dpacket, _dpacket;

/* delivery handler function callback definition */
typedef result (*phandler)(instance id, dpacket p, void *arg);

/* delivery handler list */
typedef struct handel_struct
{
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


/*** public functions for base modules ***/
void register_config(char *node, cfhandler f, void *arg); /* register a function to handle that node in the config file */
void register_phandler(instance id, order o, phandler f, void *arg); /* register a function to handle delivery for this instance */
void register_instance(instance id, char *host); /* associate an id with a hostname for that packet type */
dpacket dpacket_new(xmlnode x); /* create a new delivery packet from source xml */

/*** global logging symbols ***/
extern int debug_flag;
void debug_log(char *zone, const char *msgfmt, ...);
#define log_debug if(debug_flag) debug_log
void log_notice(char *host, const char *msgfmt, ...);
void log_warn(char *host, const char *msgfmt, ...);
void log_alert(char *host, const char *msgfmt, ...);
#define log_error log_alert
void logger(char *type, char *host, char *message); /* actually creates and delivers the log message */

/*** internal functions ***/
int configurator(char *cfgfile);
void loader(void);
int configo(int exec);

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
int xdb_set(xdbcache xc, char *host, jid owner, xmlnode data); /* sends new xml to replace old, returns non-zero if failure */

/* base_load initialization function definition */
typedef void (*base_load_init)(instance id, xmlnode x);

