#include <jabber/jabber.h>
#include <pth.h>

/* packet types */
typedef enum { p_NONE, p_NORM, p_XDB, p_LOG } ptype;

/* ordering types */
typedef enum { o_FIRST, o_ANY, o_LAST } order;

/* result types */
typedef enum { r_PASS, r_ERR, r_OK } result;

typedef struct idnode_struct *idnode, _idnode;

/* packet wrapper, d as in delivery or daemon, whichever pleases you */
typedef struct dpacket_struct
{
    char *host;
    jid id;
    ptype type;
    pool p;
    xmlnode x;
    result flag_best; /* the best result type for this packet, to know if it was actually handled */
    int flag_used; /* number of idnodes that have handled it */
} *dpacket, _dpacket;

/* delivery handler function callback definition */
typedef result (*hdgene)(idnode id, dpacket p, void *arg);

/* delivery handler list */
typedef struct handel_struct
{
    hdgene f;
    void *arg;
    order o; /* for sorting new handlers as they're inserted */
    struct handel_struct *next;
} *handel, _handel;

/* wrapper around top-level config file sections */
struct idnode_struct
{
    char *id;
    pool p;
    xmlnode x;
    ptype type;
    handel hds;
    int flag_used;
};

/* config file handler function callback definition */
typedef result (*cfgene)(idnode id, xmlnode x, void *arg);


/*** public functions for base modules ***/
void cfreg(char *node, cfgene f, void *arg); /* register a function to handle that node in the config file */
void hdreg(idnode id, order o, hdgene f, void *arg); /* register a function to handle delivery for this idnode */
void idreg(idnode id, char *host); /* associate an id with a hostname for that packet type */
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
