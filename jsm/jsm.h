#include "jabberd.h"

/* worker thread max waiting pool size */
#define SESSION_WAITERS 10

/* set to a prime number larger then the average max # of hosts, and another for the max # of users for any single host */
#define HOSTS_PRIME 5
#define USERS_PRIME 509

/* master event types */
typedef int event;
#define e_SESSION  0  /* when a session is starting up */
#define e_OFFLINE  1  /* data for an offline user */
#define e_SERVER   2  /* packets for the server.host */
#define e_DELIVER  3  /* about to deliver a packet to an mp */
#define e_SHUTDOWN 4  /* server is shutting down, last chance! */
#define e_AUTH     5  /* authentication handlers */
#define e_REGISTER 6  /* registration request */
/* always add new event types here, to maintain backwards binary compatibility */
#define e_LAST     7  /* flag for the highest */

/* session event types */
#define es_IN      0  /* for packets coming into the session */
#define es_OUT     1  /* for packets originating from the session */
#define es_END     2  /* when a session ends */
/* always add new event types here, to maintain backwards binary compatibility */
#define es_LAST    3  /* flag for the highest */


typedef enum {M_PASS,   /* we don't want this packet this tim */
              M_IGNORE, /* we don't want this packet ever */
              M_HANDLED /* stop mapi processing on this packet */
             } mreturn;

typedef struct udata_struct *udata, _udata;
typedef struct session_struct *session, _session;

typedef struct mapi_struct
{
    jsmi si;
    jpacket packet;
    event e;
    udata user;
    session s;
} *mapi, _mapi;

typedef mreturn (*mcall)(mapi m, void *arg);

typedef struct mlist_struct
{
    mcall c;
    void *arg;
    unsigned char mask;
    struct mlist_struct *next;
} *mlist, _mlist;

/* globals for this instance of jsm */
typedef struct jsmi_struct
{
    xmlnode config;
    HASHTABLE hosts;
    pth_msgport_t waiting[SESSION_WAITERS];
    pth_msgport_t mpoffline, mpserver;
    xdbcache xc;
    mlist events[e_LAST];
} *jsmi, _jsmi;

void js_xdb_register(xcall c, void *arg);
xmlnode js_xdb_get(udata user, char *ns);
void js_xdb_set(udata user, char *ns, xmlnode x);


struct udata_struct
{
    char *user;
    jid id;
    jsmi si;
    session sessions;
    int scount, ref;
    ppdb p_cache;
    rlimit rate;
    pool p;
    struct udata_struct *next;
};

xmlnode js_config(char *query);

udata js_user(char *user);
void js_users_exit(void);
void js_deliver(jpacket p);


typedef void (*session_onSend)(session s, jpacket p, void *arg);

struct session_struct
{
    /* general session data */
    jsmi si;
    char *res;
    jid id, uid;
    udata u;
    xmlnode presence;
    int priority, roster;
    int c_in, c_out;
    time_t started;

    /* mechanics */
    pool p;
    int exit_flag;
    mlist events[es_LAST];
    pth_msgport_t worker;

    /* send handler */
    session_onSend send;
    void *arg;

    struct session_struct *next;
};

session js_session_new(jid owner, session_onSend send, void *arg);
void *js_session_main(void *arg);
void js_session_end(session s, char *reason);
session js_session_get(udata user, char *res);
session js_session_primary(udata user);
void js_session_to(session s, jpacket p);
void js_session_from(session s, jpacket p);

void js_conn_connect(thread t, int sock, struct sockaddr_in sa);
void js_conn_negotiate(thread t, xmlnode in, int type);
xmlstream_onNode js_conn_namespace(command cmd, char *ns, xmlstream_onNode handler);

void *js_server_main(void *arg);
void *js_offline_main(void *arg);
void *js_unknown_main(void *arg);
void *js_users_main(void *arg);
void *js_debug_main(void *arg);

typedef struct {
    pth_message_t head; /* the standard pth message header */
    jpacket p;
} _jpq, *jpq;

void js_psend(pth_msgport_t mp, jpacket p); /* sends p to a pth message port */

void js_bounce(xmlnode x, terror terr); /* logic to bounce packets w/o looping, eats x and delivers error */

int js_config_name(command cmd, char *name);
xmlnode js_config_load(instance i); /* fetch/check the config file */
extern char *js__hostname; /* server name */
extern xmlnode js__config; /* loaded server config */

sreturn js_service_prescreen(jpacket p);
void js_mapi_register(mphase p, mcall c, void *arg);
void js_mapi_session(mphase p, session s, mcall c, void *arg);
int js_mapi_call(mphase phase, mlist l, jpacket packet, udata user, session s, int variant);



