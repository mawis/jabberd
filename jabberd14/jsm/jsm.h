#include <jabber/jabber.h>

#define HASH_PRIME 509 /* set to a prime number larger then the average max # of users, for the master hash */

#define MAPI_VARAUTH -10
#define MAPI_VARREGISTER -11

typedef enum {C_SET, 
              C_GET, 
              C_DEL, 
              C_CHECK, 
              C_INIT
             } command;

typedef enum {S_BOUNCE, 
              S_IGNORE, 
              S_AUTHED
             } sreturn;

typedef enum {P_SESSION, /* sent when a session is starting up */
              P_UNKNOWN, /* packets jserver doesn't know to handle */
              P_OFFLINE, /* data for an offline user?? */
              P_SERVER,  /* packets for the server.host */
              P_DELIVER, /* about to deliver a packet to an mp */
              P_SHUTDOWN,/* server is shutting down, last chance! */ 
              PS_IN,     /* for packets coming into the session */
              PS_OUT,    /* for packets originating from the session */
              PS_END     /* when a session ends */
             } mphase;

typedef enum {M_PASS,   /* we don't want this packet this tim */
              M_IGNORE, /* we don't want this packet ever */ 
              M_HANDLED /* stop mapi processing on this packet */
             } mreturn;

typedef struct udata_struct *udata, _udata;
typedef struct session_struct *session, _session;

typedef struct mapi_struct
{
    jpacket packet;
    mphase phase;
    udata user;
    session s;
    int variant;
} *mapi, _mapi;

typedef mreturn (*mcall)(mapi m, void *arg);

typedef struct mlist_struct
{
    mcall c;
    void *arg;
    unsigned char mask;
    struct mlist_struct *next;
} *mlist, _mlist;

/* contains a list of module function pointers */
typedef struct mapi_master
{
    mphase p;
    mlist l;
    struct mapi_master *next;
} *mmaster, _mmaster;

mmaster js_mapi_master(mphase p);

typedef struct xdb_struct
{
    char *ns;
    xmlnode data;
    int cache;
    struct xdb_struct *next;
} *xdb, _xdb;

typedef int (*xcall)(int set, xdb x, udata u, void *arg);

/* contains a list of xdb handler function pointers */
typedef struct xlist_struct
{
    xcall c;
    void *arg;
    struct xlist_struct *next;
} *xlist, _xlist;

/* worker thread max waiting pool size */
#define SESSION_WAITERS 10

/* globals for this instance of jsm */
typedef struct jsmi_struct
{
    xmlnode config;
    HASHTABLE hosts;
    pth_msgport_t waiting[SESSION_WAITERS];
    /* hold the lists of registrations here */
} *jsmi, _jsmi;

void js_xdb_register(xcall c, void *arg);
xmlnode js_xdb_get(udata user, char *ns);
void js_xdb_set(udata user, char *ns, xmlnode x);


struct udata_struct
{
    char *user;
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
    mlist m_in, m_out, m_end;
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

void js_static(void);


