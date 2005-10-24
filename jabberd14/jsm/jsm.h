/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * --------------------------------------------------------------------------*/
#include "jabberd.h"

/**
 * @dir jsm
 * @brief Contains the Jabber session manager, that is extended by modules contained in jsm/modules
 *
 * The Jabber session manager (JSM) is the component of jabberd14, that handles the visible
 * part of transporting and storing messages, and managing presence and presence subscriptions.
 * It implements the bussiness logic of the instant messaging and presence handling.
 *
 * The JSM component itself is devided into two parts: The base JSM component and modules
 * plugged into this base JSM component.
 *
 * The base JSM component (implemented inside this directory) has as less bussiness logic
 * as possible. Its main task is to manage lists of event subscriptions and to call all
 * registered event handlers if an event gets triggered. Events can either be triggered
 * by incoming stanzas, or may be triggered inside the handling of other events.
 *
 * Which modules have to be loaded is configured inside the jabberd14 configuration file.
 * The configured modules are loaded on startof of the JSM component by calling
 * a function named like the XML element, that was used inside the load element in the
 * configuration file. This function than have to initialize the module and register
 * for the callbacks, the module wants to handle.
 *
 * The events are devided into two categories. The two category of events differ on
 * if they are bound to a specific session of a user or not. Events bound to a session
 * of a user are prefixed by "es_" while the other event names are prefixed just by "e_".
 * Typically a module registers for the es_ events inside the #e_SESSION event, that
 * is called when a new session starts up.
 *
 * The events are defined inside the file jsm.h. The events not bound to a specific
 * session are: #e_SESSION, #e_OFFLINE, #e_SERVER, #e_DELIVER, #e_SHUTDOWN, #e_AUTH,
 * #e_REGISTER, #e_CREATE, and #e_DELETE. The events bound to a specific session are:
 * #es_IN, #es_OUT, and #es_END.
 *
 * When this component is started by a call of jsm(), it initializes internal data,
 * registers the function js_packet() to get called by the @link jabberd XML router@endlink
 * for packets addressed to the domain(s) that this session manager instance handles,
 * and registers the function js_users_gc() to get called periodically.
 */

/**
 * @file jsm.h
 * @brief definition of the jsm API
 */

/** worker thread max waiting pool size */
#define SESSION_WAITERS 10

#define HOSTS_PRIME 17	/**< set to a prime number larger then the average max # of hosts */
#define USERS_PRIME 3001 /**<set to a prime number larger then the average max # of users */

/** master event types */
typedef int event;
#define e_SESSION  0  /**< event type: when a session is starting up */
#define e_OFFLINE  1  /**< event type: data for an offline user */
#define e_SERVER   2  /**< event type: packets for the server.host */
#define e_DELIVER  3  /**< event type: about to deliver a packet to an mp */
#define e_SHUTDOWN 4  /**< event type: server is shutting down, last chance! */
#define e_AUTH     5  /**< event type: authentication handlers */
#define e_REGISTER 6  /**< event type: registration request */
#define e_CREATE   7  /**< event type: create a user */
#define e_DELETE   8  /**< event type: delete a user (remove data stored by the module for this user) */
/* always add new event types here, to maintain backwards binary compatibility */
#define e_LAST     9  /**< flag for the highest event type*/

/* session event types */
#define es_IN      0  /**< session event type: for packets coming into the session */
#define es_OUT     1  /**< session event type: for packets originating from the session (packets we just received from our own client) */
#define es_END     2  /**< session event type: when a session ends */
/* always add new event types here, to maintain backwards binary compatibility */
#define es_LAST    3  /**< flag for the highest session event type */

/* admin user account flags */
#define ADMIN_UNKNOWN   0x00	/**< it has not yet checked if the user is an admin */
#define ADMIN_NONE      0x01	/**< the user has no admin rights */
#define ADMIN_READ      0x02	/**< the user has read admin rights */
#define ADMIN_WRITE     0x04	/**< the user has write admin rights */

/** return codes for mapi callback calls */
typedef enum {
    M_PASS,   /**< we don't want this packet this time */
    M_IGNORE, /**< we don't want packets of this stanza type ever */
    M_HANDLED /**< stop mapi processing on this packet */
} mreturn;

typedef struct udata_struct *udata,	/**< pointer to a udata_struct */
	_udata;				/**< a udata_struct */
typedef struct session_struct *session,	/**< pointer to a session_struct */
	_session;			/**< a session_struct */
typedef struct jsmi_struct *jsmi,	/**< pointer to a jsmi_struct */
	_jsmi;				/**< a jsmi_struct */

/** structure that hold information passed to module calls */
typedef struct mapi_struct {
    jsmi si;		/**< instance internal data of the session manager calling the module */
    jpacket packet;	/**< the packet that should be processed by the module */
    event e;		/**< the event that is processed */
    udata user;		/**< the user this event is related to (if any) */
    session s;		/**< the session this event is realted to (if any) */
} *mapi, _mapi;

/** prototype of a callback function to register with the MAPI */
typedef mreturn (*mcall)(mapi m, void *arg);

/** structure to build the list of registered callback functions */
typedef struct mlist_struct
{
    mcall c;			/**< function to call */
    void *arg;			/**< argument to pass to the function */
    unsigned char mask;		/**< bitmask with packet-types the function requested to ignore (JPACKET_* constants) */
    struct mlist_struct *next;	/**< pointer to the next entry, NULL for last entry */
} *mlist, _mlist;

/** configuration options for storing message history in xdb */
struct history_storage_conf {
    int general:1;		/**< enable storing history at all */
    int offline:1;		/**< store messages, that came from offline storage already? */
    int special:1;		/**< store special messages? JPACKET__HEADLINE, JPACKET__GROUPCHAT, JPACKET_ERROR */
};

/** Globals for this instance of jsm (Jabber Session Manager) */
struct jsmi_struct {
    instance i;			/**< jabberd's instance data for the jsm component */
    xmlnode config;		/**< jsm configuration */
    xht hosts;			/**< hash with hosts as keys and hashtables (key: user, value: udata_struct) as values */
    xht sc_sessions;		/**< hash containing pointers to the udata_struct for sessions initiated by the session control protocol */
    xdbcache xc;		/**< xdbcache used to query xdb */
    mlist events[e_LAST];	/**< list of registered modules for the existing event types */
    pool p;			/**< memory pool for the instance */
    jid gtrust;			/**< "global trusted jids": jids allowed to see all presences */
    struct history_storage_conf history_sent; /**< store history for messages sent by the user? */
    struct history_storage_conf history_recv; /**< store history for messages received by the user? */
};

/** User data structure/list. See js_user(). */
struct udata_struct
{
    char *user;                /**< the user's name */
    char *pass;                /**< the user's password */
    jid id;                    /**< the user's JID */
    jid utrust;                /**< list of JIDs the user trusts to send presence to (s10n==both or from). Do not access directly, use js_trustees() instead. */
    jsmi si;                   /**< the session manager instance the user is associated with */
    session sessions;          /**< the user's session */
    int scount;                /**< the number of sessions associated to this user (w/ different JID ressource parts) */
    int ref;                   /**< reference counter */
    int admin;                 /**< 1 if the user is configured to be an admin. Do not access directly, use js_admin() instead. */
    pool p;
    struct udata_struct *next;
};

xmlnode js_config(jsmi si, char *query);

udata js_user(jsmi si, jid id, xht ht);
int js_user_create(jsmi si, jid id);
int js_user_delete(jsmi si, jid id);
void js_deliver(jsmi si, jpacket p);


/** structure that holds the data for a single session of a user */
struct session_struct {
    /* general session data */
    jsmi si;			/**< pointer to instance internal data of the session manager */
    char *res;			/**< the resource of this session */
    jid id;			/**< JabberID of the user who owns this session */
    udata u;			/**< user data structure of the user */
    xmlnode presence;		/**< the current global presence of this session */
    int priority;		/**< the current priority of this session */
    int roster;
    int c_in;			/**< counter for packets received for a client */
    int c_out;			/**< counter for packets received from a client */
    time_t started;		/**< when the session has been started */

    /* mechanics */
    pool p;			/**< memory pool for this session */
    int exit_flag;		/**< flag that a session has ended and should not be used anymore */
    mlist events[es_LAST];	/**< lists for the callbacks that have registered for the events of this session */
    mtq q;			/**< thread queue */

    /* our routed id, and remote session id */
    jid route;		/**< our id to send packets to c2s for this session */
    jid sid;		/**< the id of the c2s 'user' that handles this session */
    char *sc_c2s;	/**< the identifier for the session on c2s if session control protocol is used */
    char *sc_sm;	/**< the identifier for the session on the session manager if session control protocol is used */

    struct session_struct *next; /**< pointer to the next list element of sessions, NULL for the last entry */
};

/** this value is set as a flag to a jpacket, for a message that has been read from offline storage */
#define PACKET_FROM_OFFLINE_MAGIC 1768189505

/** this value is set as a flag to a jpacket for a subscription state change, that should be sent out in any case */
#define PACKET_FORCE_SENT_MAGIC 1836017748

session js_session_new(jsmi si, dpacket p);
session js_sc_session_new(jsmi si, dpacket p, xmlnode sc_session);
void js_session_end(session s, char *reason);
session js_session_get(udata user, char *res);
session js_session_primary(udata user);
void js_session_to(session s, jpacket p);
void js_session_from(session s, jpacket p);

void js_server_main(void *arg);
void js_offline_main(void *arg);
result js_users_gc(void *arg);

/** structure used to pass a session manager instance and a packet using only one pointer */
typedef struct jpq_struct {
    jsmi si;		/**< pointer to the session manager instance internal data */
    jpacket p;		/**< the packet */
} _jpq, *jpq;

void js_psend(jsmi si, jpacket p, mtq_callback f); /* sends p to a function */

#ifdef INCLUDE_LEGACY
void js_bounce(jsmi si, xmlnode x, terror terr); /* logic to bounce packets w/o looping, eats x and delivers error */
#endif
void js_bounce_xmpp(jsmi si, xmlnode x, xterror xterr); /* logic to bounce packets w/o looping, eats x and delivers error */

void js_mapi_register(jsmi si, event e, mcall c, void *arg);
void js_mapi_session(event e, session s, mcall c, void *arg);
int js_mapi_call(jsmi si, event e, jpacket packet, udata user, session s);

void js_authreg(void *arg);

int js_admin(udata u, int flag);

result js_packet(instance i, dpacket p, void *arg);
int js_islocal(jsmi si, jid id);
int js_trust(udata u, jid id); /* checks if id is trusted by user u */
jid js_trustees(udata u); /* returns list of trusted jids */
int js_online(mapi m); /* logic to tell if this is a go-online call */

void jsm_shutdown(void *arg);
