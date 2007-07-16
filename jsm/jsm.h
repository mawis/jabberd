/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

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
 * plugged into this base JSM component. (The modules can be found inside the directory
 * @link jsm/modules jsm/modules.@endlink)
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
 *
 * If a stanza is routed to the JSM and received by js_packet(), it is first checked
 * which type of stanza it is. Different actions are taken for &lt;route/&gt; stanzas
 * than for other stanzas (&lt;message/&gt;, &lt;iq/&gt;, or &lt;presence/&gt;). Inside the
 * &lt;route/&gt; elements there are stanzas forwarded by a component to the JSM. Normally
 * this are elements received from the client by the @link pthsock client connection manager@endlink and
 * forwarded to the session manager. They are wrapped inside this forwarding stanza,
 * to ensure that each stanza of a user is send through the user's session manager
 * and not to the recepient directly. Also there are special &lt;route/&gt; stanzas
 * used to establish sessions (supporting two types of session establishment
 * protocols: the traditional jabberd14 protocol (see http://svn.jabberd.org/trunk/jadc2s/PROTO)
 * as well es a new protocol introduced by jabberd2
 * (see http://jabberd.jabberstudio.org/dev/docs/component.shtml)). The other stanzas are stanzas
 * normally received from an other session manager (either local or remote in which case the
 * stanzas already passed the @link dialback dialback@endlink component) or a gateway/transport.
 *
 * The normal, non-&lt;route/&gt;d stanzas are processed the following way (starting processing
 * in js_deliver_local()):
 * All modules registered for the #e_DELIVER event are called. If one of the called modules
 * returned #M_HANDLED, the stanza is considered to be processed and no further actions are taken.
 * If non of the modules handled the packet, the further processing is different for the following
 * types of stanzas: Stanzas addressed just to the server domain or the domain and a resource, but
 * no user; stanzas addressed to an existing user address for a user that is; stanzas
 * addressed to an existing user address, but the user is not online or the stanza is addressed
 * to a specified resource of the user and there is no session for this resource; and stanzas
 * addressed to non-existing users.
 *
 * Stanzas for non-existing users are just bounced with #XTERROR_NOTFOUND, no further events
 * are generated.
 *
 * Stanzas for offline users and resources that are not online at present generate an
 * #e_OFFLINE event. If one of the modules registered for this event returns #M_HANDLED, the
 * stanzas is considered handled and not further processed. If no module returned #M_HANDLED,
 * the stanza is bounced using #XTERROR_RECIPIENTUNAVAIL.
 * 
 * Stanzas for online users (and stanzas addressed to an explicit resource, that is currently
 * online) generate an #es_IN event. If one of the modules handling the #es_IN event
 * returned #M_HANDLED, the stanza is considered to be processed and no further actions
 * are taken for this stanza. If no module returned #M_HANDLED, the session manager
 * delivers the stanza to the client, by wrapping the stanza inside a &lt;route/&gt; stanza
 * and sending the packet to the responsible client connection manager. While stanzas for
 * online users are processed, it is checked before and after the #es_IN event, if the
 * session is still existing and not marked as being shut down. If it is marked as being
 * shut down, the packet is reprocessed starting with the #e_DELIVER process as described
 * above.
 *
 * Stanzas addressed to the server (no user part in the Jabber ID) generate an #e_SERVER
 * event. Again the stanza is considered to be handled, if one of the modules, that
 * registered for this event, returned #M_HANDLED, or else it is bounced with #XTERROR_NOTFOUND.
 *
 * The processing for &lt;route/&gt;ed stanzas is as the following: It is first checked
 * if is a session control packet. Session control packets are processed by the following
 * functions: _js_routed_session_packet(), _js_routed_auth_packet(), and _js_routed_error_packet()
 * for the traditional jabberd14 session control protocol; and by _js_routed_session_control_packet()
 * for stanzas for the jabberd2 compatible session control protocol.
 *
 * All session control packets share the same set of events: #e_SESSION is called, when a
 * new session is created (in case of the traditional protocol, the session is not yet
 * authenticated!); #es_END is called, when a session is closed (a user logs out);
 * #e_REGISTER is called, for processing registration requests; #e_CREATE
 * is called if a user successfully registered for an account; #e_DELETE is called if an
 * account is being destroyed; #e_AUTH is an event only called for the traditional protocol,
 * when a packet arrives, that contain stanzas from a user, that is just authenticating
 * (for the jabberd2 compatible protocol it is the task of the client connection manager
 * to authenticate the user, therefore the session manager never gets stanzas while the
 * user is not yet authenticated).
 *
 * Normal &lt;route/&gt;d stanzas are processed by js_session_from(), which first checks
 * if the from address is a valid address of this user and is present at all. Afterwards
 * the #es_OUT event is called. If one of the modules registered for this event returned
 * #M_HANDLED, the processing of the stanza is stopped. Else the stanza is considered to
 * be okay and will just be delivered to the address, it is sent to by a call to
 * js_deliver().
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

/**
 * e_SESSION is a mapi event, that is fired when a new session is created. The new
 * session might just be created, but not yet authenticated by the user.
 *
 * The called module gets passed the ::udata_struct structure of the user and the ::session_struct
 * structure of the user. No ::jpacket_struct (stanza) is passed to the module.
 */
#define e_SESSION  0

/**
 * e_OFFLINE is a mapi event, that is fired for an incoming stanza for a user, that
 * is currently not online (or that is addressed to a resource, for which there is
 * no active session).
 *
 * The called module gets passed the ::jpacket_struct (stanza) and the ::udata_struct (user data),
 * but gets passed no ::session_struct as there is no such session.
 */
#define e_OFFLINE  1

/**
 * e_SERVER is a mapi event, that is fired for an incoming stanza, that is addressed
 * to a Jabber ID, that does not contain a node (user part), but just a domain and
 * optionally a resource. In the session manager of jabberd14, these packets are
 * considered to be addressed to the server.
 *
 * The called module gets passed the ::jpacket_struct (stanza), but no ::session_struct (as
 * there are no sessions for such addresses). If the stanza is sent by a local user,
 * the ::udata_struct of the sending user is passed to the module (this is a preformance
 * hack, the module should not rely on this fact and expect to get NULL passed for local
 * users as well).
 */
#define e_SERVER   2

/**
 * e_DELIVER is the first mapi event, that is fired on stanzas received for an address
 * handled by the session manager. It is called for all incoming stanzas before the session
 * manager calls the different events #e_SERVER, #e_OFFLINE, or #es_IN. If the stanza is
 * #M_HANDLED by on of the modules registered for this event, the session manager will even
 * not call one of these three other events.
 *
 * The called module gets passed the ::jpacket_struct (stanza). If the packet is addressed
 * to an existing user, the user's ::udata_struct is passed. If the stanza is for a
 * valid session, the ::session_struct is passed as well.
 *
 * The event is called in any case, even if the stanza is addressed to a non-existant
 * user.
 */
#define e_DELIVER  3

/**
 * e_SHUTDOWN is the mapi event, that should be called if the session manager is shutting
 * down.
 *
 * The called module gets passed nothing (NULL) as the stanza, user, and session.
 *
 * This event is disabled at present (since just before the release of version 1.4.4)
 * as we have problems with the memory management else. We have to free memory in the
 * right order, which is not guarantied the way it is impelemented at present.
 * To not get a software crash at shutdown, we just don't free the memory we needed all
 * the time at present. This is not really a problem, it just makes memory profilers
 * unhappy as we do not free all memory before exiting the process.
 */
#define e_SHUTDOWN 4

/**
 * e_AUTH is the mapi event, that is used for processing jabber:iq:auth packets while
 * the user did not yet authenticate. This processing is only done by the session
 * manager for sessions using the traditional session control protocol of jabberd14.
 * The jabberd2 compatible session control protocol implies that the authentication
 * is already done by the client connection manager (or another component that
 * starts the session).
 *
 * This event is called for get requests as well as for set requests. Inside handling of get
 * requests, the modules have to add their fields into the passed stanza and have
 * to return #M_PASS to let other modules add their fields as well. Inside handling of set
 * requests, the modules have to try to authenticate the user. If the module handled the
 * authentication (either by accepting or denying the authentication), it has to return
 * #M_HANDLED, else it has to return #M_PASS. If no module registered for this event
 * authenticated the set request, the session manager will deny the authentication
 * request itself.
 *
 * The registered module is passed the ::jpacket_struct (stanza) as well as the
 * ::udata_struct (user data). No ::session_struct is passed to the module.
 *
 * After this event returns, the session manager will return the content of the
 * packet. Therefore do not free the packet, and use jutil_error_xmpp() to
 * generate error replies instead of the normal js_bounce_xmpp().
 */
#define e_AUTH     5

/**
 * e_REGISTER is the mapi event, that is used for processing jabber:iq:register packets
 * in case there is no session yet. Therefore it is used to process new user
 * registration requests.
 *
 * Only the stanza is passed as ::jpacket_struct. No session and no user is passed to
 * a handler registered for this event.
 *
 * After this event returns, the session manager will return the content of the
 * packet. Therefore do not free the packet, and use jutil_error_xmpp() to
 * generate error replies instead of the normal js_bounce_xmpp().
 */
#define e_REGISTER 6

/**
 * e_CREATE is the mapi event, that is fired if a new user has just been created.
 *
 * Only the ::udata_struct of the new user is passed to the handler registered for
 * this event. Nothing is passed as the ::jpacket_struct nor as the ::session_struct.
 *
 * Do not be surprised, that there are no modules registering for this event at
 * present. The event has been introduced as the jabberd2 compatible session control
 * protocol has such an event, and it might be useful in the future. (The event is
 * fired for users that have been created by the traditional session control
 * protocol as well.)
 */
#define e_CREATE   7

/**
 * e_DELETE is the mapi event, that is fired if a user gets deleted.
 *
 * This event can be used by modules to register handlers, that remove state, that
 * has been kept for this user. This might be cancling subscritions of the user
 * as well as just deleting the user's data stored in xdb.
 *
 * The handler is passed the user's ::udata_struct. Nothing is passed as the
 * ::session_struct nor as the ::jpacket__struct.
 */
#define e_DELETE   8

/**
 * e_DESERIALIZE is the mapi event, that is fired if the session manager wants
 * the module to deserialize its data about a session
 *
 * The handler gets passed the ::udata_struct of the session owning user, the
 * ::session_struct for the session, that is deserialized. No
 * stanza is passed in ::jpacket_struct.
 *
 * As all es_ events, the e_DESERIALIZE event has to be registered for a session using
 * the js_mapi_session() call.
 */
#define e_DESERIALIZE 9

/**
 * e_PRE_REGISTER is called in the same situation as the e_REGISTER event, but
 * called before. If the event gets handled by any module, no e_REGISTER event
 * is generated. This can be used to cancel registration requests, i.e. to
 * check a request and deny it if provided data is not acceptable.
 *
 * Only the stanza is passed as ::jpacket_struct. No session and no user is passed to
 * a handler registered for this event.
 *
 * After this event returns, the session manager will return the content of the
 * packet. Therefore do not free the packet, and use jutil_error_xmpp() to
 * generate error replies instead of the normal js_bounce_xmpp().
 */
#define e_PRE_REGISTER 10

 /**
  * e_PASSWORDCHANGE is called when a user changes his password, or the first password
  * is set on registration of an account. Modules can register this event to change
  * stored credentials.
  *
  * A fictive stanza is passed as ::jpacket_struct containing the following XML
  * data:
  *
  * &lt;query xmlns='jabber:iq:auth' to='user\@server'>
  * &lt;password>newpass&lt;/password>
  * &lt/query>
  */
#define e_PASSWORDCHANGE 11

/**
 * e_FILTER_IN is called for incoming stanzas, that are handled by a session.
 * It is used to filter stanzas before they are delivered to the e_OFFLINE
 * event.
 *
 * The called module gets passed the ::jpacket_struct (stanza) and the ::udata_struct (user data),
 * but gets passed no ::session_struct as there is no such session.
 */
#define e_FILTER_IN 12

/**
 * e_FILTER_OUT is called for outgoing stanzas, that are not sent by a specific
 * session of a user. It is used to filter stanzas before they are sent out.
 *
 * The called module gets passed the ::jpacket_struct (stanza) and the ::udata_struct (user data)
 * of the sending user, but gets passed no ::session_struct.
 */
#define e_FILTER_OUT 13

/**
 * e_ROSTERCHANGE is called when the roster of a user has changed.
 *
 * The called module gets passed the ::jpacket_struct containing the updated item inside a
 * iq[\@type='set']/roster:query, the ::udata_struct (user data) of the user owning the
 * roster, but gets passed no ::session_struct.
 */
#define e_ROSTERCHANGE 14

/* always add new event types here, to maintain backwards binary compatibility */
#define e_LAST     15  /**< flag for the highest event type*/

/* session event types */

/**
 * es_IN is the mapi event, that is fired for stanzas that are received from
 * other entities on the Jabber network for a local user. (INcoming stanzas from
 * the user's view.)
 *
 * The handler is passed the ::udata_struct of the destination user, the
 * ::jpacket_struct containing the stanza, and the ::session_struct for the
 * correct user's session.
 *
 * As all es_ events, the es_IN event has to be registered for a session using
 * the js_mapi_session() call.
 */
#define es_IN      0

/**
 * es_OUT is the mapi event, that is fired for stanzas, that are received from
 * a user (forwarded by the client connection manager). (OUTgoing stanzas from
 * the user's view.)
 *
 * The handler gets passed the ::udata_struct of the sending user, the
 * ::jpacket_struct containing the stanza, and the ::session_struct for the
 * session, that is sending this packet.
 *
 * As all es_ events, the es_IN event has to be registered for a session using
 * the js_mapi_session() call.
 */
#define es_OUT     1

/**
 * es_END is the mapi event, that is fired if a session ends.
 *
 * The handler gets passed the ::udata_struct of the user, that is logged out; and
 * the ::session_struct for the session that is closed. No stanza is passed in
 * ::jpacket_struct.
 *
 * As all es_ events, the es_IN event has to be registered for a session using
 * the js_mapi_session() call.
 */
#define es_END     2

/**
 * es_SERIALIZE is the mapi event, that is fired if the session manager wants
 * the module to serialize its data about a session
 *
 * The handler gets passed the ::udata_struct of the session owning user, the
 * ::session_struct for the session, that is serialized. No
 * stanza is passed in ::jpacket_struct.
 *
 * As all es_ events, the es_SERIALIZE event has to be registered for a session using
 * the js_mapi_session() call.
 */
#define es_SERIALIZE 3

/**
 * es_FILTER_IN is the mapi event, that is fired for incoming messages, that
 * will get delivered to a session afterwards
 *
 * If the es_FILTER_IN handlers are all PASSing, the event is then sent to the
 * es_IN event queue.
 *
 * The handler is passed the ::udata_struct of the destination user, the
 * ::jpacket_struct containing the stanza, and the ::session_struct for the
 * correct user's session.
 *
 * As all es_ events, the es_IN event has to be registered for a session using
 * the js_mapi_session() call.
 */
#define es_FILTER_IN 4

/**
 * es_FILTER_OUT is the mapi event, that is fired for outgoing messages, send
 * by a user's session
 *
 * If the es_FILTER_OUT handlers are all PASSing, the packet is sent out.
 * If one handler returns M_HANDLED, the packet is not further processed.
 *
 * The handler gets passed the ::udata_struct of the sending user, the
 * ::jpacket_struct containing the stanza, and the ::session_struct for the
 * sending user's session.
 *
 * As all es_ events, the es_FILTER_OUT event has to be registered for a session
 * using the js_mapi_session() call.
 */
#define es_FILTER_OUT 5

/* always add new event types here, to maintain backwards binary compatibility */
#define es_LAST    6  /**< flag for the highest session event type */

/* admin user account flags */
#define ADMIN_MOTD	"motd"		/**< admin right to set/update/delete the message of the day */
#define ADMIN_LISTSESSIONS "listsessions"	/**< admin right to see online users */
#define ADMIN_ADMINMSG	"adminmsg"	/**< admin right to receive messages to admin address */
#define ADMIN_SHOWPRES	"showpres"	/**< request presence and last info for any user */

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
    xmlnode serialization_node; /**< xmlnode for a session for es_SERIALIZE and es_DESERIALIZE events */
    jpacket additional_result; /**< modules can create a result, that will be returned after all modules are called. Useful for co-generating a result */
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
    /* xmlnode config; */
    xht hosts;			/**< hash with hosts as keys and hashtables (key: user, value: udata_struct) as values */
    xht sc_sessions;		/**< hash containing pointers to the udata_struct for sessions initiated by the session control protocol */
    xht std_namespace_prefixes;	/**< standard prefixes used for xmlnode_get_tags() */
    xdbcache xc;		/**< xdbcache used to query xdb */
    mlist events[e_LAST];	/**< list of registered modules for the existing event types */
    pool p;			/**< memory pool for the instance */
    struct history_storage_conf history_sent; /**< store history for messages sent by the user? */
    struct history_storage_conf history_recv; /**< store history for messages received by the user? */
    char *statefile;		/**< to which file to store serialization data */
    char *auth;			/**< forward authentication request to this component, if not NULL */
};

/** User data structure/list. See js_user(). */
struct udata_struct
{
    jid id;                    /**< the user's JID */
    jid utrust;                /**< list of JIDs the user trusts to send presence to (s10n==both or from). Do not access directly, use js_trustees() instead. */
    jid useen;		/**< list of JIDs a user wants to accept presences from (s10n==both or to). Do not access directly, use js_seen_users() instead. */
    jsmi si;                   /**< the session manager instance the user is associated with */
    session sessions;          /**< the user's session */
    int ref;                   /**< reference counter */
    pool p;
    xht aux_data;		/**< additional data stored by modules */
};

xmlnode js_config(jsmi si, const char* query, const char* lang);

udata js_user(jsmi si, jid id, xht ht);
int js_user_create(jsmi si, jid id);
int js_user_delete(jsmi si, jid id);
void js_deliver(jsmi si, jpacket p, session sending_s);


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

    xht aux_data;	/**< hash where modules can store additional data for a session (data stored in this hash has to be freed by the module */

    struct session_struct *next; /**< pointer to the next list element of sessions, NULL for the last entry */
};

/** this value is set as a flag to a jpacket, for a message that has been read from offline storage */
#define PACKET_FROM_OFFLINE_MAGIC 1768189505

/** this value is set as a flag to a jpacket for a subscription state change, that should be sent out in any case */
#define PACKET_FORCE_SENT_MAGIC 1836017748

/** this value is set as a flag to a jpacket for a locally generated error stanza to pass privacy lists */
#define PACKET_PASS_FILTERS_MAGIC 20060704

session js_session_new(jsmi si, dpacket p);
session js_sc_session_new(jsmi si, dpacket p, xmlnode sc_session);
void js_session_end(session s, const char *reason);
session js_session_get(udata user, char *res);
session js_session_primary(udata user);
void js_session_to(session s, jpacket p);
void js_session_from(session s, jpacket p);
void js_session_free_aux_data(void* arg);

void js_server_main(void *arg);
void js_offline_main(void *arg);
result js_users_gc(void *arg);

/** structure used to pass a session manager instance and a packet using only one pointer */
typedef struct jpq_struct {
    jsmi si;		/**< pointer to the session manager instance internal data */
    jpacket p;		/**< the packet */
} _jpq, *jpq;

void js_psend(jsmi si, jpacket p, mtq_callback f); /* sends p to a function */

void js_bounce_xmpp(jsmi si, session s, xmlnode x, xterror xterr); /* logic to bounce packets w/o looping, eats x and delivers error */

void js_mapi_register(jsmi si, event e, mcall c, void *arg);
void js_mapi_session(event e, session s, mcall c, void *arg);
int js_mapi_call(jsmi si, event e, jpacket packet, udata user, session s);
int js_mapi_call2(jsmi si, event e, jpacket packet, udata user, session s, xmlnode serialization_node);
void js_mapi_create_additional_iq_result(mapi m, const char* name, const char *prefix, const char *ns_iri);

void js_authreg(void *arg);

/* we have acl.c now
int js_admin(udata u, int flag);
*/

result js_packet(instance i, dpacket p, void *arg);
int js_islocal(jsmi si, jid id);
int js_trust(udata u, jid id); /* checks if id is trusted by user u */
jid js_trustees(udata u); /* returns list of trusted jids */
jid js_seen_jids(udata u); /* returns list of trusted jids */
void js_remove_trustee(udata u, jid id); /* removes a user from the list of trustees */
int js_seen(udata u, jid id); /* checks if a ID is seen by user u */
void js_remove_seen(udata u, jid id); /* removes a user from the list of seen JIDs */
int js_online(mapi m); /* logic to tell if this is a go-online call */

void jsm_shutdown(void *arg);

void jsm_serialize(jsmi si);
void jsm_deserialize(jsmi si, const char *host);
