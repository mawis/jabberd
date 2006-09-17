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

/**
 * @file dialback.h
 * @brief header for the dialback implementation
 */

/**
 * @dir dialback
 * @brief implementation of the server to server connection manager
 *
 * The dialback directory contains the module, that implements server to server (s2s)
 * connections.
 */

#include <jabberd.h>

#ifdef __cplusplus
extern "C" {
#endif

/** s2s instance */
typedef struct db_struct
{
    instance i;		/**< data jabberd hold for each instance */
    xht nscache;	/**< host/ip local resolution cache */
    xht out_connecting;	/**< where unvalidated in-progress connections are, key is to/from */
    xht out_ok_db;	/**< hash table of all connected dialback hosts, key is same to/from */
    xht in_id;		/**< all the incoming connections waiting to be checked, rand id attrib is key */
    xht in_ok_db;	/**< all the incoming dialback connections that are ok, ID@to/from is key */
    xht hosts_xmpp;	/**< hash containing the XMPP version configuration for peers */
    xht hosts_tls;	/**< hash containing the STARTTLS configuration for peers */
    xht hosts_auth;	/**< hash containing the authentiction configuration for peers */
    char *secret;	/**< our dialback secret */
    int timeout_packets;/**< configuration option <queuetimeout/> */
    int timeout_idle;	/**< configuration option <idletimeout/> */
    xht std_ns_prefixes;/**< standard prefixes used inside the dialback component for xpath expressions */
    xdbcache xc;	/**< pointer to the ::xdbcache_cache structure used to access the ACL and configuration */
} *db, _db;

/** wrap an mio and track the idle time of it */
typedef struct miod_struct
{
    mio m;		/**< the mio connection */
    int last;		/**< last time this connection has been used */
    int count;		/**< number of sent stanzas on the connection */
    db d;		/**< the dialback instance */
} *miod, _miod;

void dialback_out_packet(db d, xmlnode x, char *ip);
result dialback_out_beat_packets(void *arg);

void dialback_in_read(mio s, int flags, void *arg, xmlnode x);
void dialback_in_verify(db d, xmlnode x);

int dialback_check_settings(db d, mio m, const char *server, int is_outgoing, int auth_type, int version);
char *dialback_randstr(void);
char *dialback_merlin(pool p, char *secret, char *to, char *challenge);
void dialback_miod_hash(miod md, xht ht, jid key);
miod dialback_miod_new(db d, mio m);
void dialback_miod_write(miod md, xmlnode x);
void dialback_miod_read(miod md, xmlnode x);
char *dialback_ip_get(db d, jid host, char *ip);
void dialback_ip_set(db d, jid host, char *ip);

/** simple queue for out_queue */
typedef struct dboq_struct
{
    int stamp;
    xmlnode x;
    struct dboq_struct *next;
} *dboq, _dboq;

/**
 * enumeration of dialback request states an outgoing connection can have
 */
typedef enum {
    not_requested,	/**< there was no packet yet, for that we want to request doing dialback (just sending db:verifys), and we could not yet send them  */
    could_request,	/**< there was no packet yet, that requested doing dialback, but we could send out dialback requests */
    want_request,	/**< we want to send a dialback request */
    sent_request	/**< we did sent a dialback request */
} db_request;

/**
 * enumeration of connection establishment states an outgoing connection can have
 *
 * used for more detailed logging of failed connections
 */
typedef enum {
    created,		/**< outgoing connection request created, but not yet started to connect */
    connecting,		/**< we started to connect, but have no connection yet */
    connected,		/**< we have connected to the other host */
    got_streamroot,	/**< we got the stream root of the other server */
    waiting_features,	/**< we are waiting for the stream features on a XMPP1.0 connection */
    got_features,	/**< we got the stream features on a XMPP1.0 connection */
    sent_db_request,	/**< we sent out a dialback request */
    db_succeeded,	/**< we had success with our dialback request */
    db_failed,		/**< dialback failed */
    sasl_started,	/**< we started to authenticate using sasl */
    sasl_fail,		/**< there was a failure in using sasl */
    sasl_success	/**< we successfully used sasl */
} db_connection_state;

/* for connecting db sockets */
/**
 * structure holding information about an outgoing connection
 */
typedef struct {
    char *ip;	/**< where to connect to (list of comma separated addresses of the format [ip]:port, [ip], ip:port, or ip) */
    int stamp;	/**< when we started to connect to this peer */
    db d;	/**< our dialback instance */
    jid key;	/**< destination and source for this connection, format: dest/src */
    xmlnode verifies; /**< waiting db:verify elements we have to send to the peer */
    pool p;	/**< memory pool we are using for this connections data */
    dboq q;	/**< pending stanzas, that need to be sent to the peer */
    mio m;	/**< the mio connection this outgoing stream is using */
    		/* original comment: for that short time when we're connected and open, but haven't auth'd ourselves yet */
    int xmpp_version; /**< version the peer supports, -1 not yet known, 0 preXMPP */
    int settings_failed; /**< 1 if the connection has been droped as configured settings where not fulfilled (e.g. TLS required), 0 else */
    char *stream_id; /**< the stream id the connected entity assigned */
    db_request db_state; /**< if we want to send a <db:result/> and if we already did */
    db_connection_state connection_state; /**< how far did we proceed in connecting to the other host */
    spool connect_results; /**< result messages for the connection attempts */
    struct {
	int db:1;	/**< if the peer supports dialback */
    } flags;
} *dboc, _dboc;

#ifdef __cplusplus
}
#endif
