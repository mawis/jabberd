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

#ifdef __cplusplus
}
#endif
