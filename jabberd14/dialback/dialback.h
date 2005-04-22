/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
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

/** s2s instance */
typedef struct db_struct
{
    instance i;		/**< data jabberd hold for each instance */
    xht nscache;	/**< host/ip local resolution cache */
    xht out_connecting;	/**< where unvalidated in-progress connections are, key is to/from */
    xht out_ok_db;	/**< hash table of all connected dialback hosts, key is same to/from */
    xht in_id;		/**< all the incoming connections waiting to be checked, rand id attrib is key */
    xht in_ok_db;	/**< all the incoming dialback connections that are ok, ID@to/from is key */
    xht hosts_xmpp;	/**< hash containing the hosts where no XMPP support should be advertized */
    xht hosts_tls;	/**< hash containing the hosts where STARTTLS should not be tried or is required */
    char *secret;	/**< our dialback secret */
    int timeout_packets;/**< configuration option <queuetimeout/> */
    int timeout_idle;	/**< configuration option <idletimeout/> */
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

char *dialback_randstr(void);
char *dialback_merlin(pool p, char *secret, char *to, char *challenge);
void dialback_miod_hash(miod md, xht ht, jid key);
miod dialback_miod_new(db d, mio m);
void dialback_miod_write(miod md, xmlnode x);
void dialback_miod_read(miod md, xmlnode x);
char *dialback_ip_get(db d, jid host, char *ip);
void dialback_ip_set(db d, jid host, char *ip);
