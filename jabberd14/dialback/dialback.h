/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include <jabberd.h>

/* s2s instance */
typedef struct db_struct
{
    instance i;
    HASHTABLE nscache; /* host/ip local resolution cache */
    HASHTABLE out_connecting; /* where unvalidated in-progress connections are, key is to/from */
    HASHTABLE out_ok_db; /* hash table of all connected dialback hosts, key is same to/from */
    HASHTABLE out_ok_legacy; /* hash table of all connected legacy hosts, key is same to/from */
    HASHTABLE in_id; /* all the incoming connections waiting to be checked, rand id attrib is key */
    HASHTABLE in_ok_db; /* all the incoming dialback connections that are ok, ID@to/from is key  */
    HASHTABLE in_ok_legacy; /* all the incoming legacy connections that are ok, ID@to is key */
    char *secret; /* our dialback secret */
    int legacy; /* flag to allow old servers */
    int timeout_packets;
    int timeout_idle;
} *db, _db;

/* wrap an mio and track the idle time of it */
typedef struct miod_struct
{
    mio m;
    int last, count;
    db d;
} *miod, _miod;

void dialback_out_packet(db d, xmlnode x, char *ip);
result dialback_out_beat_packets(void *arg);

void dialback_in_read(mio s, int flags, void *arg, xmlnode x);
void dialback_in_verify(db d, xmlnode x);

char *dialback_randstr(void);
char *dialback_merlin(pool p, char *secret, char *to, char *challenge);
void dialback_miod_hash(miod md, HASHTABLE ht, jid key);
miod dialback_miod_new(db d, mio m);
void dialback_miod_write(miod md, xmlnode x);
void dialback_miod_read(miod md, xmlnode x);
char *dialback_ip_get(db d, jid host, char *ip);
void dialback_ip_set(db d, jid host, char *ip);
