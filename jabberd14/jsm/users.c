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
 * users.c -- functions for manipulating data for logged in users
 * 
 --------------------------------------------------------------------------*/

#include "jsm.h"

/**
 * @file users.c
 * @brief functions for manipulating data for logged in users
 *
 * Contains the garbage collector for user records we don't need in memory anymore and
 * the function to load user records to memory.
 */

/**
 * structure used to pass a hashtable and a counter to _js_users_del()
 */
typedef struct ht_count_struct {
    xht ht;		/**< hashtable containing the users of a host */
    int *count;		/**< reference to the counter for the number of online users */
} *ht_count, _ht_count;

/**
 * call-back for deleting user from the hash table
 *  
 * This function is called periodically by the user data garbage collection
 * thread. It removes users aren't logged in from the global hashtable.
 *
 * @param h the hash table containing the users of the presently cleaned host
 * @param key the user
 * @param data the user's data
 * @param arg structure holding the hashtable of hosts and the user counter
 */
void _js_users_del(xht h, const char *key, void *data, void *arg)
{
    ht_count htc = (ht_count)arg;
    udata u = (udata)data;	/* cast the pointer into udata */

    /*
     * if the reference count for this user's record
     * is positive, or if there are active sessions
     * we can't free it, so return immediately
     */
    if(u->ref > 0 || (u->sessions != NULL && ++*(htc->count)))
        return;

    log_debug2(ZONE, LOGT_SESSION, "freeing %s",u->user);

    xhash_zap(htc->ht,u->user);
    pool_free(u->p);
}


/**
 * xhash_walker callback for walking the host hash tree
 *
 * @param h the hash table containing all hosts
 * @param key the host for which the callback ist called
 * @param data the hashtable containing the users of this host
 * @param arg pointer to the user counter
 */
void _js_hosts_del(xht h, const char *key, void *data, void *arg)
{
    _ht_count htc;
    htc.ht = (xht)data;
    htc.count = (int*)arg;

    log_debug2(ZONE, LOGT_SESSION, "checking users for host %s",(char*)key);

    xhash_walk(htc.ht, _js_users_del, &htc);
}

/**
 *  js_users_gc is a heartbeat that flushes old users from memory.  
 *
 *  @param arg the session manager internal data
 *  @return always r_DONE
 */
result js_users_gc(void *arg)
{
    jsmi si = (jsmi)arg;

    /* free user struct if we can */
    int js__usercount = 0;
    xhash_walk(si->hosts,_js_hosts_del, &js__usercount);
    log_debug2(ZONE, LOGT_STATUS, "%d\ttotal users",js__usercount);
    return r_DONE;
}



/**
 *  get the udata record for a user
 *  
 *  js_user attempts to locate the user data record
 *  for the specifed id. First it looks in current list,
 *  if that fails, it looks in xdb and creates new list entry.
 *  If THAT fails, it returns NULL (not a user).
 *
 *  @param si the session manager instance data
 *  @param id which user to load
 *  @param ht the hash table for the host the user belongs to (may be NULL)
 *  @return the udata record for the user, NULL if no such user
 */
udata js_user(jsmi si, jid id, xht ht)
{
    pool p;
    udata cur, newu;
    char *ustr;
    xmlnode x, y;
    jid uid;

    if(si == NULL || id == NULL || id->user == NULL) return NULL;

    /* get the host hash table if it wasn't provided */
    if(ht == NULL)
        ht = xhash_get(si->hosts,id->server);

    /* hrm, like, this isn't our user! */
    if(ht == NULL) return NULL;

    /* copy the id and convert user to lower case (if not done by libidn) */
    uid = jid_new(id->p, jid_full(jid_user(id)));
#ifndef LIBIDN
    for(ustr = uid->user; *ustr != '\0'; ustr++)
        *ustr = tolower(*ustr);
#endif

    /* debug message */
    log_debug2(ZONE, LOGT_SESSION, "js_user(%s,%X)",jid_full(uid),ht);

    /* try to get the user data from the hash table */
    if((cur = xhash_get(ht,uid->user)) != NULL)
        return cur;

    /* debug message */
    log_debug2(ZONE, LOGT_SESSION, "## js_user not current ##");

    /* try to get the user auth data from xdb */
    x = xdb_get(si->xc, uid, NS_AUTH);

    /* try to get hashed user auth data from xdb, if there was no plain data */
    y = (x == NULL) ? xdb_get(si->xc, uid, NS_AUTH_CRYPT) : NULL;

    /* does the user exist? */
    if (x == NULL && y == NULL)
	return NULL;

    /* create a udata struct */
    p = pool_heap(64);
    newu = pmalloco(p, sizeof(_udata));
    newu->p = p;
    newu->si = si;
    newu->user = pstrdup(p, uid->user);
    newu->pass = x ? pstrdup(p, xmlnode_get_data(x)) : NULL;
    newu->id = jid_new(p,jid_full(uid));
    if (x)
	xmlnode_free(x);
    if (y)
	xmlnode_free(y);


    /* got the user, add it to the user list */
    xhash_put(ht,newu->user,newu);
    log_debug2(ZONE, LOGT_SESSION, "js_user debug %X %X",xhash_get(ht,newu->user),newu);

    return newu;
}

