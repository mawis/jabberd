/*
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 *
 *  users.c -- functions for manipulating data for logged in users
 *
 */

#include "jsm.h"

/*
 *  _js_users_del -- call-back for deleting user from the hash table
 *  
 *  This function is called periodically by the user data garbage collection
 *  thread. It removes users aren't logged in from the global hashtable.
 *
 *  parameters
 *  	arg -- not used
 *		key -- the users key in the hashtable, not used
 *      data -- the user data to check
 *
 *  returns
 *      1  
 */
int _js_users_del(void *arg, const void *key, void *data)
{
    HASHTABLE ht = (HASHTABLE)arg;
    udata u = (udata)data;	/* cast the pointer into udata */

    /*
     * if the reference count for this user's record
     * is positive, or if there are active sessions
     * we can't free it, so return immediately
     */
    if(u->ref > 0 || u->sessions != NULL)
        return 1;

    log_debug(ZONE,"freeing %s",u->user);

    ghash_remove(ht,u->user);

    /* free the data structures */
    ppdb_free(u->p_cache);
    /* XXX add back in rates! 
    rate_free(u->rate); */
    pool_free(u->p);

    return 1;
}


/* callback for walking the host hash tree */
int _js_hosts_del(void *arg, const void *key, void *data)
{
    HASHTABLE ht = (HASHTABLE)data;

    log_debug(ZONE,"checking users for host %s",(char*)key);

    ghash_walk(ht,_js_users_del,ht);

    return 1;
}

/*
 *  js_users_main -- entry point for user gc thread
 *  
 *  js_users_main is the main loop for a thread that
 *  flushes old users from memory.  
 *
 */
void *js_users_main(void *arg)
{
    jsmi si = (jsmi)arg;

    /* debug message */
    log_debug(ZONE,"THREAD:USERS starting");

    /* infinite loop */
    while(1)
    {
        /* XXX sleep for 5 seconds, config me and default higher */
        pth_sleep(5);

        /* free user struct if we can */
        ghash_walk(si->hosts,_js_hosts_del,NULL);
    }
}



/*
 *  js_user -- gets the udata record for a user
 *  
 *  js_user attempts to locate the user data record
 *  for the specifed id. First it looks in current list,
 *  if that fails, it looks in xdb and creates new list entry.
 *  If THAT fails, it returns NULL (not a user).
 */
udata js_user(jsmi si, jid id, HASHTABLE ht)
{
    pool p;
    udata cur, newu;
    char *ustr, *u;

    if(si == NULL || id == NULL || id->user == NULL) return NULL;

    /* get the host hash table if it wasn't provided */
    if(ht == NULL)
        ht = ghash_get(si->hosts,id->server);

    /* hrm, like, this isn't our user! */
    if(ht == NULL) return NULL;

    /* copy the user name and convert to lower case */
    for(ustr = u = strdup(id->user); *ustr != '\0'; ustr++)
        *ustr = tolower(*ustr);

    /* debug message */
    log_debug(ZONE,"js_user(%s,%X)",jid_full(id),ht);

    /* try to get the user data from the hash table */
    cur = ghash_get(ht,u);
    if(cur != NULL)
    {
        /* found it, free the search string and return the data */
        free(u);
        return cur;
    }

    /* debug message */
    log_debug(ZONE,"js_user not current");

    /* try to get the user auth data from xdb */
    if(!xdb_get(si->xc, id->server, id, NS_AUTH))
        return NULL;

    /* create a udata struct */
    p = pool_heap(64);
    newu = pmalloco(p, sizeof(_udata));
    newu->p = p;
    newu->si = si;
    newu->user = pstrdup(p, u);
    newu->id = jid_new(p,jid_full(id));
    jid_set(newu->id,NULL,JID_RESOURCE);
    free(u);

    /* got the user, add it to the user list */
    ghash_put(ht,newu->user,newu);
    log_debug(ZONE,"js_user debug %X %X",ghash_get(ht,newu->user),newu);

    return newu;
}

