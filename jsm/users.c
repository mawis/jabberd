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

/* global hash table of logged in users */
HASHTABLE js__users = NULL;

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
    udata u = (udata)data;	/* cast the pointer into udata */
    xdb curd;				/* persisent storage structure for user data */

    /*
     * if the reference count for this user's record
     * is positive, or if there are active sessions
     * we can't free it, so return immediately
     */
    if(u->ref > 0 || u->sessions != NULL)
        return 1;

    /* FIXME: duplicate debug message */
    fprintf(stderr,"[%s]",u->user);
    log_debug(ZONE,"freeing %s",u->user);

    /* free the xdb cache associated with this user */
    for(curd = u->x_cache; curd != NULL; curd = curd->next)
        xmlnode_free(curd->data);

    /* remove the udata record from the hash table */
    ghash_remove(js__users,u->user);

    /* free the data structures */
    ppdb_free(u->p_cache);
    rate_free(u->rate);
    pool_free(u->p);

    return 1;
}

/*
 *  js_users_main -- entry point for user gc thread
 *  
 *  js_users_main is the main loop for a thread that
 *  flushes old users from memory.  
 *
 *  parameters
 *  	arg -- not used
 *
 */
void *js_users_main(void *arg)
{
    int flag = 0; /* controls the dumping of memory stats every 30 seconds or so */

    /* if there's no global hashtable of users, create one */
    if(js__users == NULL)
        js__users = ghash_create(HASH_PRIME,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);

    /* debug message */
    log_debug(ZONE,"THREAD:USERS starting");

    /* infinite loop */
    while(1)
    {
        /* sleep for 5 seconds */
        pth_sleep(5);

        /* free user struct if we can */
        ghash_walk(js__users,_js_users_del,NULL);

        /* if we have debug pools compiled */
        if(flag++ > 5)
        {
            pool_stat(1);
            flag = 0;
        }else{
            pool_stat(0);
        }
    }
}



/*
 *  js_user -- gets the udata record for a user
 *  
 *  js_user attempts to locate the user data record
 *  for the specifed username. First it looks in current list,
 *  if that fails, it looks in xdb and creates new list entry.
 *  If THAT fails, it returns NULL (not a user).
 *
 *  parameters
 *  	user -- the user name to search for
 *
 *  returns
 *      a udata pointer if the user data is found 
 *      NULL if user isn't user
 */
udata js_user(char *user)
{
    pool p;
    udata cur, newu;
    char *ustr, *u;

    /* if no user is specified, skip the search */
    if(user == NULL) return NULL;

    /* if there's no user list yet, create one */
    if(js__users == NULL)
        js__users = ghash_create(HASH_PRIME,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);

    /* copy the user name and convert to lower case */
    for(ustr = u = strdup(user); *ustr != '\0'; ustr++)
        *ustr = tolower(*ustr);

    /* debug message */
    log_debug(ZONE,"js_user(%s)",u);

    /* try to get the user data from the hash table */
    cur = ghash_get(js__users,u);
    if(cur != NULL)
    {
        /* found it, free the search string and return the data */
        free(u);
        return cur;
    }

    /* debug message */
    log_debug(ZONE,"js_user not current");

    /* create a udata struct */
    p = pool_heap(64);
    newu = pmalloc(p, sizeof(_udata));
    memset(newu, '\0', sizeof(_udata));
    newu->p = p;
    newu->user = pstrdup(p, u);
    free(u);

    /* try to get the data from xdb */
    if(!js_xdb_get(newu, NS_AUTH))
    {
        /* no password, no user! */
        pool_free(newu->p);
        return NULL;
    }

    /* got the user, add it to the user list */
    ghash_put(js__users,newu->user,newu);

    /* return it to the caller */
    return newu;

}

/*
 *  _js_users_exit -- shut down a session
 *  
 *  This internal function gets called once for each user in 
 *  js__users when the server shuts down. It calls js_session_end()
 *  to end the session gracefully.
 *
 *  parameters
 *  	arg -- not used
 *      key -- not used 
 *      data - the user data 
 *      
 *  returns
 *      1 
 */
int _js_users_exit(void *arg, const void *key, void *data)
{
    udata u = (udata)data;	/* cast the data pointer to udata */
    session s;				/* the session to shut down */

    /* shut down all sessions for this user */
    for(s = u->sessions; s != NULL; s = s->next)
        js_session_end(s, "Server Exiting");

    return 1;
}

/*
 *  js_users_exit -- shut down all user sessions
 *  
 *  This just calls the walk function on the global user
 *  hash table so _js_users_exit() gets called for each user
 *
 */
void js_users_exit(void)
{
    /* tell all the sessions to exit */
    ghash_walk(js__users,_js_users_exit,NULL);
}

