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

#include "jsm.h"

/**
 * @file users.cc
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

    log_debug2(ZONE, LOGT_SESSION, "freeing %s", u->id->user);

    xhash_zap(htc->ht, key);
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

#ifdef POOL_DEBUG
class js_pool_debug_stats {
    private:
	int hosts;

	int users;
	size_t users_pool_sum;
	size_t biggest_user_pool;
	std::string biggest_user;

	int sessions;
	size_t sessions_pool_sum;
	size_t biggest_session_pool;
	std::string biggest_session;

	void updateSession(session s);
    public:
	js_pool_debug_stats();
	void hostUpdate();
	void updateUser(udata user);
	std::string getSummary();
};

js_pool_debug_stats::js_pool_debug_stats() : hosts(0), users(0), users_pool_sum(0), biggest_user_pool(0), sessions(0), sessions_pool_sum(0), biggest_session_pool(0) {
}

void js_pool_debug_stats::hostUpdate() {
    hosts++;
}

void js_pool_debug_stats::updateSession(session s) {
    sessions++;

    size_t session_pool_size = pool_size(s->p);

    sessions_pool_sum += session_pool_size;

    if (session_pool_size > biggest_session_pool) {
	biggest_session_pool = session_pool_size;
	biggest_session = jid_full(s->id);
    }
}

void js_pool_debug_stats::updateUser(udata user) {
    users++;

    size_t user_pool_size = pool_size(user->p);

    users_pool_sum += user_pool_size;

    if (user_pool_size > biggest_user_pool) {
	biggest_user_pool = user_pool_size;
	biggest_user = jid_full(user->id);
    }

    session iter = user->sessions;
    while (iter != NULL) {
	updateSession(iter);
	iter = iter->next;
    }
}

std::string js_pool_debug_stats::getSummary() {
    std::ostringstream result;

    result << "hosts: " << hosts << " / users: " << users << " " << users_pool_sum << " / biggest user: " << biggest_user << " " << biggest_user_pool;
    result << " / sessions: " << sessions << " " << sessions_pool_sum << " / biggest session: " << biggest_session << " " << biggest_session_pool;

    return result.str();
}

static void js_users_pool_debug_walk(xht hash, const char* key, void* value, void* arg) {
    js_pool_debug_stats* stats = static_cast<js_pool_debug_stats*>(arg);
    udata user = static_cast<udata>(value);

    // sanity check
    if (stats == NULL || user == NULL) {
	return;
    }

    stats->updateUser(user);
}

static void js_hosts_pool_debug_walk(xht hash, const char* key, void* value, void* arg) {
    js_pool_debug_stats* stats = static_cast<js_pool_debug_stats*>(arg);
    xht users = static_cast<xht>(value);

    // sanity check
    if (stats == NULL || users == NULL) {
	return;
    }

    stats->hostUpdate();

    xhash_walk(users, js_users_pool_debug_walk, stats);
}
#endif

/**
 *  js_users_gc is a heartbeat that flushes old users from memory.  
 *
 *  @param arg the session manager internal data
 *  @return always r_DONE
 */
result js_users_gc(void *arg) {
    jsmi si = (jsmi)arg;

    /* free user struct if we can */
    int js__usercount = 0;
    xhash_walk(si->hosts,_js_hosts_del, &js__usercount);
    log_debug2(ZONE, LOGT_STATUS, "%d\ttotal users",js__usercount);

#ifdef POOL_DEBUG
    js_pool_debug_stats* stats = new js_pool_debug_stats;
    xhash_walk(si->hosts, js_hosts_pool_debug_walk, stats);
    static char own_pid[32] = "";
    if (own_pid[0] == '\0') {
        snprintf(own_pid, sizeof(own_pid), "%i jsm_pool_debug", getpid());
    }
    log_notice(own_pid, "%s", stats->getSummary().c_str());
    delete stats;
#endif

    return r_DONE;
}


void js_user_free_aux_data(void *arg) {
    xht aux_data = (xht)arg;

    if (aux_data == NULL)
	return;

    xhash_free(aux_data);
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
 *  @param id which user to load (some memory is allocated from this jid's pool)
 *  @param ht the hash table for the host the user belongs to (may be NULL)
 *  @return the udata record for the user, NULL if no such user
 */
udata js_user(jsmi si, jid id, xht ht) {
    pool p;
    udata cur, newu;
    char *ustr;
    xmlnode x, y;
    jid uid;

    if (si == NULL || id == NULL || id->user == NULL)
	return NULL;

    /* get the host hash table if it wasn't provided */
    if (ht == NULL)
        ht = static_cast<xht>(xhash_get(si->hosts,id->server));

    /* hrm, like, this isn't our user! */
    if (ht == NULL)
	return NULL;

    /* copy the id and convert user to lower case (if not done by libidn) */
    uid = jid_new(id->p, jid_full(jid_user(id)));
#ifndef LIBIDN
    for (ustr = uid->user; *ustr != '\0'; ustr++)
        *ustr = tolower(*ustr);
#endif

    /* debug message */
    log_debug2(ZONE, LOGT_SESSION, "js_user(%s,%X)",jid_full(uid),ht);

    /* try to get the user data from the hash table */
    if ((cur = static_cast<udata>(xhash_get(ht,uid->user))) != NULL)
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
    newu = static_cast<udata>(pmalloco(p, sizeof(_udata)));
    newu->p = p;
    newu->si = si;
    newu->aux_data = xhash_new(17);
    pool_cleanup(p, js_user_free_aux_data, newu->aux_data);
    newu->id = jid_new(p,jid_full(uid));
    if (x)
	xmlnode_free(x);
    if (y)
	xmlnode_free(y);


    /* got the user, add it to the user list */
    xhash_put(ht, newu->id->user, newu);
    log_debug2(ZONE, LOGT_SESSION, "js_user debug %X %X", xhash_get(ht, newu->id->user), newu);

    return newu;
}

/**
 * inform registered modules of a newly created user
 *
 * @param si the session manager instance
 * @param id the jid of the new user
 * @return 1 if the call was handled by a module, 0 if not
 */
int js_user_create(jsmi si, jid id) {
    udata u = js_user(si, id, NULL); /* XXX: flag it as unconditional */
    if (u != NULL) {
	return js_mapi_call(si, e_CREATE, NULL, u, NULL);
    }

    return 0;
}

/**
 * inform registered modules of a deleted user
 *
 * @param si the session manager instance
 * @param id the jid of the deleted user
 * @return 1 if the call was handled by a module, 0 if not
 */
int js_user_delete(jsmi si, jid id) {
    udata u = js_user(si, id, NULL);
    if (u != NULL) {
	return js_mapi_call(si, e_DELETE, NULL, u, NULL);
    }

    return 0;
}
