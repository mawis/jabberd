/*
 * Copyrights
 *
 * Copyright (c) 2008 Matthias Wimmer
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

/**
 * @file jid.cc
 * @brief compatibility functions for old JID handling
 */

#include <jid.hh>

static void jid_pool_cleaner(void *arg) {
    jid id = static_cast<jid>(arg);

    delete id;
}

/**
 * create a new jid
 */
jid jid_new(pool p, const char *idstr) {
    // sanity check
    if (!p || !idstr)
        return NULL;

    try {
        jid id = new xmppd::jabberid_pool(idstr, p);
        pool_cleanup(p, jid_pool_cleaner, id);
        return id;
    } catch (std::invalid_argument&) {
        return NULL;
    }
}

/**
 * set part of a jabberid
 */
void jid_set(jid id, const char *str, int item) {
    // sanity check
    if (!str || !id)
        return;

    try {
        switch (item) {
            case JID_RESOURCE:
                id->set_resource(str);
                break;
            case JID_USER:
                id->set_node(str);
                break;
            case JID_SERVER:
                id->set_domain(str);
                break;
        }
    } catch (std::invalid_argument&) {
    }
}

char *jid_full(jid id) {
    if (!id)
        return NULL;

    return id->full_pooled();
}

int jid_cmp(jid a, jid b) {
    if (!a || !b)
        return -1;

    return (*a) == (*b) ? 0 : -1;
}

int jid_cmpx(jid a, jid b, int parts) {
    if (!a || !b)
        return -1;

    return a->compare(*b, parts & JID_RESOURCE, parts & JID_USER,
                      parts & JID_SERVER)
               ? 0
               : -1;
}

/**
 * Returns the same jid but without the resource.
 *
 * Returns the jid, if it does not contain a resource, else a new jid is
 * created.
 *
 * If memory needs to be allocated, the given memory pool is used.
 *
 * @param a the original jid
 * @param p the memory pool to use
 * @return the jid without the resource
 */
jid jid_user_pool(jid a, pool p) {
    // sanity check
    if (!a || !p)
        return NULL;

    return jid_new(p, a->get_user().full().c_str());
}

jid jid_user(jid a) { return jid_user_pool(a, a->get_pool()); }

jid jid_append(jid a, jid b) {
    if (!a)
        return NULL;
    if (!b)
        return a;

    jid next = a;
    while (next) {
        if (jid_cmp(next, b) == 0)
            break;
        if (next->next == NULL) {
            next->next = jid_new(a->get_pool(), jid_full(b));
            return a;
        }
        next = next->next;
    }
    return a;
}
