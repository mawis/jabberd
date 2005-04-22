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

#include <jabberdlib.h>

/**
 * @file genhash.c
 * @brief stubs that hook back to new xhash - DEPRECATED
 *
 * These functions are not used by jabberd14 anymore. Not sure if there
 * is still something that uses these functions and we might removed them
 * from jabberd14's code some. Do not use them! Use the xhash functions
 * instead.
 *
 * @deprecated use xhash instead!
 */

#ifdef INCLUDE_LEGACY

/**
 * create a 'ghash'
 *
 * @param buckets initial size of the hash table
 * @param hash ignored
 * @param cmp ignored
 * @return the new hash table
 */
HASHTABLE ghash_create(int buckets, KEYHASHFUNC hash, KEYCOMPAREFUNC cmp)
{
    return xhash_new(buckets);
}

/**
 * create a ghash that is freed if the pool is freed
 *
 * @param p the memory pool used
 * @param buckets the initial size of the hash table
 * @param hash unused/ignored
 * @param cmp unused/ignored
 * @return the new hash table
 */
HASHTABLE ghash_create_pool(pool p, int buckets, KEYHASHFUNC hash, KEYCOMPAREFUNC cmp)
{
    xht h = xhash_new(buckets);
    pool_cleanup(p, (pool_cleaner)xhash_free, h);
    return h;
}

/**
 * destroy a hash table
 *
 * @param tbl the hash table that should be destroyed
 */
void ghash_destroy(HASHTABLE tbl)
{
    xhash_free(tbl);
}

/**
 * get a value from a hash table
 *
 * @param tbl the hash table
 * @param key the key for which we want to know the value
 * @return the value
 */
void *ghash_get(HASHTABLE tbl, const void *key)
{
    return xhash_get(tbl, key);
}

/**
 * put a value into a hash table, eventually overwriting the old value
 *
 * @param tbl the hash table
 * @param key the key in the hash table
 * @param value the new value
 * @return always 1
 */
int ghash_put(HASHTABLE tbl, const void *key, void *value)
{
    xhash_put(tbl, key, value);
    return 1;
}

/**
 * remove a value from a hash table
 *
 * @param tbl the hash table
 * @param key the key we want to remove
 * @return always 1
 */
int ghash_remove(HASHTABLE tbl, const void *key)
{
    xhash_zap(tbl, key);
    return 1;
}

/**
 * walk through all values in a hash table
 *
 * @param tbl the hash table
 * @param func the function that should be called for each value
 * @param user_data pointer passed to the callback function
 * @return always 1
 */
int ghash_walk(HASHTABLE tbl, TABLEWALKFUNC func, void *user_data)
{
    int i;
    xhn n;
    xht h = (xht)tbl;

    for(i = 0; i < h->prime; i++)
        for(n = &h->zen[i]; n != NULL; n = n->next)
            if(n->key != NULL && n->val != NULL)
                (*func)(user_data, n->key, n->val);

    return 1;
}


int _xhasher(const char *key);
int str_hash_code(const char *s)
{
    return _xhasher(s);
}

#endif
