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
