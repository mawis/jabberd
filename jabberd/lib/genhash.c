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

#include "lib.h"

/*** stubs that hook back to new xhash */

HASHTABLE ghash_create(int buckets, KEYHASHFUNC hash, KEYCOMPAREFUNC cmp)
{
    return xhash_new(buckets);
}

HASHTABLE ghash_create_pool(pool p, int buckets, KEYHASHFUNC hash, KEYCOMPAREFUNC cmp)
{
    xht h = xhash_new(buckets);
    pool_cleanup(p, (pool_cleaner)xhash_free, h);
    return h;
}

void ghash_destroy(HASHTABLE tbl)
{
    xhash_free(tbl);
}

void *ghash_get(HASHTABLE tbl, const void *key)
{
    return xhash_get(tbl, key);
}

int ghash_put(HASHTABLE tbl, const void *key, void *value)
{
    xhash_put(tbl, key, value);
    return 1;
}

int ghash_remove(HASHTABLE tbl, const void *key)
{
    xhash_zap(tbl, key);
    return 1;
}


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

