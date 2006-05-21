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
 * --------------------------------------------------------------------------*/

#include "util.h"


/* Generates a hash code for a string.
 * This function uses the ELF hashing algorithm as reprinted in 
 * Andrew Binstock, "Hashing Rehashed," Dr. Dobb's Journal, April 1996.
 */
int _xhasher(const char *s, int len)
{
    /* ELF hash uses unsigned chars and unsigned arithmetic for portability */
    const unsigned char *name = (const unsigned char *)s;
    unsigned long h = 0, g;
    int i;

    for(i=0;i<len;i++)
    { /* do some fancy bitwanking on the string */
        h = (h << 4) + (unsigned long)(name[i]);
        if ((g = (h & 0xF0000000UL))!=0)
            h ^= (g >> 24);
        h &= ~g;

    }

    return (int)h;
}


xhn _xhash_node_new(xht h, int index)
{
    xhn n;
    int i = index % h->prime;

    /* track total */
    h->count++;

    /* get existing empty one */
    for(n = h->zen[i]; n != NULL; n = n->next)
        if(n->key == NULL)	/* should not happen anymore, we are now removing unused nodes */
            return n;

    /* overflowing, new one! */
    n = malloc(sizeof(_xhn));	/* XXX dangerous not to use a memory pool, but current pools don't allow to free memory! */
    bzero(n, sizeof(_xhn));
    n->next = h->zen[i];
    h->zen[i] = n;
    return n;
}


xhn _xhash_node_get(xht h, const char *key, int index)
{
    xhn n;
    int i = index % h->prime;
    for(n = h->zen[i]; n != NULL; n = n->next)
        if(n->key != NULL && strcmp(key, n->key) == 0)
            return n;
    return NULL;
}

/**
 * removes a single entry in an xhash (xhash_walker function)
 *
 * @param hash the hash to remove the entry from
 * @param key the key to remove
 * @param value ignored
 * @param arg ignored
 */
static void _xhash_cleaner_walk(xht hash, const char *key, void *value, void *arg) {
    if (hash == NULL || key == NULL)
	return;

    xhash_zap(hash, key);
}

/**
 * removes all entries in an xhash
 *
 * used as a pool_cleaner() function
 *
 * @param arg the xhash to clean
 */
static void _xhash_cleaner(void *arg) {
    xht h = (xht)arg;

    /* sanity check */
    if (h == NULL)
	return;

    xhash_walk(h, _xhash_cleaner_walk, NULL);
}


xht xhash_new(int prime)
{
    xht xnew;
    pool p;

/*    log_debug(ZONE,"creating new hash table of size %d",prime); */

    p = pool_heap(sizeof(_xhn)*prime + sizeof(_xht));
    xnew = pmalloco(p, sizeof(_xht));
    xnew->prime = prime;
    xnew->p = p;
    xnew->zen = pmalloco(p, sizeof(xhn)*prime); /* array of xhn size of prime */
    pool_cleanup(p, _xhash_cleaner, (void*)xnew);
    return xnew;
}


void xhash_put(xht h, const char *key, void *val)
{
    int index;
    xhn n;
    int klen;

    if(h == NULL || key == NULL)
        return;

    klen = strlen(key);
    index = _xhasher(key,klen);

    /* dirty the xht */
    h->dirty++;

    /* if existing key, replace it */
    if((n = _xhash_node_get(h, key, index)) != NULL)
    {
/*        log_debug(ZONE,"replacing %s with new val %X",key,val); */

        n->key = key;
        n->val = val;
        return;
    }

/*    log_debug(ZONE,"saving %s val %X",key,val); */

    /* new node */
    n = _xhash_node_new(h, index);
    n->key = key;
    n->val = val;
}


void *xhash_getx(xht h, const char *key, int len)
{
    xhn n;

    if(h == NULL || key == NULL || len <= 0 || (n = _xhash_node_get(h, key, _xhasher(key,len))) == NULL)
    {
/*        log_debug(ZONE,"failed lookup of %s",key); */
        return NULL;
    }

/*    log_debug(ZONE,"found %s returning %X",key,n->val); */
    return n->val;
}

void *xhash_get(xht h, const char *key)
{
    if(h == NULL || key == NULL) return NULL;
    return xhash_getx(h,key,strlen(key));
}

void xhash_zap(xht h, const char *key)
{
    xhn n = NULL;
    xhn previous_node = NULL;
    int klen = 0;
    int index = 0;

    if(h == NULL || key == NULL || (klen = strlen(key)) == 0)
        return;

    index = _xhasher(key, klen) % h->prime;

    for (n = h->zen[index]; n != NULL; n = n->next) {
        if (n->key != NULL && strcmp(key, n->key) == 0) {
            /* found entry */

            /* update count and dirty of the hash */
            h->dirty++;
            h->count--;

            /* remove entry */
            if (previous_node == NULL) {
                /* first entry for this index */
                h->zen[index] = n->next;
            } else {
                previous_node->next = n->next;
            }
            free(n);

            /* entry removed, we can return */
            return;
        }

        previous_node = n;
    }
}


void xhash_free(xht h)
{
/*    log_debug(ZONE,"hash free %X",h); */

    if(h != NULL)
        pool_free(h->p);
}

void xhash_walk(xht h, xhash_walker w, void *arg)
{
    int i;
    xhn n;
    xhn next;

    if(h == NULL || w == NULL)
        return;

/*    log_debug(ZONE,"walking %X",h); */

    for(i = 0; i < h->prime; i++) {
        for(n = h->zen[i]; n != NULL; n = next) {
	    next = n->next; /* n might get freed in the xhash_walk ... */
            if(n->key != NULL && n->val != NULL)
                (*w)(h, n->key, n->val, arg);
	}
    }
}

/* return the dirty flag (and reset) */
int xhash_dirty(xht h)
{
    int dirty;

    if(h == NULL) return 1;

    dirty = h->dirty;
    h->dirty = 0;
    return dirty;
}

/* return the total number of entries in this xht */
int xhash_count(xht h)
{
    if(h == NULL) return 0;

    return h->count;
}

/* get our pool */
pool xhash_pool(xht h)
{
    return h->p;
}
