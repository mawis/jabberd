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

/**
 * @file xhash.c
 * @brief implements a hash type collection
 */

#include <jabberdlib.h>


/**
 * Generates a hash code for a string.
 * 
 * This function uses the ELF hashing algorithm as reprinted in 
 * Andrew Binstock, "Hashing Rehashed," Dr. Dobb's Journal, April 1996.
 *
 * @param s the string to hash
 * @return the hash value
 */
int _xhasher(const char *s) {
    /* ELF hash uses unsigned chars and unsigned arithmetic for portability */
    const unsigned char *name = (const unsigned char *)s;
    unsigned long h = 0, g;

    while (*name) {
	/* do some fancy bitwanking on the string */
        h = (h << 4) + (unsigned long)(*name++);
        if ((g = (h & 0xF0000000UL))!=0)
            h ^= (g >> 24);
        h &= ~g;

    }

    return (int)h;
}

/**
 * insert a new 'node' in the xhash
 *
 * @param h the xhash where to insert the new node
 * @param index to which index the node should be inserted
 * @return the newly created node
 */
xhn _xhash_node_new(xht h, int index) {
    xhn n;
    int i = index % h->prime;

    /* get existing empty one */
    for(n = &h->zen[i]; n != NULL; n = n->next)
        if(n->key == NULL)
            return n;

    /* overflowing, new one! */
    n = pmalloco(h->p, sizeof(_xhn));
    n->next = h->zen[i].next;
    h->zen[i].next = n;
    return n;
}

/**
 * get the node for a given key out of the xhash
 *
 * @param h the xhash to get the node from
 * @param key which key to get
 * @param index the index for the key
 * @return the node for the key, NULL if no such node
 */
xhn _xhash_node_get(xht h, const char *key, int index) {
    xhn n;
    int i = index % h->prime;
    for(n = &h->zen[i]; n != NULL; n = n->next)
        if(j_strcmp(key, n->key) == 0)
            return n;
    return NULL;
}


/**
 * create a new xhash hash collection
 *
 * @param prime size of the hash (use a prime number!)
 * @return pointer to the new hash
 */
xht xhash_new(int prime) {
    xht xnew;
    pool p;

/*    log_debug(ZONE,"creating new hash table of size %d",prime); */

    p = pool_heap(sizeof(_xhn)*prime + sizeof(_xht));
    xnew = pmalloco(p, sizeof(_xht));
    xnew->prime = prime;
    xnew->p = p;
    xnew->zen = pmalloco(p, sizeof(_xhn)*prime); /* array of xhn size of prime */
    return xnew;
}


/**
 * put an entry in the xhash
 *
 * @param h the hash to insert the entry in
 * @param key with which key the value should be entered
 * @param val the value, that should be entered
 */
void xhash_put(xht h, const char *key, void *val) {
    int index;
    xhn n;

    if(h == NULL || key == NULL)
        return;

    index = _xhasher(key);

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

/**
 * retrive a value from a xhash
 *
 * @param h the xhash to get the value from
 * @param key which value to get
 * @return pointer to the value, NULL if no such key
 */
void *xhash_get(xht h, const char *key) {
    xhn n;

    if(h == NULL || key == NULL || (n = _xhash_node_get(h, key, _xhasher(key))) == NULL)
    {
/*        log_debug(ZONE,"failed lookup of %s",key); */
        return NULL;
    }

/*    log_debug(ZONE,"found %s returning %X",key,n->val); */
    return n->val;
}

/**
 * remove an entry from the xhash
 *
 * @param h the xhash where a value should be removed
 * @param key the key of the value, that should be removed
 */
void xhash_zap(xht h, const char *key) {
    xhn n;

    if(h == NULL || key == NULL || (n = _xhash_node_get(h, key, _xhasher(key))) == NULL)
        return;

/*    log_debug(ZONE,"zapping %s",key); */

    /* kill an entry by zeroing out the key */
    n->key = NULL;
}

/**
 * free a xhash structure
 *
 * @param h the xhash to free
 */
void xhash_free(xht h) {
/*    log_debug(ZONE,"hash free %X",h); */

    if(h != NULL)
        pool_free(h->p);
}

/**
 * iterate over a xhash strucutre
 *
 * @param h the xhash to iterave over
 * @param w which function should be called for each value
 * @param arg what to pass to the optional argument of the xhash_walker function
 */
void xhash_walk(xht h, xhash_walker w, void *arg) {
    int i;
    xhn n;

    if(h == NULL || w == NULL)
        return;

/*    log_debug(ZONE,"walking %X",h); */

    for(i = 0; i < h->prime; i++)
        for(n = &h->zen[i]; n != NULL; n = n->next)
            if(n->key != NULL && n->val != NULL)
                (*w)(h, n->key, n->val, arg);
}
