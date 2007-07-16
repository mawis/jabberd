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

/**
 * @file xhash.cc
 * @brief implements a hash type collection
 *
 * @deprecated Use STL containers (e.g. std::map) instead xhash for new code.
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
    for(n = h->zen[i]; n != NULL; n = n->next)
        if(n->key == NULL)	/* should not happen anymore, we are now removing unused nodes */
            return n;

    /* overflowing, new one! */
    n = new _xhn;	/* XXX dangerous not to use a memory pool, but current pools don't allow to free memory! */
    bzero(n, sizeof(_xhn));
    n->next = h->zen[i];
    h->zen[i] = n;
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
    for(n = h->zen[i]; n != NULL; n = n->next)
        if(j_strcmp(key, n->key) == 0)
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
    xnew = static_cast<xht>(pmalloco(p, sizeof(_xht)));
    xnew->prime = prime;
    xnew->p = p;
    xnew->zen = static_cast<xhn_struct**>(pmalloco(p, sizeof(xhn)*prime)); /* array of xhn size of prime */
    pool_cleanup(p, _xhash_cleaner, (void*)xnew);
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
 * retrive a value from a xhash ... considering the key to be a domain
 *
 * In contrast to xhash_get() this function interprets the key as a
 * domain and checks all higher level domains, if the key is not found
 * in the hash. If now higher level domains are found either, the
 * key '*' is tried.
 *
 * Example: For the domain 'a.example.com' the following lookups
 * are done in this order until there is the first match: 'a.example.com',
 * 'example.com', 'com', and '*'.
 *
 * @param h the xhash to get the value from
 * @param domain the domain which should be used as the key
 */
void *xhash_get_by_domain(xht h, const char *domain) {
    const char* next_token = domain;

    while (next_token != NULL) {
        /* is there a setting for this level of subdomains? */
        void *result = xhash_get(h, next_token);

        if (result != NULL) {
            return result;
        }

        /* skip one level of subdomains */
        next_token = strstr(next_token, ".");
        if (next_token != NULL) {
            next_token++;
        }
    }

    /* nothing found: return the default, or NULL */
    return xhash_get(h, "*");
}

/**
 * remove an entry from the xhash
 *
 * @param h the xhash where a value should be removed
 * @param key the key of the value, that should be removed
 */
void xhash_zap(xht h, const char *key) {
    xhn n = NULL;
    xhn previous_node = NULL;
    int index = 0;

    if(h == NULL || key == NULL)
          return;

    index = _xhasher(key) % h->prime;

    for (n = h->zen[index]; n != NULL; n = n->next) {
        if (n->key != NULL && strcmp(key, n->key) == 0) {
            /* found entry */

            /* remove entry */
            if (previous_node == NULL) {
                /* first entry for this index */
                h->zen[index] = n->next;
            } else {
                previous_node->next = n->next;
            }
            delete n;

            /* entry removed, we can return */
            return;
        }

        previous_node = n;
    }
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

/**
 * xhash_walker() function used by xhash_to_xml to put entries in an ::xhash into an ::xmlnode
 *
 * @param h the hash containing the entires (ignored)
 * @param key the key of the entry
 * @param value the value of the entry
 * @param arg ::xmlnode to insert the entry to
 */
static void _xhash_to_xml_walker(xht h, const char *key, void *value, void *arg) {
    xmlnode rootnode = (xmlnode)arg;
    xmlnode entry = NULL;
    xmlnode keynode = NULL;
    xmlnode valuenode = NULL;

    entry = xmlnode_insert_tag_ns(rootnode, "entry", NULL, NS_JABBERD_HASH);

    keynode = xmlnode_insert_tag_ns(entry, "key", NULL, NS_JABBERD_HASH);
    xmlnode_insert_cdata(keynode, key, -1);

    valuenode = xmlnode_insert_tag_ns(entry, "value", NULL, NS_JABBERD_HASH);
    xmlnode_insert_cdata(valuenode, static_cast<const char*>(value), -1);
}

/**
 * write the contents of an xhash to an xmlnode
 *
 * @note the result has to be freed by the caller using xmlnode_free()
 *
 * @param h the xhash to be converted
 * @return xmlnode tree containing the content of the xhash
 */
xmlnode xhash_to_xml(xht h) {
    xmlnode result = NULL;
    char prime[32] = "";

    /* sanity check */
    if (h == NULL)
	return NULL;

    /* create root node */
    result = xmlnode_new_tag_ns("hash", NULL, NS_JABBERD_HASH);
    snprintf(prime, sizeof(prime), "%i", h->prime);
    xmlnode_put_attrib_ns(result, "prime", NULL, NULL, prime);

    /* insert entries */
    xhash_walk(h, _xhash_to_xml_walker, result);

    return result;
}

/**
 * convert the xmlnode representation of an xhash back to an xhash
 *
 * @note the result has to be freed by the caller using xhash_free()
 *
 * @param hash the xhash in xml notation
 * @return xhash that has been created
 */
xht xhash_from_xml(xmlnode hash) {
    xht result = NULL;
    xht ns = NULL;
    xmlnode_list_item entry = NULL;
    int prime = j_atoi(xmlnode_get_attrib_ns(hash, "prime", NULL), 101);

    if (hash == NULL)
	return NULL;

    result = xhash_new(prime);
    ns = xhash_new(2);
    xhash_put(ns, "", const_cast<char*>(NS_JABBERD_HASH));

    pool temp_p = pool_new();

    for (entry = xmlnode_get_tags(hash, "entry", ns, temp_p); entry != NULL; entry = entry->next) {
	char const* key = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(entry->node, "key", ns, temp_p), 0));
	char const* value = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(entry->node, "value", ns, temp_p), 0));

	if (value == NULL)
	    value = "";

	if (key == NULL)
	    key = "";

	xhash_put(result, pstrdup(result->p, key), pstrdup(result->p, value));
    }

    pool_free(temp_p);
    temp_p = NULL;

    xhash_free(ns);

    return result;
}
