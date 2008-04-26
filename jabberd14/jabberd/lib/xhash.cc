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
 * @brief implements a hashmap using STL containers
 */

#include <jabberdlib.h>

namespace xmppd {
    template<class value_type> typename xmppd::xhash<value_type>::iterator xhash<value_type>::get_by_domain(std::string domainkey) {
	while (true) {
	    typename xmppd::xhash<value_type>::iterator result = xhash<value_type>::find(domainkey);
	    if (result != xhash<value_type>::end())
		return result;

	    std::string::size_type dot_pos = domainkey.find(".");
	    if (dot_pos == std::string::npos)
		return xhash<value_type>::find("*");

	    domainkey.erase(0, dot_pos+1);
	}
    }
}

/**
 * create a new xhash hash collection
 *
 * @param prime size of the hash (use a prime number!)
 * @return pointer to the new hash
 */
xht xhash_new(int prima) {
    return new xmppd::xhash<void*>();
}

/**
 * put an entry in the xhash
 *
 * @param h the hash to insert the entry in
 * @param key with which key the value should be entered
 * @param val the value, that should be entered
 */
void xhash_put(xht h, const char *key, void *val) {
    // sanity checks
    if (h == NULL || key == NULL) {
	return;
    }

    // insert the element
    (*h)[key] = val;
}

/**
 * retrive a value from a xhash
 *
 * @param h the xhash to get the value from
 * @param key which value to get
 * @return pointer to the value, NULL if no such key
 */
void* xhash_get(xht h, const char *key) {
    // sanity checks
    if (h == NULL || key == NULL) {
	return NULL;
    }

    // check if the element exists
    xmppd::xhash<void*>::iterator i = h->find(key);

    // element does not exist?
    if (i == h->end()) {
	return NULL;
    }

    // it exists, return it
    return i->second;
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
    // sanity checks
    if (h == NULL || domain == NULL) {
	return NULL;
    }

    // check if the element exists
    xmppd::xhash<void*>::iterator i = h->get_by_domain(domain);

    // element does not exist?
    if (i == h->end()) {
	return NULL;
    }

    // it exists, return it
    return i->second;
}

/**
 * remove an entry from the xhash
 *
 * @param h the xhash where a value should be removed
 * @param key the key of the value, that should be removed
 */
void xhash_zap(xht h, const char *key) {
    // sanity check
    if (h == NULL || key == NULL) {
	return;
    }

    // erase the element from the hashtable
    h->erase(key);
}

/**
 * free a xhash structure
 *
 * @param h the xhash to free
 */
void xhash_free(xht h) {
    // sanity check
    if (h == NULL) {
	return;
    }

    // free the instance
    delete h;
}

/**
 * iterate over a xhash strucutre
 *
 * @param h the xhash to iterave over
 * @param w which function should be called for each value
 * @param arg what to pass to the optional argument of the xhash_walker function
 */
void xhash_walk(xht h, xhash_walker w, void *arg) {
    // sanity checks
    if (h == NULL || w == NULL) {
	return;
    }

    // iterate the elements
    xmppd::xhash<void*>::iterator p;
    xmppd::xhash<void*>::iterator next = h->begin();
    for (p = h->begin(); p != h->end(); p = next) {
	// already get iterator to the next element, the callback might remove this one
	++next;

	(*w)(h, p->first.c_str(), p->second, arg);
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
xht xhash_from_xml(xmlnode hash, pool p) {
    xht result = NULL;
    xht ns = NULL;
    int prime = j_atoi(xmlnode_get_attrib_ns(hash, "prime", NULL), 101);

    if (hash == NULL)
	return NULL;

    result = xhash_new(prime);
    ns = xhash_new(2);
    xhash_put(ns, "", const_cast<char*>(NS_JABBERD_HASH));

    xmlnode_vector entry = xmlnode_get_tags(hash, "entry", ns);
    xmlnode_vector::iterator iter;
    for (iter = entry.begin(); iter != entry.end(); ++iter) {
	char *key = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(*iter, "key", ns), 0));
	char *value = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(*iter, "value", ns), 0));

	if (value == NULL)
	    value = pstrdup(p, "");

	if (key == NULL)
	    key = pstrdup(p, "");

	xhash_put(result, key, pstrdup(p, value));
    }

    xhash_free(ns);

    return result;
}
