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

#include "lib.h"

#ifdef LIBIDN

#  include <stringprep.h>


/**
 * datastructure to build the stringprep caches
 */
typedef struct _jid_prep_entry_st {
    char *preped;	/**< the result of the preparation */
    time_t last_used;	/**< when this result has last been successfully used */
    unsigned int used_count; /**< how often this result has been successfully used */
    int size;		/**< the min buffer size needed to hold the result (strlen+1) */
} *_jid_prep_entry_t;

/**
 * hashtable containing already preped nodes
 *
 * we are using global caches here for two reasons:
 * - I do not see why different instances would want
 *   to have different caches as we are always doing
 *   the same
 * - For per instance caches I would have to modify the
 *   interface of the jid_*() functions which would break
 *   compatibility with transports
 */
xht _jid_prep_cache_node = NULL;

/**
 * mutex that protects the access to the nodeprep cache
 */
pth_mutex_t _jid_prep_cache_node_mutex = PTH_MUTEX_INIT;

/**
 * hashtable containing already preped domains
 */
xht _jid_prep_cache_domain = NULL;

/**
 * mutex that protects the access to the nameprep cache
 */
pth_mutex_t _jid_prep_cache_domain_mutex = PTH_MUTEX_INIT;

/**
 * hashtable containing already preped resources
 */
xht _jid_prep_cache_resource = NULL;

/**
 * mutex that protects the access to the resourceprep cache
 */
pth_mutex_t _jid_prep_cache_resource_mutex = PTH_MUTEX_INIT;

/**
 * walker for cleaning up stringprep caches
 *
 * @param h the hash we are walking through
 * @param key the key of this item
 * @param val the value of this item
 * @param arg delete entries older as this unix timestamp
 */
void _jid_clean_walker(xht h, const char *key, void *val, void *arg) {
    time_t *keep_newer_as = (time_t*)arg;
    _jid_prep_entry_t entry = (_jid_prep_entry_t)val;

    if (entry == NULL)
	return;

    if (entry->last_used <= *keep_newer_as) {
	xhash_zap(h, key);
	if (entry->preped != NULL)
	    free(entry->preped);
	free(entry);

	/* sorry, I have to cast the const away */
	/* any idea how I could delete the key else? */
	if (key != NULL)
	    free((void*)key);
    }
}

/**
 * walk through the stringprep caches and check which entries have expired
 */
void jid_clean_cache() {
    /* XXX make this configurable? */
    time_t keep_newer_as = time(NULL) - 900;

    /* cleanup the nodeprep cache */
    
    /* acquire the lock on the cache */
    pth_mutex_acquire(&_jid_prep_cache_node_mutex, FALSE, NULL);

    /* walk over all entries */
    xhash_walk(_jid_prep_cache_node, _jid_clean_walker, (void*)&keep_newer_as);

    /* we're done, release the lock on the cache */
    pth_mutex_release(&_jid_prep_cache_node_mutex);

    /* cleanup the domain preparation cache */
    
    /* acquire the lock on the cache */
    pth_mutex_acquire(&_jid_prep_cache_domain_mutex, FALSE, NULL);

    /* walk over all entries */
    xhash_walk(_jid_prep_cache_domain, _jid_clean_walker, (void*)&keep_newer_as);

    /* we're done, release the lock on the cache */
    pth_mutex_release(&_jid_prep_cache_domain_mutex);

    /* cleanup the resourceprep cache */
    
    /* acquire the lock on the cache */
    pth_mutex_acquire(&_jid_prep_cache_resource_mutex, FALSE, NULL);

    /* walk over all entries */
    xhash_walk(_jid_prep_cache_resource, _jid_clean_walker, (void*)&keep_newer_as);

    /* we're done, release the lock on the cache */
    pth_mutex_release(&_jid_prep_cache_resource_mutex);
}

/**
 * caching wrapper around libidn's stringprep_xmpp_nodeprep()
 *
 * @param in_out_buffer buffer containing what has to be stringpreped and that gets the result
 * @param max_len size of the buffer
 * @return the return code of stringprep_xmpp_nodeprep()
 */
int _jid_cached_stringprep_xmpp_nodeprep(char *in_out_buffer, int max_len) {
    _jid_prep_entry_t preped;
    int result = STRINGPREP_OK;

    /* check that the cache already exists */
    if (_jid_prep_cache_node == NULL) {
	_jid_prep_cache_node = xhash_new(2003);
    }

    /* did we get an argument? */
    if (in_out_buffer == NULL) {
	return STRINGPREP_OK;
    }

    /* acquire the lock on the cache */
    pth_mutex_acquire(&_jid_prep_cache_node_mutex, FALSE, NULL);

    /* check if the requested preparation has already been done */
    preped = (_jid_prep_entry_t)xhash_get(_jid_prep_cache_node, in_out_buffer);
    if (preped != NULL) {
	/* we already prepared this argument */
	if (preped->size <= max_len) {
	    /* we can use the result */

	    /* update the statistic */
	    preped->used_count++;
	    preped->last_used = time(NULL);

	    /* copy the result */
	    strcpy(in_out_buffer, preped->preped);
	    result = STRINGPREP_OK;
	} else {
	    /* we need a bigger buffer */
	    result = STRINGPREP_TOO_SMALL_BUFFER;
	}
	
	/* we're done, release the lock on the cache */
	pth_mutex_release(&_jid_prep_cache_node_mutex);

    } else {
	char *original;

	/* stringprep needs time, release the lock on the cache for the meantime */
	pth_mutex_release(&_jid_prep_cache_node_mutex);

	/* we have to keep the key */
	original = strdup(in_out_buffer);
	
	/* try to prepare the string */
	result = stringprep_xmpp_nodeprep(in_out_buffer, max_len);

	/* did we manage to prepare the string? */
	if (result == STRINGPREP_OK && original != NULL) {
	    /* generate an entry for the cache */
	    preped = (_jid_prep_entry_t)malloc(sizeof(struct _jid_prep_entry_st));
	    if (preped != NULL) {
		preped->preped = strdup(in_out_buffer);
		preped->last_used = time(NULL);
		preped->used_count = 1;
		preped->size = strlen(in_out_buffer)+1;

		/* acquire the lock on the cache again */
		pth_mutex_acquire(&_jid_prep_cache_node_mutex, FALSE, NULL);

		/* store the entry in the cache */
		xhash_put(_jid_prep_cache_node, original, preped);

		/* we're done, release the lock on the cache */
		pth_mutex_release(&_jid_prep_cache_node_mutex);
	    } else {
		/* we don't need the copy of the key, if there is no memory to store it */
		free(original);
	    }
	} else {
	    /* we don't need the copy of the original value */
	    if (original != NULL)
		free(original);
	}
    }

    return result;
}


/**
 * caching wrapper around libidn's stringprep_nameprep_no_unassigned()
 *
 * @param in_out_buffer buffer containing what has to be stringpreped and that gets the result
 * @param max_len size of the buffer
 * @return the return code of stringprep_nameprep_no_unassigned
 */
int _jid_cached_stringprep_nameprep_no_unassigned(char *in_out_buffer, int max_len) {
    _jid_prep_entry_t preped;
    int result = STRINGPREP_OK;

    /* check that the cache already exists */
    if (_jid_prep_cache_domain == NULL) {
	_jid_prep_cache_domain = xhash_new(2003);
    }

    /* did we get an argument? */
    if (in_out_buffer == NULL) {
	return STRINGPREP_OK;
    }

    /* acquire the lock on the cache */
    pth_mutex_acquire(&_jid_prep_cache_domain_mutex, FALSE, NULL);

    /* check if the requested preparation has already been done */
    preped = (_jid_prep_entry_t)xhash_get(_jid_prep_cache_domain, in_out_buffer);
    if (preped != NULL) {
	/* we already prepared this argument */
	if (preped->size <= max_len) {
	    /* we can use the result */

	    /* update the statistic */
	    preped->used_count++;
	    preped->last_used = time(NULL);

	    /* copy the result */
	    strcpy(in_out_buffer, preped->preped);
	    result = STRINGPREP_OK;
	} else {
	    /* we need a bigger buffer */
	    result = STRINGPREP_TOO_SMALL_BUFFER;
	}
	
	/* we're done, release the lock on the cache */
	pth_mutex_release(&_jid_prep_cache_domain_mutex);

    } else {
	char *original;

	/* stringprep needs time, release the lock on the cache for the meantime */
	pth_mutex_release(&_jid_prep_cache_domain_mutex);

	/* we have to keep the key */
	original = strdup(in_out_buffer);
	
	/* try to prepare the string */
	result = stringprep_nameprep_no_unassigned(in_out_buffer, max_len);

	/* did we manage to prepare the string? */
	if (result == STRINGPREP_OK && original != NULL) {
	    /* generate an entry for the cache */
	    preped = (_jid_prep_entry_t)malloc(sizeof(struct _jid_prep_entry_st));
	    if (preped != NULL) {
		preped->preped = strdup(in_out_buffer);
		preped->last_used = time(NULL);
		preped->used_count = 1;
		preped->size = strlen(in_out_buffer)+1;

		/* acquire the lock on the cache again */
		pth_mutex_acquire(&_jid_prep_cache_domain_mutex, FALSE, NULL);

		/* store the entry in the cache */
		xhash_put(_jid_prep_cache_domain, original, preped);

		/* we're done, release the lock on the cache */
		pth_mutex_release(&_jid_prep_cache_domain_mutex);
	    } else {
		/* we don't need the copy of the key, if there is no memory to store it */
		free(original);
	    }
	} else {
	    /* we don't need the copy of the original value */
	    if (original != NULL)
		free(original);
	}
    }

    return result;
}

/**
 * caching wrapper around libidn's stringprep_xmpp_resourceprep()
 *
 * @param in_out_buffer buffer containing what has to be stringpreped and that gets the result
 * @param max_len size of the buffer
 * @return the return code of stringprep_xmpp_resourceprep()
 */
int _jid_cached_stringprep_xmpp_resourceprep(char *in_out_buffer, int max_len) {
    _jid_prep_entry_t preped;
    int result = STRINGPREP_OK;

    /* check that the cache already exists */
    if (_jid_prep_cache_resource == NULL) {
	_jid_prep_cache_resource = xhash_new(2003);
    }

    /* did we get an argument? */
    if (in_out_buffer == NULL) {
	return STRINGPREP_OK;
    }

    /* acquire the lock on the cache */
    pth_mutex_acquire(&_jid_prep_cache_resource_mutex, FALSE, NULL);

    /* check if the requested preparation has already been done */
    preped = (_jid_prep_entry_t)xhash_get(_jid_prep_cache_resource, in_out_buffer);
    if (preped != NULL) {
	/* we already prepared this argument */
	if (preped->size <= max_len) {
	    /* we can use the result */

	    /* update the statistic */
	    preped->used_count++;
	    preped->last_used = time(NULL);

	    /* copy the result */
	    strcpy(in_out_buffer, preped->preped);
	    result = STRINGPREP_OK;
	} else {
	    /* we need a bigger buffer */
	    result = STRINGPREP_TOO_SMALL_BUFFER;
	}
	
	/* we're done, release the lock on the cache */
	pth_mutex_release(&_jid_prep_cache_resource_mutex);

    } else {
	char *original;

	/* stringprep needs time, release the lock on the cache for the meantime */
	pth_mutex_release(&_jid_prep_cache_resource_mutex);

	/* we have to keep the key */
	original = strdup(in_out_buffer);
	
	/* try to prepare the string */
	result = stringprep_xmpp_resourceprep(in_out_buffer, max_len);

	/* did we manage to prepare the string? */
	if (result == STRINGPREP_OK && original != NULL) {
	    /* generate an entry for the cache */
	    preped = (_jid_prep_entry_t)malloc(sizeof(struct _jid_prep_entry_st));
	    if (preped != NULL) {
		preped->preped = strdup(in_out_buffer);
		preped->last_used = time(NULL);
		preped->used_count = 1;
		preped->size = strlen(in_out_buffer)+1;

		/* acquire the lock on the cache again */
		pth_mutex_acquire(&_jid_prep_cache_resource_mutex, FALSE, NULL);

		/* store the entry in the cache */
		xhash_put(_jid_prep_cache_resource, original, preped);

		/* we're done, release the lock on the cache */
		pth_mutex_release(&_jid_prep_cache_resource_mutex);
	    } else {
		/* we don't need the copy of the key, if there is no memory to store it */
		free(original);
	    }
	} else {
	    /* we don't need the copy of the original value */
	    if (original != NULL)
		free(original);
	}
    }

    return result;
}


/**
 * nameprep the domain identifier in a JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if JID is valid, non zero otherwise
 */
int _jid_safe_domain(jid id) {
    int result=0;

    /* there must be a domain identifier */
    if (j_strlen(id->server) == 0)
	return 1;

    /* nameprep the domain identifier */
    result = _jid_cached_stringprep_nameprep_no_unassigned(id->server, strlen(id->server)+1);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nameprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->server);
	result = _jid_cached_stringprep_nameprep_no_unassigned(biggerbuffer, biggerbuffersize);
	id->server = biggerbuffer;
    }
    if (result != STRINGPREP_OK)
	return 1;

    /* the namepreped domain must not be longer than 1023 bytes */
    if (j_strlen(id->server) > 1023)
	return 1;

    /* if nothing failed, the domain is valid */
    return 0;
}

/**
 * nodeprep the node identifier in a JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if JID is valid, non zero otherwise
 */
int _jid_safe_node(jid id) {
    int result=0;

    /* it is valid to have no node identifier in the JID */
    if (id->user == NULL)
	return 0;

    /* nodeprep */
    result = _jid_cached_stringprep_xmpp_nodeprep(id->user, strlen(id->user)+1);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nodeprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->user);
	result = _jid_cached_stringprep_xmpp_nodeprep(biggerbuffer, biggerbuffersize);
	id->user = biggerbuffer;
    }
    if (result != STRINGPREP_OK)
	return 1;

    /* the nodepreped node must not be longer than 1023 bytes */
    if (j_strlen(id->user) > 1023)
	return 1;

    /* if nothing failed, the node is valid */
    return 0;
}

/**
 * resourceprep the resource identifier in a JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if JID is valid, non zero otherwise
 */
int _jid_safe_resource(jid id) {
    int result=0;

    /* it is valid to have no resource identifier in the JID */
    if (id->resource == NULL)
	return 0;

    /* resource prep the resource identifier */
    result = _jid_cached_stringprep_xmpp_resourceprep(id->resource, strlen(id->resource)+1);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* resourceprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->resource);
	result = _jid_cached_stringprep_xmpp_resourceprep(biggerbuffer, biggerbuffersize);
	id->resource = biggerbuffer;
    }
    if (result != STRINGPREP_OK)
	return 1;

    /* the resourcepreped node must not be longer than 1023 bytes */
    if (j_strlen(id->resource) > 1023)
	return 1;

    /* if nothing failed, the resource is valid */
    return 0;

}

#else /* no LIBIDN */

/**
 * check if the domain identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if domain is valid, non zero otherwise
 */
int _jid_safe_domain(jid id) {
    char *str;

    /* there must be a domain identifier */
    if (j_strlen(id->server) == 0)
	return 1;

    /* and it must not be longer than 1023 bytes */
    if (strlen(id->server) > 1023)
	return 1;

    /* lowercase the hostname, make sure it's valid characters */
    for(str = id->server; *str != '\0'; str++)
    {
        *str = tolower(*str);
        if(!(isalnum(*str) || *str == '.' || *str == '-' || *str == '_')) return 1;
    }

    /* otherwise it's okay as far as we can tell without LIBIDN */
    return 0;
}

/**
 * check if the node identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if node is valid, non zero otherwise
 */
int _jid_safe_node(jid id) {
    char *str;

    /* node identifiers may not be longer than 1023 bytes */
    if (j_strlen(id->user) > 1023)
	return 1;

    /* check for low and invalid ascii characters in the username */
    if(id->user != NULL)
        for(str = id->user; *str != '\0'; str++)
            if(*str <= 32 || *str == ':' || *str == '@' || *str == '<' || *str == '>' || *str == '\'' || *str == '"' || *str == '&') return 1;

    /* otherwise it's okay as far as we can tell without LIBIDN */
    return 0;
}

/**
 * check if the resource identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if resource is valid, non zero otherwise
 */
int _jid_safe_resource(jid id) {
    /* resources may not be longer than 1023 bytes */
    if (j_strlen(id->resource) > 1023)
	return 1;

    /* otherwise it's okay as far as we can tell without LIBIDN */
    return 0;
}

#endif

/**
 * nodeprep/nameprep/resourceprep the JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return NULL if the JID is invalid, pointer to the jid otherwise
 */
jid jid_safe(jid id)
{
    if (_jid_safe_domain(id))
	return NULL;
    if (_jid_safe_node(id))
	return NULL;
    if (_jid_safe_resource(id))
	return NULL;

    return id;
}

jid jid_new(pool p, char *idstr)
{
    char *server, *resource, *type, *str;
    jid id;

    if(p == NULL || idstr == NULL || strlen(idstr) == 0)
        return NULL;

    /* user@server/resource */

    str = pstrdup(p, idstr);

    id = pmalloco(p,sizeof(struct jid_struct));
    id->p = p;

    resource = strstr(str,"/");
    if(resource != NULL)
    {
        *resource = '\0';
        ++resource;
        if(strlen(resource) > 0)
            id->resource = resource;
    }else{
        resource = str + strlen(str); /* point to end */
    }

    type = strstr(str,":");
    if(type != NULL && type < resource)
    {
        *type = '\0';
        ++type;
        str = type; /* ignore the type: prefix */
    }

    server = strstr(str,"@");
    if(server == NULL || server > resource)
    { /* if there's no @, it's just the server address */
        id->server = str;
    }else{
        *server = '\0';
        ++server;
        id->server = server;
        if(strlen(str) > 0)
            id->user = str;
    }

    return jid_safe(id);
}

void jid_set(jid id, char *str, int item)
{
    char *old;

    if(id == NULL)
        return;

    /* invalidate the cached copy */
    id->full = NULL;

    switch(item)
    {
    case JID_RESOURCE:
	old = id->resource;
        if(str != NULL && strlen(str) != 0)
            id->resource = pstrdup(id->p, str);
        else
            id->resource = NULL;
        if(_jid_safe_resource(id))
            id->resource = old; /* revert if invalid */
        break;
    case JID_USER:
        old = id->user;
        if(str != NULL && strlen(str) != 0)
            id->user = pstrdup(id->p, str);
        else
            id->user = NULL;
        if(_jid_safe_node(id))
            id->user = old; /* revert if invalid */
        break;
    case JID_SERVER:
        old = id->server;
        id->server = pstrdup(id->p, str);
        if(_jid_safe_domain(id))
            id->server = old; /* revert if invalid */
        break;
    }

}

char *jid_full(jid id)
{
    spool s;

    if(id == NULL)
        return NULL;

    /* use cached copy */
    if(id->full != NULL)
        return id->full;

    s = spool_new(id->p);

    if(id->user != NULL)
        spooler(s, id->user,"@",s);

    spool_add(s, id->server);

    if(id->resource != NULL)
        spooler(s, "/",id->resource,s);

    id->full = spool_print(s);
    return id->full;
}

/* parses a /resource?name=value&foo=bar into an xmlnode representing <resource name="value" foo="bar"/> */
xmlnode jid_xres(jid id)
{
    char *cur, *qmark, *amp, *eq;
    xmlnode x;

    if(id == NULL || id->resource == NULL) return NULL;

    cur = pstrdup(id->p, id->resource);
    qmark = strstr(cur, "?");
    if(qmark == NULL) return NULL;
    *qmark = '\0';
    qmark++;

    x = _xmlnode_new(id->p, cur, NTYPE_TAG);

    cur = qmark;
    while(cur != '\0')
    {
        eq = strstr(cur, "=");
        if(eq == NULL) break;
        *eq = '\0';
        eq++;

        amp = strstr(eq, "&");
        if(amp != NULL)
        {
            *amp = '\0';
            amp++;
        }

        xmlnode_put_attrib(x,cur,eq);

        if(amp != NULL)
            cur = amp;
        else
            break;
    }

    return x;
}

/* local utils */
int _jid_nullstrcmp(char *a, char *b)
{
    if(a == NULL && b == NULL) return 0;
    if(a == NULL || b == NULL) return -1;
    return strcmp(a,b);
}
int _jid_nullstrcasecmp(char *a, char *b)
{
    if(a == NULL && b == NULL) return 0;
    if(a == NULL || b == NULL) return -1;
    return strcasecmp(a,b);
}

int jid_cmp(jid a, jid b)
{
    if(a == NULL || b == NULL)
        return -1;

    if(_jid_nullstrcmp(a->resource, b->resource) != 0) return -1;
    if(_jid_nullstrcasecmp(a->user, b->user) != 0) return -1;
    if(_jid_nullstrcmp(a->server, b->server) != 0) return -1;

    return 0;
}

/* suggested by Anders Qvist <quest@valdez.netg.se> */
int jid_cmpx(jid a, jid b, int parts)
{
    if(a == NULL || b == NULL)
        return -1;

    if(parts & JID_RESOURCE && _jid_nullstrcmp(a->resource, b->resource) != 0) return -1;
    if(parts & JID_USER && _jid_nullstrcasecmp(a->user, b->user) != 0) return -1;
    if(parts & JID_SERVER && _jid_nullstrcmp(a->server, b->server) != 0) return -1;

    return 0;
}

/* makes a copy of b in a's pool, requires a valid a first! */
jid jid_append(jid a, jid b)
{
    jid next;

    if(a == NULL)
        return NULL;

    if(b == NULL)
        return a;

    next = a;
    while(next != NULL)
    {
        /* check for dups */
        if(jid_cmp(next,b) == 0)
            break;
        if(next->next == NULL)
            next->next = jid_new(a->p,jid_full(b));
        next = next->next;
    }
    return a;
}

xmlnode jid_nodescan(jid id, xmlnode x)
{
    xmlnode cur;
    pool p;
    jid tmp;

    if(id == NULL || xmlnode_get_firstchild(x) == NULL) return NULL;

    p = pool_new();
    for(cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(xmlnode_get_type(cur) != NTYPE_TAG) continue;

        tmp = jid_new(p,xmlnode_get_attrib(cur,"jid"));
        if(tmp == NULL) continue;

        if(jid_cmp(tmp,id) == 0) break;
    }
    pool_free(p);

    return cur;
}

jid jid_user(jid a)
{
    jid ret;

    if(a == NULL || a->resource == NULL) return a;

    ret = pmalloco(a->p,sizeof(struct jid_struct));
    ret->p = a->p;
    ret->user = a->user;
    ret->server = a->server;

    return ret;
}
