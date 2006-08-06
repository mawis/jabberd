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

/**
 * @file jid.c
 * @brief Handling of JabberIDs
 *
 * This file contains functions to store, manipulate, and compare JabberIDs
 */

#include "util.h"

#ifdef LIBIDN

/**
 * walker for cleaning up stringprep caches
 *
 * @param h the hash we are walking through
 * @param key the key of this item
 * @param val the value of this item
 * @param arg delete entries older as this unix timestamp
 */
static void _jid_clean_walker(xht h, const char *key, void *val, void *arg) {
    time_t *keep_newer_as = (time_t*)arg;
    _jid_prep_entry_t entry = (_jid_prep_entry_t)val;

    /* safty check */
    if (entry == NULL)
	return;

    if (entry->last_used <= *keep_newer_as) {
	/* the entry expired, remove it */
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
 * walk through a single stringprep cache and check which entries
 * have expired
 *
 * @param cache the cache to walk
 * @param keep_newer_as what to keep in the cache
 */
static void _jid_clean_single_cache(_jid_prep_cache_t cache, time_t keep_newer_as) {
    xhash_walk(cache->hashtable, _jid_clean_walker, (void*)&keep_newer_as);
}

/**
 * walk through all stringprep caches and check which entries have expired
 *
 * @param environment the jid environment that holds the caches
 */
void jid_clean_cache(jid_environment_t environment) {
    time_t keep_newer_as = time(NULL) - 900;

    _jid_clean_single_cache(environment->nodes, keep_newer_as);
    _jid_clean_single_cache(environment->domains, keep_newer_as);
    _jid_clean_single_cache(environment->resources, keep_newer_as);
}

/**
 * caching wrapper around stringprep
 *
 * @param in_out_buffer buffer containing waht has to be stringpreped and that gets the result
 * @param max_len size of the buffer
 * @param cache the used cache, defining also the used stringprep profile
 * @return the return code of the stringprep call
 */
static int _jid_cached_stringprep(char *in_out_buffer, int max_len, _jid_prep_cache_t cache) {
    _jid_prep_entry_t preped;
    int result = STRINGPREP_OK;

    /* check that the cache already exists
     * we can not do anything as we don't know which profile has to be used */
    if (cache == NULL) {
	return STRINGPREP_UNKNOWN_PROFILE;
    }

    /* is there something that has to be stringpreped? */
    if (in_out_buffer == NULL) {
	return STRINGPREP_OK;
    }

    /* check if the requested preparation has already been done */
    preped = (_jid_prep_entry_t)xhash_get(cache->hashtable, in_out_buffer);
    if (preped != NULL) {
	/* we already prepared this argument */

	if (preped->size <= max_len) {
	    /* we can use the result */

	    /* update the statistics */
	    preped->used_count++;
	    preped->last_used = time(NULL);

	    /* do we need to copy the result? */
	    if (preped->preped != NULL) {
		/* copy the result */
		strcpy(in_out_buffer, preped->preped);
	    }
	} else {
	    /* we need a bigger buffer */
	    result = STRINGPREP_TOO_SMALL_BUFFER;
	}
    } else {
	char *original;

	/* we have to keep the key */
	original = strdup(in_out_buffer);

	/* try to prepare the string */
	result = stringprep(in_out_buffer, max_len, STRINGPREP_NO_UNASSIGNED, cache->profile);

	/* did we manage to prepare the string? */
	if (result == STRINGPREP_OK && original != NULL) {
	    /* generate an entry for the cache */
	    preped = (_jid_prep_entry_t)malloc(sizeof(struct _jid_prep_entry_st));
	    if (preped != NULL) {
		/* has there been modified something? */
		if (j_strcmp(in_out_buffer, original) == 0) {
		    /* no, we don't need to store a copy of the original string */
		    preped->preped = NULL;
		} else {
		    /* yes, store the stringpreped string */
		    preped->preped = strdup(in_out_buffer);
		}
		preped->last_used = time(NULL);
		preped->used_count = 1;
		preped->size = strlen(in_out_buffer)+1;

		/* store the entry in the cache */
		xhash_put(cache->hashtable, original, preped);
	    } else {
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
 * free a single stringprep cache
 *
 * @param cache the cache that should be freed
 */
static void _jid_stop_single_cache(_jid_prep_cache_t *cache) {
    if (*cache == NULL)
	return;

    _jid_clean_single_cache(*cache, time(NULL));

    xhash_free((*cache)->hashtable);

    *cache = NULL;
}

/**
 * init a single stringprep cache
 *
 * @param cache the cache to init
 * @param prime the time used to init the hashtable
 * @param profile profile used to prepare the strings
 */
static void _jid_init_single_cache(_jid_prep_cache_t *cache, int prime, const Stringprep_profile *profile) {
    /* do not init a cache twice */
    if (*cache == NULL) {
	*cache = (_jid_prep_cache_t)malloc(sizeof(struct _jid_prep_cache_st));
	(*cache)->hashtable = xhash_new(prime);
	(*cache)->profile = profile;
    } else {
	printf("Ooups!");
	exit(1);
    }
}

/**
 * free a jid preparing environment
 *
 * @param environment the environment to be freed
 */
void jid_free_environment(jid_environment_t environment) {
    if (environment == NULL)
	return;

    _jid_stop_single_cache(&(environment->nodes));
    _jid_stop_single_cache(&(environment->domains));
    _jid_stop_single_cache(&(environment->resources));

    free(environment);
}

/**
 * create a new jid preparing environment
 *
 * @return the new environment
 */
jid_environment_t jid_new_environment() {
    jid_environment_t environment = (jid_environment_t)malloc(sizeof(struct _jid_environment));
    bzero(environment, sizeof(struct _jid_environment));

    _jid_init_single_cache(&(environment->nodes), 2003, stringprep_xmpp_nodeprep);
    _jid_init_single_cache(&(environment->domains), 2003, stringprep_nameprep);
    _jid_init_single_cache(&(environment->resources), 2003, stringprep_xmpp_resourceprep);

    return environment;
}

/**
 * nameprep the domain identifier in a JID and check if it is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if JID is valid, non zero otherwise
 */
static int _jid_safe_domain(jid id) {
    int result=0;

    /* there must be a domain identifier */
    if (j_strlen(id->server) == 0)
	return 1;

    /* nameprep the domain identifier */
    result = _jid_cached_stringprep(id->server, strlen(id->server)+1, id->environment->domains);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nameprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->server);
	result = _jid_cached_stringprep(biggerbuffer, biggerbuffersize, id->environment->domains);
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
static int _jid_safe_node(jid id) {
    int result=0;

    /* it is valid to have no node identifier in the JID */
    if (id->user == NULL)
	return 0;

    /* nodeprep */
    result = _jid_cached_stringprep(id->user, strlen(id->user)+1, id->environment->nodes);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nodeprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->user);
	result = _jid_cached_stringprep(biggerbuffer, biggerbuffersize, id->environment->nodes);
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
static int _jid_safe_resource(jid id) {
    int result=0;

    /* it is valid to have no resource identifier in the JID */
    if (id->resource == NULL)
	return 0;

    /* resource prep the resource identifier */
    result = _jid_cached_stringprep(id->resource, strlen(id->resource)+1, id->environment->resources);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* resourceprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->resource);
	result = _jid_cached_stringprep(biggerbuffer, biggerbuffersize, id->environment->resources);
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

/* empty implementation, we do not have caches if compiled without libidn */
void	jid_clean_cache(jid_environment_t environment) {}

/* empty implementation, we do not have caches if compiled without libidn */
void	jid_free_environment(jid_environment_t environment) {}

/* empty implementation, we do not have caches if compiled without libidn */
jid_environment_t jid_new_environment() { return NULL; }

/**
 * check if the domain identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if domain is valid, non zero otherwise
 */
static int _jid_safe_domain(jid id) {
    char *str;

    /* there must be a domain identifier */
    if (j_strlen(id->server) == 0)
	return 1;

    /* and it must not be longer than 1023 bytes */
    if (strlen(id->server) > 1023)
	return 1;

    /* lowercase the hostname, make sure it's valid characters */
    for (str = id->server; *str != '\0'; str++) {
        *str = tolower(*str);
        if (!(isalnum(*str) || *str == '.' || *str == '-' || *str == '_'))
	    return 1;
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
static int _jid_safe_node(jid id) {
    char *str;

    /* node identifiers may not be longer than 1023 bytes */
    if (j_strlen(id->user) > 1023)
	return 1;

    /* check for low and invalid ascii characters in the username */
    if (id->user != NULL)
        for (str = id->user; *str != '\0'; str++)
            if (*str <= 32 || *str == ':' || *str == '@' || *str == '<' || *str == '>' || *str == '\'' || *str == '"' || *str == '&')
		return 1;

    /* otherwise it's okay as far as we can tell without LIBIDN */
    return 0;
}

/**
 * check if the resource identifier in a JID is valid
 *
 * @param jid data structure holding the JID
 * @return 0 if resource is valid, non zero otherwise
 */
static int _jid_safe_resource(jid id) {
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
jid jid_safe(jid id) {
    if (_jid_safe_domain(id))
	return NULL;
    if (_jid_safe_node(id))
	return NULL;
    if (_jid_safe_resource(id))
	return NULL;

    return id;
}

/**
 * create a new jid
 *
 * This creates a new jid from a string
 *
 * @param p memory pool to use for this jid
 * @param environment the JID environment used to stringprep the JabberID
 * @param idstr the string containing the textual representation of the jid
 * @param len the length of the string (in characters)
 * @return the new jid
 */
jid jid_newx(pool p, jid_environment_t environment, const char *idstr, int len) {
    char *server, *resource, *type, *str;
    jid id;

    if (p == NULL || idstr == NULL || len <= 0)
        return NULL;

    /* user@server/resource */

    str = pstrdupx(p, idstr, len);
    id = pmalloco(p,sizeof(struct jid_struct));
    id->p = p;
    id->environment = environment;

    resource = strstr(str,"/");
    if (resource != NULL) {
        *resource = '\0';
        ++resource;
        if (strlen(resource) > 0)
            id->resource = resource;
    } else {
        resource = str + len; /* point to end */
    }

    type = strstr(str,":");
    if (type != NULL && type < resource) {
        *type = '\0';
        ++type;
        str = type; /* ignore the type: prefix */
    }

    server = strstr(str,"@");
    if (server == NULL || server > resource) {
	/* if there's no @, it's just the server address */
        id->server = str;
    } else {
        *server = '\0';
        ++server;
        id->server = server;
        if (len > 0)
            id->user = str;
    }

    return jid_safe(id);
}

/**
 * create a new jid
 *
 * This creates a new jid from a zero-terminated string
 *
 * @param p memory pool to use for this jid
 * @param environment the JID environment used to stringprep the JabberID
 * @param idstr the zero-terminated string containing the textual representation of the jid
 * @return the new jid
 */
jid jid_new(pool p, jid_environment_t environment, const char *idstr) {
    if (idstr == NULL)
	return NULL;
    return jid_newx(p, environment, idstr, strlen(idstr));
}

/**
 * set a specific component of a jid
 *
 * @param id the jid to modify
 * @param str the new value of the component
 * @param item the component to set (one of JID_USER, JID_SERVER, JID_RESOURCE)
 */
void jid_set(jid id, const char *str, int item) {
    char *old;

    if (id == NULL)
        return;

    /* invalidate the cached copy */
    id->full = NULL;

    switch (item) {
	case JID_RESOURCE:
	    old = id->resource;
	    if (str != NULL && strlen(str) != 0)
		id->resource = pstrdup(id->p, str);
	    else
		id->resource = NULL;
	    if (_jid_safe_resource(id))
		id->resource = old; /* revert if invalid */
	    break;
	case JID_USER:
	    old = id->user;
	    if (str != NULL && strlen(str) != 0)
		id->user = pstrdup(id->p, str);
	    else
		id->user = NULL;
	    if (_jid_safe_node(id))
		id->user = old; /* revert if invalid */
	    break;
	case JID_SERVER:
	    old = id->server;
	    id->server = pstrdup(id->p, str);
	    if (_jid_safe_domain(id))
		id->server = old; /* revert if invalid */
	    break;
    }

}

/**
 * get the textual representation of a jid
 *
 * @param id the jid to get the textual representation for
 * @return zero-terminated string
 */
char *jid_full(jid id) {
    spool s;

    if (id == NULL)
        return NULL;

    /* use cached copy */
    if (id->full != NULL)
        return id->full;

    s = spool_new(id->p);

    if (id->user != NULL)
        spooler(s, id->user,"@",s);

    spool_add(s, id->server);

    if (id->resource != NULL)
        spooler(s, "/",id->resource,s);

    id->full = spool_print(s);
    return id->full;
}

/* local utils */

/**
 * NULL-safe version of strcmp()
 *
 * @param a one string
 * @param b other string
 * @param if both a and b are NULL 0, if one of a or b are NULL -1, else the same as strcmp(a,b)
 */
static int _jid_nullstrcmp(char *a, char *b) {
    if (a == NULL && b == NULL)
	return 0;
    if (a == NULL || b == NULL)
	return -1;
    return strcmp(a,b);
}

/**
 * NULL-safe version of strcasecmp()
 *
 * @param a one string
 * @param b other string
 * @param if both a and b are NULL 0, if one of a or b are NULL -1, else the same as strcasecmp(a,b)
 */
static int _jid_nullstrcasecmp(char *a, char *b) {
    if (a == NULL && b == NULL)
	return 0;
    if (a == NULL || b == NULL)
	return -1;
    return strcasecmp(a,b);
}

/**
 * compare two JabberIDs if they are the same
 *
 * @param a the one jid
 * @param b the other jid
 * @return -1 if both JIDs are different, 0 if they are the same
 */
int jid_cmp(jid a, jid b) {
    if (a == NULL || b == NULL)
        return -1;

    if (_jid_nullstrcmp(a->resource, b->resource) != 0)
	return -1;
    if (_jid_nullstrcasecmp(a->user, b->user) != 0)
	return -1;
    if (_jid_nullstrcmp(a->server, b->server) != 0)
	return -1;

    return 0;
}

/* suggested by Anders Qvist <quest@valdez.netg.se> */
/**
 * compare parts of two JabberIDs if they are the same
 *
 * @param a the one jid
 * @param b the other jid
 * @param parts which parts of the JID should be compared, ORed values of JID_USER, JID_SERVER, and JID_RESOURCE
 * @return -1 if both JIDs are different in the selected parts, 0 if they are the same in the selected parts
 */
int jid_cmpx(jid a, jid b, int parts) {
    if (a == NULL || b == NULL)
        return -1;

    if (parts & JID_RESOURCE && _jid_nullstrcmp(a->resource, b->resource) != 0)
	return -1;
    if (parts & JID_USER && _jid_nullstrcasecmp(a->user, b->user) != 0)
	return -1;
    if (parts & JID_SERVER && _jid_nullstrcmp(a->server, b->server) != 0)
	return -1;

    return 0;
}

/**
 * append a copy of a JabberID to a list of JabberIDs
 *
 * This function appends a copy the JabberID b to a list of JabberIDs, that start with JabberID a.
 * The function checks, that the JabberID is not already contained in the list.
 *
 * The copy of b is created in the memory pool of a.
 * 
 * @param a start of the list of JabberIDs where a copy of b should be appended
 * @param b the JabberID that should be appended
 * @return new start jid of the list
 */
jid jid_append(jid a, jid b) {
    jid next;

    if (a == NULL)
        return NULL;

    if (b == NULL)
        return a;

    next = a;
    while (next != NULL) {
        /* check for dups */
        if (jid_cmp(next,b) == 0)
            break;
        if (next->next == NULL)
            next->next = jid_new(a->p, a->environment, jid_full(b));
        next = next->next;
    }
    return a;
}

/**
 * get a copy of a jid with the resource removed from the jid
 *
 * @param a the jid that should be copied without the resource
 * @return the copied JID with the resource removed
 */
jid jid_user(jid a) {
    jid ret;

    if (a == NULL || a->resource == NULL)
	return a;

    ret = pmalloco(a->p, sizeof(struct jid_struct));
    ret->p = a->p;
    ret->user = a->user;
    ret->server = a->server;

    return ret;
}
