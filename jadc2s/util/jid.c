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

#ifdef LIBIDN

#  include <stringprep.h>

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
    result = stringprep_nameprep_no_unassigned(id->server, strlen(id->server)+1);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nameprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->server);
	result = stringprep_nameprep_no_unassigned(biggerbuffer, biggerbuffersize);
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
    result = stringprep_xmpp_nodeprep(id->user, strlen(id->user)+1);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* nodeprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->user);
	result = stringprep_xmpp_nodeprep(biggerbuffer, biggerbuffersize);
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
    result = stringprep_xmpp_resourceprep(id->resource, strlen(id->resource)+1);
    if (result == STRINGPREP_TOO_SMALL_BUFFER) {
	/* resourceprep wants to expand the string, e.g. conversion from &szlig; to ss */
	size_t biggerbuffersize = 1024;
	char *biggerbuffer = pmalloc(id->p, biggerbuffersize);
	if (biggerbuffer == NULL)
	    return 1;
	strcpy(biggerbuffer, id->resource);
	result = stringprep_xmpp_resourceprep(biggerbuffer, biggerbuffersize);
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

jid jid_newx(pool p, char *idstr, int len)
{
    char *server, *resource, *type, *str;
    jid id;

    if(p == NULL || idstr == NULL || len <= 0)
        return NULL;

    /* user@server/resource */

    str = pstrdupx(p, idstr, len);
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
        resource = str + len; /* point to end */
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
        if(len > 0)
            id->user = str;
    }

    return jid_safe(id);
}

jid jid_new(pool p, char *idstr)
{
    if(idstr == NULL) return NULL;
    return jid_newx(p, idstr, strlen(idstr));
}

void jid_set(jid id, const char *str, int item)
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
