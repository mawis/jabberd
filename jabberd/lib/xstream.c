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
 * @file xstream.c
 * @brief handling of incoming XML stream based events
 *
 * xstream is a way to have a consistent method of handling incoming XML stream based events ...
 * if doesn't handle the generation of an XML stream, but provides some facilities to help doing that
 *
 * Currently this is only used by base_stdout.c and the stream used by dnsrv to communicate with the
 * co-process. Other XML streams (c2s, s2s, components, ...) use XML streaming implemented in mio_xml.c.
 */

#include <jabberdlib.h>

/* ========== internal expat callbacks =========== */

/**
 * internal expat callback for read start tags of an element
 */
void _xstream_startElement(xstream xs, const char* name, const char** atts) {
    pool p = NULL;
    char *prefix = NULL;
    char *ns_iri = NULL;
    char *local_name = NULL;

    /* create a new memory pool if necessary, and copy what namespaces we already have on the root element */
    if (xs->ns_pool == NULL) {
        xs->ns_pool = pool_new();
        xmlnode_copy_decl_list(xs->ns_pool, xs->first_ns_root, &(xs->first_ns_stanza), &(xs->last_ns_stanza));
    }

    /* get prefix, iri, and local name of the element */
    if (strchr(name, XMLNS_SEPARATOR) != NULL) {
        /* expat found the namespace IRI for us */
        ns_iri = pstrdup(xs->ns_pool, name);
        local_name = strchr(ns_iri, XMLNS_SEPARATOR);
        local_name[0] = 0;
        local_name++;
        prefix = pstrdup(xs->ns_pool, xmlnode_list_get_nsprefix(xs->last_ns_stanza, ns_iri));
    } else if (strchr(name, ':') != NULL) {
        /* expat could not expand the prefix, it's not declared */

        /* ... be liberal in what you accept ... */

        /* start with a guess */
        prefix = pstrdup(xs->ns_pool, name);
        local_name = strchr(prefix, ':');
        local_name[0] = 0;
        local_name++;
        ns_iri = "http://jabberd.org/no/clue";

        /* some well known prefixes (but they would have to been declared!) */
        if (j_strcmp(prefix, "stream") == 0) {
            ns_iri = NS_STREAM;
        } else if (j_strcmp(prefix, "db") == 0) {
            ns_iri = NS_DIALBACK;
        }
    } else {
        /* default namespace, but not declared */

        /* ... be liberal in what you accept ... (guessing it's 'jabber:server') */
        prefix = NULL;
        ns_iri = "jabber:server";
        local_name = pstrdup(xs->ns_pool, name);
    }

    if (prefix != NULL && prefix[0] == '\0')
        prefix = NULL;


    /* if xstream is bad, get outa here */
    if(xs->status > XSTREAM_NODE) return;

    if(xs->node == NULL) {
        p = pool_heap(5*1024); /* 5k, typically 1-2k each plus copy of self and workspace */
        xs->node = xmlnode_new_tag_pool_ns(p, local_name, prefix, ns_iri);
        xmlnode_put_expat_attribs(xs->node, atts, xs->last_ns_stanza);

        if(xs->status == XSTREAM_ROOT) {
	    const char *prefix = NULL;

            xs->root_lang = pstrdup(xs->p, xmlnode_get_lang(xs->node));

            /* move the namespace list to where we look for the root namespace list */
            xmlnode_copy_decl_list(xs->p, xs->first_ns_stanza, &(xs->first_ns_root), &(xs->last_ns_root));
            pool_free(xs->ns_pool);
            xs->ns_pool = NULL;

            /* for the root element: check if NS_SERVER, NS_CLIENT, NS_COMPONENT_ACCEPT, or NS_DIALBACK has been declared => add explicitly */
            if (prefix = xmlnode_list_get_nsprefix(xs->last_ns_root, NS_SERVER))
                xmlnode_put_attrib_ns(xs->node, prefix && prefix[0] ? prefix : "xmlns", prefix && prefix[0] ? "xmlns" : NULL, NS_XMLNS, NS_SERVER);
            if (prefix = xmlnode_list_get_nsprefix(xs->last_ns_root, NS_CLIENT))
                xmlnode_put_attrib_ns(xs->node, prefix && prefix[0] ? prefix : "xmlns", prefix && prefix[0] ? "xmlns" : NULL, NS_XMLNS, NS_CLIENT);
            if (prefix = xmlnode_list_get_nsprefix(xs->last_ns_root, NS_COMPONENT_ACCEPT))
                xmlnode_put_attrib_ns(xs->node, prefix && prefix[0] ? prefix : "xmlns", prefix && prefix[0] ? "xmlns" : NULL, NS_XMLNS, NS_COMPONENT_ACCEPT);
            if (prefix = xmlnode_list_get_nsprefix(xs->last_ns_root, NS_DIALBACK))
                xmlnode_put_attrib_ns(xs->node, prefix && prefix[0] ? prefix : "xmlns", prefix && prefix[0] ? "xmlns" : NULL, NS_XMLNS, NS_DIALBACK);

            xs->status = XSTREAM_NODE; /* flag status that we're processing nodes now */
            (xs->f)(XSTREAM_ROOT, xs->node, xs->arg); /* send the root, f must free all nodes */
            xs->node = NULL;
        }
    }else{
        xs->node = xmlnode_insert_tag(xs->node, name);
        xmlnode_put_expat_attribs(xs->node, atts, xs->last_ns_stanza);
    }

    /* depth check */
    xs->depth++;
    if(xs->depth > XSTREAM_MAXDEPTH)
        xs->status = XSTREAM_ERR;
}

/**
 * internal expat callback for read end tags of an element
 */
void _xstream_endElement(xstream xs, const char* name) {
    xmlnode parent;

    /* if xstream is bad, get outa here */
    if(xs->status > XSTREAM_NODE) return;

    /* if it's already NULL we've received </stream>, tell the app and we're outta here */
    if(xs->node == NULL)
    {
        xs->status = XSTREAM_CLOSE;
        (xs->f)(XSTREAM_CLOSE, NULL, xs->arg);
    }else{
        parent = xmlnode_get_parent(xs->node);

        /* we are the top-most node, feed to the app who is responsible to delete it */
        if(parent == NULL) {
	    /* we do not need the list of namespaces for the stanza anymore */
	    pool_free(xs->ns_pool);
	    xs->ns_pool = NULL;
	    xs->first_ns_stanza = NULL;
	    xs->last_ns_stanza = NULL;
	    
            (xs->f)(XSTREAM_NODE, xs->node, xs->arg);
	}

        xs->node = parent;
    }
    xs->depth--;
}

/**
 * internal expat callback for read CDATA
 */
void _xstream_charData(xstream xs, const char *str, int len) {
    /* if xstream is bad, get outa here */
    if(xs->status > XSTREAM_NODE) return;

    if(xs->node == NULL)
    {
        /* we must be in the root of the stream where CDATA is irrelevant */
        return;
    }

    xmlnode_insert_cdata(xs->node, str, len);
}

/**
 * callback function for the beginning of a namespace declaration
 *
 * This function will insert a new namespace prefix in the list of declared namespaces
 *
 * @param arg xs the callback is related to
 * @param prefix prefix that gets declared
 * @param iri namespace IRI for this prefix
 */
static void _xstream_startNamespaceDecl(void *arg, const XML_Char *prefix, const XML_Char *iri) {
    xstream xs = (xstream)arg;

    /* create a new memory pool if necessary, and copy what namespaces we already have on the root element */
    if (xs->ns_pool == NULL) {
        xs->ns_pool = pool_new();
        xmlnode_copy_decl_list(xs->ns_pool, xs->first_ns_root, &(xs->first_ns_stanza), &(xs->last_ns_stanza));
    }

    /* store the new prefix in the list */
    xmlnode_update_decl_list(xs->ns_pool, &(xs->first_ns_stanza), &(xs->last_ns_stanza), prefix, iri);
}

/**
 * callback function for the end of the scope of a declared namespace prefix
 *
 * This function will insert the last occurance of the prefix from the list of declared namespaces
 *
 * @param arg xs the callback is related to
 * @param prefix prefix that gets undeclared
 */
static void _xstream_endNamespaceDecl(void *arg, const XML_Char *prefix) {
    xstream xs = (xstream)arg;

    /* remove the prefix from the list */
    xmlnode_delete_last_decl(&(xs->first_ns_stanza), &(xs->last_ns_stanza), prefix);
}

/**
 * internal function to be registered as pool cleaner, frees a stream if the associated memory pool is freed
 *
 * @param pointer to the xstream to free
 */
void _xstream_cleanup(void *arg) {
    xstream xs = (xstream)arg;

    xmlnode_free(xs->node); /* cleanup anything left over */
    XML_ParserFree(xs->parser);

    if (xs->ns_pool != NULL) {
	pool_free(xs->ns_pool);
    }
    xs->ns_pool = NULL;
    xs->first_ns_stanza = NULL;
    xs->last_ns_stanza = NULL;
    xs->first_ns_root = NULL;
    xs->last_ns_root = NULL;
}


/**
 * creates a new xstream with given pool, xstream will be cleaned up w/ pool
 *
 * @param p the memory pool to use for the stream
 * @param f function pointer to the event handler function
 * @param arg parameter to pass to the event handler function
 * @return the created xstream
 */
xstream xstream_new(pool p, xstream_onNode f, void *arg) {
    xstream newx;

    if(p == NULL || f == NULL)
    {
        fprintf(stderr,"Fatal Programming Error: xstream_new() was improperly called with NULL.\n");
        return NULL;
    }

    newx = pmalloco(p, sizeof(_xstream));
    newx->p = p;
    newx->f = f;
    newx->arg = arg;

    /* create expat parser and ensure cleanup */
    newx->parser = XML_ParserCreateNS(NULL, XMLNS_SEPARATOR);
    XML_SetUserData(newx->parser, (void *)newx);
    XML_SetElementHandler(newx->parser, (void *)_xstream_startElement, (void *)_xstream_endElement);
    XML_SetCharacterDataHandler(newx->parser, (void *)_xstream_charData);
    XML_SetNamespaceDeclHandler(newx->parser, _xstream_startNamespaceDecl, _xstream_endNamespaceDecl);
    pool_cleanup(p, _xstream_cleanup, (void *)newx);

    return newx;
}

/**
 * attempts to parse the buff onto this stream firing events to the handler
 *
 * @param xs the xstream to parse the data on
 * @param buff the new data
 * @param len length of the data
 * @return last known xstream status
 */
int xstream_eat(xstream xs, char *buff, int len)
{
    char *err;
    xmlnode xerr;
    static char maxerr[] = "maximum node size reached";
    static char deeperr[] = "maximum node depth reached";

    if(xs == NULL)
    {
        fprintf(stderr,"Fatal Programming Error: xstream_eat() was improperly called with NULL.\n");
        return XSTREAM_ERR;
    }

    if(len == 0 || buff == NULL)
        return xs->status;

    if(len == -1) /* easy for hand-fed eat calls */
        len = strlen(buff);

    if(!XML_Parse(xs->parser, buff, len, 0))
    {
        err = (char *)XML_ErrorString(XML_GetErrorCode(xs->parser));
        xs->status = XSTREAM_ERR;
    }else if(pool_size(xmlnode_pool(xs->node)) > XSTREAM_MAXNODE || xs->cdata_len > XSTREAM_MAXNODE){
        err = maxerr;
        xs->status = XSTREAM_ERR;
    }else if(xs->status == XSTREAM_ERR){ /* set within expat handlers */
        err = deeperr;
    }

    /* fire parsing error event, make a node containing the error string */
    if(xs->status == XSTREAM_ERR)
    {
        xerr = xmlnode_new_tag("error");
        xmlnode_insert_cdata(xerr,err,-1);
        (xs->f)(XSTREAM_ERR, xerr, xs->arg);
    }

    return xs->status;
}


/* STREAM CREATION UTILITIES */

/** give a standard template xmlnode to work from 
 *
 * @param to where the stream is sent to
 * @param from where we are (source of the stream)
 * @return the xmlnode that has been generated as the template
 */
xmlnode xstream_header(const char *to, const char *from) {
    xmlnode x;
    char id[41];

    snprintf(id, sizeof(id), "%08X%08X%08X%08X%08X", rand(), rand(), rand(), rand(), rand());
    shahash_r(id, id); /* don't let them see what our rand() returns */

    x = xmlnode_new_tag("stream:stream");
    xmlnode_put_attrib(x, "xmlns:stream", NS_STREAM);
    xmlnode_put_attrib(x, "id", id);
    xmlnode_put_attrib(x, "xmlns", NS_SERVER);
    if(to != NULL)
        xmlnode_put_attrib(x, "to", to);
    if(from != NULL)
        xmlnode_put_attrib(x, "from", from);

    return x;
}

/**
 * trim the xmlnode to only the opening header :)
 *
 * @note NO CHILDREN ALLOWED
 *
 * @param x the xmlnode
 * @param stream_type 0 for 'jabber:server', 1 for 'jabber:client', 2 for 'jabber:component:accept'
 * @return string representation of the start tag
 */
char *xstream_header_char(xmlnode x, int stream_type) {
    spool s;
    char *fixr, *head;

    if(xmlnode_has_children(x)) {
        fprintf(stderr,"Fatal Programming Error: xstream_header_char() was sent a header with children!\n");
        return NULL;
    }

    s = spool_new(xmlnode_pool(x));
    spooler(s,"<?xml version='1.0'?>",xmlnode_serialize_string(x, NULL, NULL, stream_type),s);
    head = spool_print(s);
    fixr = strstr(head,"/>");
    *fixr = '>';
    ++fixr;
    *fixr = '\0';

    return head;
}

/**
 * format a stream error for logging
 *
 * @param s where to spool the result
 * @param errstruct the information about the error
 */
void xstream_format_error(spool s, streamerr errstruct) {
    /* sanity checks */
    if (s == NULL)
	return;
    if (errstruct == NULL) {
	spool_add(s, "stream:error=(NULL)");
	return;
    }

    switch (errstruct->reason) {
	case unknown_error_type:
	    spool_add(s, "unknown error type / legacy stream error");
	    break;
	case bad_format:
	    spool_add(s, "sent XML that cannot be processed");
	    break;
	case bad_namespace_prefix:
	    spool_add(s, "sent a namespace prefix that is unsupported");
	    break;
	case conflict:
	    spool_add(s, "new stream has been initiated that confilicts with the existing one");
	    break;
	case connection_timeout:
	    spool_add(s, "not generated any traffic over some time");
	    break;
	case host_gone:
	    spool_add(s, "hostname is no longer hosted by the server");
	    break;
	case host_unknown:
	    spool_add(s, "hostname is not hosted by the server");
	    break;
	case improper_addressing:
	    spool_add(s, "stanza lacks a 'to' or 'from' attribute");
	    break;
	case internal_server_error:
	    spool_add(s, "internal server error: maybe missconfiguration");
	    break;
	case invalid_from:
	    spool_add(s, "from address does not match an authorized JID or validated domain");
	    break;
	case invalid_id:
	    spool_add(s, "stream or dialback id is invalid or does not match a previous one");
	    break;
	case invalid_namespace:
	    spool_add(s, "invalid namespace");
	    break;
	case invalid_xml:
	    spool_add(s, "sent invalid XML, did not pass validation");
	    break;
	case not_authorized:
	    spool_add(s, "tried to send data before stream has been authed");
	    break;
	case policy_violation:
	    spool_add(s, "policy violation");
	    break;
	case remote_connection_failed:
	    spool_add(s, "remote connection failed");
	    break;
	case resource_constraint:
	    spool_add(s, "server lacks resources to service the stream");
	    break;
	case restricted_xml:
	    spool_add(s, "sent XML features that are forbidden by RFC3920");
	    break;
	case see_other_host:
	    spool_add(s, "redirected to other host");
	    break;
	case system_shutdown:
	    spool_add(s, "system is being shut down");
	    break;
	case undefined_condition:
	    spool_add(s, "undefined condition");
	    break;
	case unsupported_encoding:
	    spool_add(s, "unsupported encoding");
	    break;
	case unsupported_stanza_type:
	    spool_add(s, "sent a first-level child element (stanza) that is not supported");
	    break;
	case unsupported_version:
	    spool_add(s, "unsupported stream version");
	    break;
	case xml_not_well_formed:
	    spool_add(s, "sent XML that is not well-formed");
	    break;
	default:
	    spool_add(s, "something else (shut not happen)");
	    break;
    }

    if (errstruct->text != NULL) {
	spool_add(s, ": ");
	if (errstruct->lang != NULL) {
	    spool_add(s, "[");
	    spool_add(s, errstruct->lang);
	    spool_add(s, "]");
	}
	spool_add(s, errstruct->text);
    }
}

/**
 * parse a received stream error
 *
 * @param p memory pool used to allocate memory for strings
 * @param errnode the xmlnode containing the stream error
 * @param errstruct where to place the results
 * @return severity of the stream error
 */
streamerr_severity xstream_parse_error(pool p, xmlnode errnode, streamerr errstruct) {
    xmlnode cur = NULL;

    /* sanity checks */
    if (errstruct == NULL || p == NULL || errnode == NULL)
	return error;

    /* init the error structure */
    errstruct->text = NULL;
    errstruct->lang = NULL;
    errstruct->reason = unknown_error_type;
    errstruct->severity = error;

    /* iterate over the nodes in the stream error */
    for (cur = xmlnode_get_firstchild(errnode); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	char *ns = NULL;
	char *name = NULL;

	/* direct CDATA? Then it might be a preXMPP stream error */
	if (xmlnode_get_type(cur) == NTYPE_CDATA) {
	    /* only if we did not receive a text element yet */
	    if (errstruct->text == NULL) {
		errstruct->text = pstrdup(p, xmlnode_get_data(cur));
	    }
	    continue;
	}

	/* else we only care about elements */
	if (xmlnode_get_type(cur) != NTYPE_TAG)
	    continue;

	/* only handle the relevant namespace */
	ns = xmlnode_get_attrib(cur, "xmlns");
	if (ns == NULL)
	    continue;
	if (j_strcmp(ns, NS_XMPP_STREAMS) != 0)
	    continue;

	/* check which element it is */
	name = xmlnode_get_name(cur);
	if (j_strcmp(name, "text") == 0) {
	    if (errstruct->text == NULL) {
		errstruct->text = pstrdup(p, xmlnode_get_data(cur));
		errstruct->lang = pstrdup(p, xmlnode_get_attrib(cur, "xml:lang"));
	    }
	} else if (j_strcmp(name, "bad-format") == 0) {
	    errstruct->reason = bad_format;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "bad-namespace-prefix") == 0) {
	    errstruct->reason = bad_namespace_prefix;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "conflict") == 0) {
	    errstruct->reason = conflict;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "connection-timeout") == 0) {
	    errstruct->reason = connection_timeout;
	    errstruct->severity = normal;
	} else if (j_strcmp(name, "host-gone") == 0) {
	    errstruct->reason = host_gone;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "host-unknown") == 0) {
	    errstruct->reason = host_unknown;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "improper-addressing") == 0) {
	    errstruct->reason = improper_addressing;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "internal-server-error") == 0) {
	    errstruct->reason = internal_server_error;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "invalid-from") == 0) {
	    errstruct->reason = invalid_from;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "invalid-id") == 0) {
	    errstruct->reason = invalid_id;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "invalid-namespace") == 0) {
	    errstruct->reason = invalid_namespace;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "invalid-xml") == 0) {
	    errstruct->reason = invalid_xml;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "not-authorized") == 0) {
	    errstruct->reason = not_authorized;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "policy-violation") == 0) {
	    errstruct->reason = policy_violation;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "remote-connection-failed") == 0) {
	    errstruct->reason = remote_connection_failed;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "resource-constraint") == 0) {
	    errstruct->reason = resource_constraint;
	    errstruct->severity = normal;
	} else if (j_strcmp(name, "restricted-xml") == 0) {
	    errstruct->reason = restricted_xml;
	    errstruct->severity = error;
	} else if (j_strcmp(name, "see-other-host") == 0) {
	    errstruct->reason = see_other_host;
	    errstruct->severity = configuration;
	} else if (j_strcmp(name, "system-shutdown") == 0) {
	    errstruct->reason = system_shutdown;
	    errstruct->severity = normal;
	} else if (j_strcmp(name, "undefined-condition") == 0) {
	    errstruct->reason = undefined_condition;
	    errstruct->severity = unknown;
	} else if (j_strcmp(name, "unsupported-encoding") == 0) {
	    errstruct->reason = unsupported_encoding;
	    errstruct->severity = feature_lack;
	} else if (j_strcmp(name, "unsupported-stanza-type") == 0) {
	    errstruct->reason = unsupported_stanza_type;
	    errstruct->severity = feature_lack;
	} else if (j_strcmp(name, "unsupported-version") == 0) {
	    errstruct->reason = unsupported_version;
	    errstruct->severity = feature_lack;
	} else if (j_strcmp(name, "xml-not-well-formed") == 0) {
	    errstruct->reason = xml_not_well_formed;
	    errstruct->severity = error;
	}
    }

    return errstruct->severity;
}
