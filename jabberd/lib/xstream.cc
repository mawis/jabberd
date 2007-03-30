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
 * @file xstream.cc
 * @brief handling of incoming XML stream based events
 *
 * xstream is a way to have a consistent method of handling incoming XML stream based events ...
 * if doesn't handle the generation of an XML stream, but provides some facilities to help doing that
 *
 * Currently this is only used by base_stdout.c and the stream used by dnsrv to communicate with the
 * co-process. Other XML streams (c2s, s2s, components, ...) use XML streaming implemented in mio_xml.c.
 */

#include <jabberdlib.h>

#include <iostream>

/* ========== internal expat callbacks =========== */

/**
 * internal expat callback for read start tags of an element
 */
static void _xstream_startElement(void* _xs, const char* name, const char** atts) {
    xstream xs = static_cast<xstream>(_xs);
    std::string prefix;
    std::string ns_iri;
    std::string local_name;
    std::string qname(name ? name : "");

    // if we do not have a ns declaration list for the stanza yet create one by copying the root's ns_decl_list
    if (!xs->ns_stanza) {
	xs->ns_stanza = xs->ns_root ? new xmppd::ns_decl_list(*xs->ns_root) : new xmppd::ns_decl_list();
    }

    // get prefix and local name of the element
    std::string::size_type separator_pos = qname.find(XMLNS_SEPARATOR);
    if (separator_pos != std::string::npos) {
	ns_iri = qname.substr(0, separator_pos);
	local_name = qname.substr(separator_pos+1);
	try {
	    // XXX do we need to care about the prefix at all?
	    prefix = xs->ns_stanza->get_nsprefix(ns_iri);
	} catch (std::invalid_argument) {
	}
    } else {
	// expat could not expand the prefix, it's not declared
	//
	// ... be liberal in what you accept ...
	//
	// XXX do we really want to be?
	
	// start with a guess
	std::string::size_type colon_pos = qname.find(':');
	if (colon_pos != std::string::npos) {
	    prefix = qname.substr(0, colon_pos);
	    local_name = qname.substr(colon_pos+1);
	    ns_iri = "http://jabberd.org/ns/clue";

	    // some well known prefixes (but tehy would have to be declared!)
	    if (prefix == "stream") {
		ns_iri = NS_STREAM;
	    } else if (prefix == "db") {
		ns_iri = NS_DIALBACK;
	    }
	} else {
	    local_name = qname;
	    ns_iri = NS_SERVER;
	}
    }

    /* if xstream is bad, get outa here */
    if (xs->status > XSTREAM_NODE)
	return;

    if (xs->node == NULL) {
        pool p = pool_heap(5*1024); /* 5k, typically 1-2k each plus copy of self and workspace */
        xs->node = xmlnode_new_tag_pool_ns(p, local_name.c_str(), prefix=="" ? NULL : prefix.c_str(), ns_iri.c_str());
        xmlnode_put_expat_attribs(xs->node, atts, *xs->ns_stanza);

        if (xs->status == XSTREAM_ROOT) {
	    const char *prefix = NULL;

            xs->root_lang = pstrdup(xs->p, xmlnode_get_lang(xs->node));

            /* move the namespace list to where we look for the root namespace list */
	    xs->ns_root = xs->ns_stanza;
	    xs->ns_stanza = NULL;
	    
	    // for the root element: check if NS_SERVER, NS_CLIENT, NS_COMPONENT_ACCEPT, or NS_DIALBACK has been declared => add attribute explicitly
	    try {
		std::string prefix = xs->ns_root->get_nsprefix(NS_SERVER);
		xmlnode_put_attrib_ns(xs->node, prefix == "" ? "xmlns" : prefix.c_str(), prefix == "" ? NULL : "xmlns", NS_XMLNS, NS_SERVER);
	    } catch (std::invalid_argument) {
	    }
	    try {
		std::string prefix = xs->ns_root->get_nsprefix(NS_CLIENT);
		xmlnode_put_attrib_ns(xs->node, prefix == "" ? "xmlns" : prefix.c_str(), prefix == "" ? NULL : "xmlns", NS_XMLNS, NS_CLIENT);
	    } catch (std::invalid_argument) {
	    }
	    try {
		std::string prefix = xs->ns_root->get_nsprefix(NS_COMPONENT_ACCEPT);
		xmlnode_put_attrib_ns(xs->node, prefix == "" ? "xmlns" : prefix.c_str(), prefix == "" ? NULL : "xmlns", NS_XMLNS, NS_COMPONENT_ACCEPT);
	    } catch (std::invalid_argument) {
	    }
	    try {
		std::string prefix = xs->ns_root->get_nsprefix(NS_DIALBACK);
		xmlnode_put_attrib_ns(xs->node, prefix == "" ? "xmlns" : prefix.c_str(), prefix == "" ? NULL : "xmlns", NS_XMLNS, NS_DIALBACK);
	    } catch (std::invalid_argument) {
	    }

            xs->status = XSTREAM_NODE; /* flag status that we're processing nodes now */
            (xs->f)(XSTREAM_ROOT, xs->node, xs->arg); /* send the root, f must free all nodes */
            xs->node = NULL;
        }
    } else {
        xs->node = xmlnode_insert_tag_ns(xs->node, local_name.c_str(), prefix.c_str(), ns_iri.c_str());
        xmlnode_put_expat_attribs(xs->node, atts, *xs->ns_stanza);
    }

    /* depth check */
    xs->depth++;
    if(xs->depth > XSTREAM_MAXDEPTH)
        xs->status = XSTREAM_ERR;
}

/**
 * internal expat callback for read end tags of an element
 */
static void _xstream_endElement(void* _xs, const char* name) {
    xstream xs = static_cast<xstream>(_xs);
    xmlnode parent;

    /* if xstream is bad, get outa here */
    if (xs->status > XSTREAM_NODE)
	return;

    /* if it's already NULL we've received </stream>, tell the app and we're outta here */
    if (xs->node == NULL) {
        xs->status = XSTREAM_CLOSE;
        (xs->f)(XSTREAM_CLOSE, NULL, xs->arg);
    } else {
        parent = xmlnode_get_parent(xs->node);

        /* we are the top-most node, feed to the app who is responsible to delete it */
        if (parent == NULL) {
	    /* we do not need the list of namespaces for the stanza anymore */
	    delete xs->ns_stanza;
	    xs->ns_stanza = NULL;
	    
            (xs->f)(XSTREAM_NODE, xs->node, xs->arg);
	}

        xs->node = parent;
    }
    xs->depth--;
}

/**
 * internal expat callback for read CDATA
 */
static void _xstream_charData(void* _xs, const char *str, int len) {
    xstream xs = static_cast<xstream>(_xs);

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
    xstream xs = static_cast<xstream>(arg);

    // create a new ns_decl_list if necessary, and copy what namespaces we already have on the root element
    if (!xs->ns_stanza) {
	xs->ns_stanza = xs->ns_root ? new xmppd::ns_decl_list(*xs->ns_root) : new xmppd::ns_decl_list();
    }

    // add the new prefix to the list
    xs->ns_stanza->update(prefix ? prefix : "", iri ? iri : "");
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
    xstream xs = static_cast<xstream>(arg);

    // remove the prefix from the list of namespaces
    if (xs->ns_stanza)
	xs->ns_stanza->delete_last(prefix ? prefix : "");
}

/**
 * internal function to be registered as pool cleaner, frees a stream if the associated memory pool is freed
 *
 * @param pointer to the xstream to free
 */
static void _xstream_cleanup(void *arg) {
    xstream xs = (xstream)arg;

    xmlnode_free(xs->node); /* cleanup anything left over */
    XML_ParserFree(xs->parser);

    // cleanup lists of namespace declarations
    if (xs->ns_stanza) {
	delete xs->ns_stanza;
	xs->ns_stanza = NULL;
    }
    if (xs->ns_root) {
	delete xs->ns_root;
	xs->ns_root = NULL;
    }
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

    if (p == NULL || f == NULL) {
        fprintf(stderr,"Fatal Programming Error: xstream_new() was improperly called with NULL.\n");
        return NULL;
    }

    newx = static_cast<xstream>(pmalloco(p, sizeof(_xstream)));
    newx->p = p;
    newx->f = f;
    newx->arg = arg;

    /* create expat parser and ensure cleanup */
    newx->parser = XML_ParserCreateNS(NULL, XMLNS_SEPARATOR);
    XML_SetUserData(newx->parser, (void *)newx);
    XML_SetElementHandler(newx->parser, _xstream_startElement, _xstream_endElement);
    XML_SetCharacterDataHandler(newx->parser, _xstream_charData);
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
int xstream_eat(xstream xs, char *buff, int len) {
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
    if(xs->status == XSTREAM_ERR) {
        xerr = xmlnode_new_tag_ns("error", NULL, NS_SERVER);
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

    x = xmlnode_new_tag_ns("stream", "stream", NS_STREAM);
    xmlnode_put_attrib_ns(x, "id", NULL, NULL, id);
    xmlnode_put_attrib_ns(x, "xmlns", NULL, NS_XMLNS, NS_SERVER);
    if(to != NULL)
        xmlnode_put_attrib_ns(x, "to", NULL, NULL, to);
    if(from != NULL)
        xmlnode_put_attrib_ns(x, "from", NULL, NULL, from);

    return x;
}

/**
 * trim the xmlnode to only the opening header :)
 *
 * @note NO CHILDREN ALLOWED
 *
 * @note this function does ignore most explicit declarations of namespace prefixes.
 * The only exceptions are explicit declarations of the default namespace, or the
 * namespace defined by the prefix 'db'
 *
 * @param x the xmlnode
 * @param stream_type 0 for 'jabber:server', 1 for 'jabber:client', 2 for 'jabber:component:accept'
 * @return string representation of the start tag
 */
char *xstream_header_char(xmlnode x, int stream_type) {
    if (xmlnode_has_children(x)) {
	std::cerr << "Fatal programming error: xstream_header_char() was sent a header with children!" << std::endl;
	return NULL;
    }

    std::string head = "<?xml version='1.0'?>";
    head += xmlnode_serialize_string(x, xmppd::ns_decl_list(), stream_type);
    head = head.substr(0, head.find("/>"));

    char const* default_namespace = xmlnode_get_attrib_ns(x, "xmlns", NS_XMLNS);
    if (default_namespace) {
	if (stream_type && std::string(default_namespace) == NS_SERVER) {
	    default_namespace = stream_type == 1 ? NS_CLIENT : stream_type == 2 ? NS_COMPONENT_ACCEPT : NS_SERVER;
	}
	head += " xmlns='" + strescape(default_namespace) + "'";
    }
    char const* db_namespace = xmlnode_get_attrib_ns(x, "db", NS_XMLNS);
    if (db_namespace) {
	head += " xmlns:db='" + strescape(db_namespace) + "'";
    }

    head += ">";

    return pstrdup(xmlnode_pool(x), head.c_str());
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
	if (j_strcmp(xmlnode_get_namespace(cur), NS_XMPP_STREAMS) != 0)
	    continue;

	/* check which element it is */
	name = pstrdup(xmlnode_pool(cur), xmlnode_get_localname(cur));
	if (j_strcmp(name, "text") == 0) {
	    if (errstruct->text == NULL) {
		errstruct->text = pstrdup(p, xmlnode_get_data(cur));
		errstruct->lang = pstrdup(p, xmlnode_get_lang(cur));
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
