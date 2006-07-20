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
 * @file clients.c
 * @brief provides most of the functionality to handle client connections
 */

#include "jadc2s.h"

static char header_start[] = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'";
#ifdef FLASH_HACK
static char header_start_flash[] = "<flash:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' xmlns:flash='http://www.jabber.com/streams/flash'";
#endif

/**
 * check if the host is contained in a list of hosts
 *
 * @param config a configuration element containing valid hosts or valid aliases
 * @param host the host which should be checked
 * @return -1 if host invalid, if valid the index in the configuration is returned
 * */
int _client_check_in_hostlist(config_elem_t config, const char* host)
{
    int id;

    if (config == NULL || host == NULL)
	return -1;

    /* iterate over the valid hosts and compare */
    for (id = 0; id < config->nvalues; id++)
	if (j_strcmp(host, config->values[id]) == 0)
	    return id;

    /* nothing found, it is invalid */
    return -1;
}

/**
 * process the to attribute of the incoming stream root element
 *
 * @param c the connection of the stream
 * @param value the value of the attribute
 * @return 1 if we don't have to further process this element, 0 else
 */
int _client_root_attribute_to(conn_t c, const char *value) {
    int id;

    log_debug(ZONE, "checking to: %s", value);

    /* check if the to attribute is a real host */
    id = _client_check_in_hostlist(c->c2s->local_id, value);
    if (id != -1)
    {
	c->local_id = c->c2s->local_id->values[id];
	log_debug(ZONE, "matched local id '%s''", c->local_id);
    }

    /* if host not yet confirmed, check if there is an alias */
    if (c->local_id == NULL)
    {
	id = _client_check_in_hostlist(c->c2s->local_alias, value);
	if (id != -1)
	{
	    if (c->c2s->local_alias->attrs == NULL)
	    {
		log_write(c->c2s->log, LOG_ERR, "missing to attribute in configuration for alias %s", value);
	    }
	    else
	    {
		c->local_id = j_attr((const char **)c->c2s->local_alias->attrs[id], "to");
		log_debug(ZONE, "aliased requested id '%s' to '%s'", value, c->local_id);
	    }
	}
    }

    if (c->local_id == NULL)
    {
	/* send the stream error */
	conn_error(c, STREAM_ERR_HOST_UNKNOWN, "Invalid to address");
	c->depth = -1;
	return 1;
    }

    /* set the SASL default realm */
#ifdef WITH_SASL
    if (c->sasl_conn != NULL) {
	int sasl_result = 0;

	sasl_result = sasl_setprop(c->sasl_conn, SASL_DEFUSERREALM, c->local_id);
	if (sasl_result != SASL_OK) {
	    log_write(c->c2s->log, LOG_ERR, "could not set default SASL user realm to %s: %i", c->local_id, sasl_result);
	}
    }
#endif

    return 0;
}

/**
 * process the xmlns 'attribute' of the incoming stream root element
 *
 * @param c the connection of the stream
 * @param value the value of the attribute
 * @return 1 if we don't have to further process this element, 0 else
 */
int _client_root_attribute_xmlns(conn_t c, const char *value) {
    log_debug(ZONE, "checking xmlns: %s", value);

    if (j_strcmp(value, "jabber:client") != 0)
    {
	/* send the stream error */
	conn_error(c, STREAM_ERR_INVALID_NAMESPACE, "Invalid namespace, should be using jabber:client");
	c->depth = -1;
	return 1;
    }
    return 0;
}

/**
 * process the version attribute of the incoming stream root element
 *
 * @param c the connection of the stream
 * @param value the value of the attribute
 * @return 1 if we don't have to further process this element, 0 else
 */
int _client_root_attribute_version(conn_t c, const char *value) {
    int version = 0;

    /* stone age Jabber protocol */
    if (value == NULL) {
	return 0;
    }

    version = j_atoi(value, 0);
    if (version >= 1) {
	if (c->type == type_NORMAL) {
	    c->type = type_XMPP;
	} else {
	    /* only accept XMPP streams if no hacks are active */
	    conn_error(c, STREAM_ERR_BAD_FORMAT, "Please don't use HTTP headers or the Flash hack for XMPP streams");
	    c->depth = -1;
	    return 1;
	}
    }
    return 0;
}

#ifdef FLASH_HACK
/**
 * process the xmlns:flash 'attribute' of the incoming stream root element
 *
 * @param c the connection of the stream
 * @param value the value of the attribute
 * @return 1 if we don't have to further process this element, 0 else
 */
int _client_root_attribute_flash_ns(conn_t c, const char *value) {
    log_debug(ZONE, "checking xmlns:flash: %s", value);
    if (j_strcasecmp(value, "http://www.jabber.com/streams/flash") != 0) {
	/* send the stream error */
	conn_error(c, STREAM_ERR_INVALID_NAMESPACE, "Invalid flash:stream namespace");
	c->depth = -1;
	return 1;
    }

    return 0;
}
#endif

/**
 * process the xmlns:stream 'attribute' of the incoming stream root element
 *
 * @param c the connection of the stream
 * @param value the value of the attribute
 * @return 1 if we don't have to further process this element, 0 else
 */
int _client_root_attribute_stream_ns(conn_t c, const char *value) {
    log_debug(ZONE, "checking xmlns:stream: %s", value);
    if (j_strcasecmp(value, "http://etherx.jabber.org/streams") != 0) {
	/* send the stream error */
	conn_error(c, STREAM_ERR_INVALID_NAMESPACE, "Invalid stream namespace");
	c->depth = -1;
	return 1;
    }

    return 0;
}

/**
 * check if it is possible to start a TLS layer
 *
 * @param c the connection to be checked
 * @param host the host for which it should be checked
 * @return 1 if it is possible to start a TLS layer, 0 if not
 */
int _client_check_tls_possible(conn_t c, const char *host) {
#ifdef USE_SSL
    /* SSL/TLS already active? */
    if (c->ssl != NULL)
	return 0;

    /* is there an SSL context? */
    if (c->c2s->ssl_ctx == NULL)
	return 0;

    /* no reason why it shouldn't be possible */
    return 1;
#else
    /* without SSL/TLS support it's never possible */
    return 0;
#endif
}

/**
 * send our own stream root element to the client, for XMPP streams also send the stream features
 *
 * @param c the connection on which we will sent the root element
 */
void _client_stream_send_root(conn_t c) {
    char *header, *header_from, header_id[30];
    char sid[24];

    /* XXX fancier algo for id generation? */
    snprintf(sid, 24, "%d", rand());

    /* keep the generated session id ... we might need it for digest authentication */
    c->sid = strdup(sid);

    /* build our root element */
    header_from = malloc( 9 + strlen( c->local_id ) );
    sprintf(header_from, " from='%s'", c->local_id);

    sprintf(header_id, " id='%s'", sid);

    /* generate which stream header? */
    if (c->type == type_XMPP) {
	header = malloc( strlen(header_start) + strlen(header_from) + strlen(header_id) + 16);
	sprintf(header,"%s%s%s version='1.0'>",header_start,header_from,header_id);
	c->root_element = root_element_NORMAL;
#ifdef FLASH_HACK
    } else if (c->type == type_FLASH) {
	header = malloc( strlen(header_start_flash) + strlen(header_from) + strlen(header_id) + 3);
	sprintf(header,"%s%s%s/>",header_start_flash,header_from,header_id);
	c->root_element = root_element_FLASH;
#endif
    } else {
	header = malloc( strlen(header_start) + strlen(header_from) + strlen(header_id) + 2);
	sprintf(header,"%s%s%s>",header_start,header_from,header_id);
	c->root_element = root_element_NORMAL;
    }

    /* sent it to the client */
    _write_actual(c,c->fd,header,strlen(header));

    /* send stream features */
    if (c->type == type_XMPP) {
	_write_actual(c, c->fd, "<stream:features>", 17);
	if (c->sasl_state == state_auth_NONE && _client_check_in_hostlist(c->c2s->local_noregister, header_from) == -1)
	    _write_actual(c, c->fd, "<register xmlns='http://jabber.org/features/iq-register'/>", 58);
	if (c->sasl_state == state_auth_NONE && _client_check_in_hostlist(c->c2s->local_nolegacyauth, header_from) == -1 && (!c->c2s->sasl_enabled || c->c2s->sasl_jep0078))
	    _write_actual(c, c->fd, "<auth xmlns='http://jabber.org/features/iq-auth'/>", 50);
#ifdef USE_SSL
	if (c->sasl_state == state_auth_NONE && _client_check_tls_possible(c, header_from)) {
	    if (!c->c2s->tls_required)
		_write_actual(c, c->fd, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", 51);
	    else
		_write_actual(c, c->fd, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>", 72);
	}
#endif
#ifdef WITH_SASL
	if (c->c2s->sasl_enabled && c->sasl_conn != NULL && c->sasl_state == state_auth_NONE) { /* XXX send only if SASL not already done */
	    int sasl_result = 0;
	    const char *sasl_mechs = NULL;
	    unsigned sasl_mechs_len = 0;
	    int sasl_mech_count = 0;

	    sasl_result = sasl_listmech(c->sasl_conn, NULL, "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>", "</mechanism><mechanism>", "</mechanism></mechanisms>", &sasl_mechs, &sasl_mechs_len, &sasl_mech_count);
	    if (sasl_result != SASL_OK) {
		log_write(c->c2s->log, LOG_WARNING, "Problem getting available SASL mechanisms: %i", sasl_result);
	    } else if (sasl_mech_count == 0) {
		log_write(c->c2s->log, LOG_WARNING, "No SASL mechanisms available!");
	    } else {
		_write_actual(c, c->fd, sasl_mechs, sasl_mechs_len);
	    }
	} else if (c->c2s->sasl_enabled && c->sasl_state == state_auth_SASL_DONE) {
	    _write_actual(c, c->fd, "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>", 48);
	    _write_actual(c, c->fd, "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>", 54);
	}
#endif
	_write_actual(c, c->fd, "</stream:features>", 18);
    }

    /* free the memory we allocated */
    free(header);
    free(header_from);

    /* set up smid based on to="" host */
    c->userid = c->smid = jid_new(c->idp,c->c2s->jid_environment, c->local_id);
}

/**
 * process the stream root element of a newly opened stream
 *
 * @param c the connection on which the element has been received
 * @param name the name of the stream root element
 * @param atts the attributes on this element
 */
void _client_stream_root(conn_t c, const char *name, const char **atts) {
    int i=0, got_to_attrib=0, got_stanza_namespace=0, got_stream_namespace=0;
#ifdef FLASH_HACK
    int got_flash_namespace=0;

    /* check if it is a flash client, activate our flash hacks and
     * replace expat after <flash:stream/> has been processed */
    if (j_strcmp(name, "flash:stream") == 0)
    {
	/* enable our special handling of flash streams */
	c->type = type_FLASH;

	/* flag that we have to replace expat */
	c->flash_hack = 1;
    } else
#endif
	if (j_strcmp(name, "stream:stream") != 0) {

	    conn_error(c, STREAM_ERR_BAD_FORMAT, "Wrong root element for this XMPP stream.");

	    log_write(c->c2s->log, LOG_NOTICE, "Wrong root element on fd %i (%s)", c->fd, name);
	    c->depth = -1;
	    return;
	}

    /* Iterate over the attributes and test them
     * error tracks the required attributes in the header */
    while (atts[i] != '\0')
    {
	/* depending on the name of the attribute delegate to different functions */
	if (j_strcmp(atts[i], "to") == 0) {
	    if(_client_root_attribute_to(c, atts[i+1]))
		return;
	    got_to_attrib = 1;
	} else if (j_strcmp(atts[i], "xmlns") == 0) {
	    if (_client_root_attribute_xmlns(c, atts[i+1]))
		return;
	    got_stanza_namespace = 1;
#ifdef FLASH_HACK
	} else if (j_strcmp(atts[i], "xmlns:flash") == 0) {
	    if(_client_root_attribute_flash_ns(c, atts[i+1]))
		return;
	    got_flash_namespace = 1;
#endif
	} else if (j_strcmp(atts[i], "xmlns:stream") == 0) {
	    if(_client_root_attribute_stream_ns(c, atts[i+1]))
		return;
	    got_stream_namespace = 1;
	} else if (j_strcmp(atts[i], "version") == 0) {
	    if(_client_root_attribute_version(c, atts[i+1]))
		return;
	}

	/* move to the next attribute */
	i+=2;
    }

    /* check that we got what we need */

    /* if it is flash we don't need a namespace declaration for the stream prefix */
    if (c->type != type_FLASH && !got_stream_namespace)
    {
	conn_error(c, STREAM_ERR_INVALID_NAMESPACE, "Stream namespace not specified");

	log_write(c->c2s->log, LOG_DEBUG, "Stream namespace not specified in connection on fd %i", c->fd);
	c->depth = -1;
	return;
    }

#ifdef FLASH_HACK
    /* ... but we need a declaration of the flash prefix then */
    if (c->type == type_FLASH && !got_flash_namespace)
    {
	conn_error(c, STREAM_ERR_INVALID_NAMESPACE, "(Flash-)Stream namespace not specified");

	log_write(c->c2s->log, LOG_DEBUG, "(Flash-)Stream namespace not specified in connection on fd %i", c->fd);
	c->depth = -1;
	return;
    }
#endif
  
    if (!got_stanza_namespace)
    {
	conn_error(c, STREAM_ERR_INVALID_NAMESPACE, "Stanza namespace not specified");

	log_write(c->c2s->log, LOG_DEBUG, "Stanza namespace not specified in connection on fd %i", c->fd);
	c->depth = -1;
	return;
    }
    
    if (!got_to_attrib)
    {
	conn_error(c, STREAM_ERR_HOST_UNKNOWN, "No destination specified in to attribute");

	log_write(c->c2s->log, LOG_DEBUG, "To attribute missing in connection on fd %i", c->fd);
	c->depth = -1;
	return;
    }

    /* check the security strength factor of the TLS layer and pass to the SASL layer */
#ifdef WITH_SASL
#ifdef USE_SSL
    if (c->sasl_conn != NULL && c->ssl != NULL) {
	sasl_ssf_t tls_ssf = 0;
	int sasl_result = 0;

	tls_ssf = SSL_get_cipher_bits(c->ssl, NULL);
	sasl_result = sasl_setprop(c->sasl_conn, SASL_SSF_EXTERNAL, &tls_ssf);
	if (sasl_result != SASL_OK) {
	    log_write(c->c2s->log, LOG_WARNING, "Could not pass TLS security strength factor (%u) to SASL layer: %i", tls_ssf, sasl_result);
	}
    }
#endif
#endif
    
    /* send our stream root element */
    _client_stream_send_root(c);

    /* going one level deeper in the XML stream */
    c->depth++;

#ifdef FLASH_HACK
    /* The flash:stream ends in a /> so we need to hack around this... */
    if (c->type == type_FLASH)
	c->depth++;
#endif
}

/**
 * our callback for expat where it can signal new XML elements
 *
 * @param arg the connection for which this expat instance is parsing
 * @param name the name of the parsed element
 * @param atts the attributes in this element
 */
void _client_startElement(void *arg, const char* name, const char** atts)
{
    int i;
    conn_t c = (conn_t)arg;

    /* don't do anything if we're about to bail out */
    if(c->depth < 0)
        return;

#ifdef FLASH_HACK
    /* if it is the pseudo element we generated ourself, than we don't have to handle
     * this element
     */
    if (c->flash_hack == 1)
        return;
#endif

    /* process stream header first */
    if(c->depth == 0)
    {
	_client_stream_root(c, name, atts);
	return;
    }

    /* make a new nad if we don't already have one */
    if(c->nad == NULL)
        c->nad = nad_new(c->c2s->nads);

    /* append new element data to nad */
    nad_append_elem(c->nad, (char *) name, c->depth);
    for (i=0; atts[i] != '\0'; i += 2)
        nad_append_attr(c->nad, (char *) atts[i], (char *) atts[i+1]);

    /* going deeper */
    c->depth++;
}

/* prototype */
void _client_process(conn_t c);

/**
 * our callback for expat where it can signal closed XML elements
 *
 * @param arg the connection for which this expat instance is parsing
 * @param name the name of the parsed element
 */
void _client_endElement(void *arg, const char* name)
{
    conn_t c = (conn_t)arg;

    /* don't do anything if we're about to bail out */
    if(c->depth < 0)
        return;

    /* going up for air */
    c->depth--;

    /* if we are now on level 1, a stanza has been finished */
    if(c->depth == 1)
    {
        _client_process(c);
        if(c->nad != NULL)
        {   
            nad_free(c->nad);
            c->nad = NULL;
        }
    }

    /* if we processed the closing stream root, flag to close l8r */
    if(c->depth == 0)
        c->depth = -1; /* we can't close here, expat gets free'd on close :) */
}

/**
 * our callback for expat where it can signal read CDATA
 *
 * @param arg the connection for which this expat instance is parsing
 * @param str buffer with the CDATA that has been read
 * @param len number of bytes read by expat
 */
void _client_charData(void *arg, const char *str, int len)
{
    conn_t c = (conn_t)arg;

    /* don't do anything if we're about to bail out */
    if(c->depth < 0)
        return;

    /* if we're in the root of the stream the CDATA is irrelevant */
    if(c->nad == NULL) return;

    nad_append_cdata(c->nad, (char *) str, len, c->depth);
}

/**
 * process completed nads for stone age authentication
 * (every iq stanza as long as the session is not open)
 *
 * @param c the connection on which the nad has been received
 * @param chunk the chunk containing the nad
 * @return 1 if the packet need no further handling, 0 else
 */
int _client_process_stoneage_auth(conn_t c, chunk_t chunk) {
    int elem, attr, attr2;
    char str[3072]; /* see xmpp-core, 1023(node) + 1(@) + 1023(domain) + 1(/) + 1023(resource) + 1(\0) */

    /* get the handles of some attributes we need to check */
    attr = nad_find_attr(chunk->nad, 1, "xmlns", NULL);
    attr2 = nad_find_attr(chunk->nad, 0, "type", NULL);

    /* authorization request? */
    if (attr >= 0 && (j_strncmp(NAD_AVAL(chunk->nad, attr), "jabber:iq:auth", 14) == 0)) {
	/* sort out the username */
	elem = nad_find_elem(chunk->nad, 0, "username", 2);
	if(elem == -1) {
	    log_debug(ZONE, "auth packet with no username, dropping it");
	    chunk_free(chunk);
	    return 1;
	}
	
	snprintf(str, sizeof(str), "%.*s", NAD_CDATA_L(chunk->nad, elem), NAD_CDATA(chunk->nad, elem));
	jid_set(c->smid, str, JID_USER);

	/* and the resource, for sets */
	if(attr2 >= 0 && j_strncmp(NAD_AVAL(chunk->nad, attr2), "set", 3) == 0) {
	    elem = nad_find_elem(chunk->nad, 0, "resource", 2);
	    if(elem == -1) {
		log_debug(ZONE, "auth packet with no resource, dropping it");
		chunk_free(chunk);
		return 1;
	    }
	    
	    snprintf(str, sizeof(str), "%.*s", NAD_CDATA_L(chunk->nad, elem), NAD_CDATA(chunk->nad, elem));
	    jid_set(c->smid, str, JID_RESOURCE);

	    /* add the stream id to digest packets */
	    elem = nad_find_elem(chunk->nad, 0, "digest", 2);
	    if(elem >= 0 && c->sid != NULL)
		nad_set_attr(chunk->nad, elem, "sid", c->sid);
	    
	    /* we're in the auth state */
	    c->state = state_AUTH;
	}
    }
    /* registration request? */
    else if (attr >= 0 && attr2 >= 0 &&
	    ( (j_strncmp(NAD_AVAL(chunk->nad, attr), "jabber:iq:register", 18) == 0)
	      && (j_strncmp(NAD_AVAL(chunk->nad, attr2), "set", 3) == 0))) {
	/* sort out the username */
	elem = nad_find_elem(chunk->nad, 0, "username", 2);
	if(elem == -1)
	{
	    /* XXX send a stanza error */
	    log_debug(ZONE, "registration packet with no username, dropping it");
	    chunk_free(chunk);
	    return 1;
	}
	
	snprintf(str, sizeof(str), "%.*s", NAD_CDATA_L(chunk->nad, elem), NAD_CDATA(chunk->nad, elem));
	jid_set(c->smid, str, JID_USER);
    }

    /* if we have not returned yet, there is now a chunk that
     * should be transmitted to the session manager */
    return 0;
}

/**
 * process a SASL response from the client
 *
 * @param c the connection to work on
 * @param chunk the chunk received from the client
 */
void _client_do_sasl_step(conn_t c, chunk_t chunk) {
    char *client_response = NULL;
    unsigned client_response_len = 0;
    int sasl_result = 0;
    const char *server_out = NULL;
    unsigned server_out_len = 0;

    /* received what we expected? */
    if (j_strncmp(NAD_ENAME(chunk->nad, 0), "response", NAD_ENAME_L(chunk->nad, 0)) != 0) {
	conn_error(c, STREAM_ERR_NOT_AUTHORIZED, "expecting &lt;response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/&gt;");
	c->depth = -1; /* flag to close the connection */
	return;
    }

    /* is there response data? */
    if (NAD_CDATA_L(chunk->nad, 0) > 0) {
	client_response_len = (NAD_CDATA_L(chunk->nad, 0)+3)/4*3 + 1;

	client_response = (char*)malloc(client_response_len);
	sasl_result = sasl_decode64(NAD_CDATA(chunk->nad, 0), NAD_CDATA_L(chunk->nad, 0), client_response, client_response_len, &client_response_len);
	if (sasl_result != SASL_OK) {
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><incorrect-encoding/></failure></stream:stream>", 97);
	    log_write(c->c2s->log, LOG_NOTICE, "Problem decoding BASE64 data: %i", sasl_result);
	    c->depth = -1;	/* flag to close the connection */
	    if (client_response != NULL) {
		free(client_response);
		client_response = NULL;
	    }
	    return;
	}
    }

    /* doing SASL authentication */
    sasl_result = sasl_server_step(c->sasl_conn, client_response, client_response_len, &server_out, &server_out_len);
    if (client_response != NULL) {
	free(client_response);
	client_response = NULL;
    }
    switch (sasl_result) {
	case SASL_CONTINUE:
	case SASL_OK:
	    if (sasl_result == SASL_CONTINUE) {
		_write_actual(c, c->fd, "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>", 52);
	    } else {
		_write_actual(c, c->fd, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>", 50);
	    }
	    if (server_out_len > 0) {
		char *out_data_buffer = NULL;
		unsigned out_data_buffer_len = (server_out_len+2)/3*4 + 1;
		int sasl_result2 = 0;

		out_data_buffer = (char*)malloc(out_data_buffer_len);
		sasl_result2 = sasl_encode64(server_out, server_out_len, out_data_buffer, out_data_buffer_len, &out_data_buffer_len);
		if (sasl_result2 == SASL_OK) {
		    _write_actual(c, c->fd, out_data_buffer, out_data_buffer_len);
		}
		if (out_data_buffer != NULL)
		    free(out_data_buffer);
	    }
	    if (sasl_result == SASL_CONTINUE) {
		_write_actual(c, c->fd, "</challenge>", 12);
		c->state = state_SASL;
	    } else {
		const char *sasl_username = NULL;
		int sasl_result2 = 0;

		/* get the name of the authenticated user */
		sasl_result2 = sasl_getprop(c->sasl_conn, SASL_USERNAME, (const void**)&sasl_username);
		/* XXX we should not check that here, if that fails, we should not return success and drop the connection */
		if (sasl_result2 == SASL_OK) {
		    log_write(c->c2s->log, LOG_NOTICE, "SASL authentication successfull for user %s", sasl_username);
		    c->reset_stream = 1;
		    c->sasl_state = state_auth_SASL_DONE;

		    /* only username or username and realm? */
		    if (sasl_username != NULL && strchr(sasl_username, '@') != NULL) {
			c->authzid = jid_new(c->idp, c->c2s->jid_environment, sasl_username);
		    } else if (c->userid != NULL && c->userid->server != NULL) {
			c->authzid = jid_new(c->idp, c->c2s->jid_environment, c->userid ? c->userid->server : "");
			jid_set(c->authzid, sasl_username, JID_USER);
		    } else {
			c->authzid = NULL;
		    }

		    /* remember authentication id for logging */
		    c->userid = c->authzid;

		    /* did we get a valid JabberID? */
		    if (c->authzid == NULL) {
			/* no -> close connection */
			c->depth = -1;
		    }
		} else {
		    c->depth = -1; /* internal error? flag to close the connection */
		}

		_write_actual(c, c->fd, "</success>", 10);
	    }
	    break;
	case SASL_NOMECH:
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>", 96);
	    c->depth = -1;	/* flag to close the connection */
	    break;
	case SASL_TRYAGAIN:
	case SASL_NOTINIT:
	case SASL_TRANS:
	case SASL_EXPIRED:
	case SASL_BADVERS:
	case SASL_NOVERIFY:
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><temporary-auth-failure/></failure></stream:stream>", 101);
	    c->depth = -1;	/* flag to close the connection */
	    break;
	case SASL_NOAUTHZ:
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure></stream:stream>", 94);
	    log_write(c->c2s->log, LOG_NOTICE, "SASL authentication failure");
	    c->depth = -1;	/* flag to close the connection */
	    break;
	case SASL_TOOWEAK:
	case SASL_ENCRYPT:
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism-too-weak/></failure></stream:stream>", 97);
	    log_write(c->c2s->log, LOG_NOTICE, "SASL authentication failure");
	    c->depth = -1;	/* flag to close the connection */
	    break;
	default:
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure></stream:stream>", 93);
	    log_write(c->c2s->log, LOG_NOTICE, "SASL authentication failure");
	    c->depth = -1;	/* flag to close the connection */
    }
}

/**
 * process completed nads
 *
 * @param c the connection on which the nad has been received
 */
void _client_process(conn_t c) {
    chunk_t chunk;

    log_debug(ZONE, "got packet from client, processing");

    chunk = chunk_new(c);

    if (chunk->nad == NULL)
        return;
    
    log_debug(ZONE, "tag(%.*s)", NAD_ENAME_L(chunk->nad, 0), NAD_ENAME(chunk->nad, 0));

    /* handle stoneage auth requests */
    if((c->state != state_OPEN) && (j_strncmp(NAD_ENAME(chunk->nad, 0), "iq", NAD_ENAME_L(chunk->nad, 0)) == 0)) {
	if (_client_process_stoneage_auth(c, chunk))
	    return;
    }

    /* handle starttls */
    if ((c->state == state_NONE) && (j_strncmp(NAD_ENAME(chunk->nad, 0), "starttls", NAD_ENAME_L(chunk->nad, 0)) == 0)) {
#ifdef USE_SSL
	if (!_client_check_tls_possible(c, c->local_id)) {
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>", 66);
	    c->depth = -1;	/* flag to close the connection */
	    return;
	}
	_write_actual(c, c->fd, "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>", 50);
	c->ssl = SSL_new(c->c2s->ssl_ctx);
	SSL_set_fd(c->ssl, c->fd);
	SSL_accept(c->ssl);
	c->reset_stream = 1;
#else
	_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:stream>", 66);
	c->depth = -1;	/* flag to close the connection */
#endif
	chunk_free(chunk);
	return;
    }

    /* handle SASL authentication */
    if ((c->state == state_NONE) && (j_strncmp(NAD_ENAME(chunk->nad, 0), "auth", NAD_ENAME_L(chunk->nad, 0)) == 0)) {
#ifdef WITH_SASL
	int mech_attr = 0;
	char *initial_data = NULL;
	unsigned initial_data_len = 0;
	int sasl_result = 0;
	const char *server_out = NULL;
	unsigned server_out_len = 0;
	char *mechanism = NULL;

	mech_attr = nad_find_attr(chunk->nad, 0, "mechanism", NULL);
	if (mech_attr < 0) {
	    _write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>", 96);
	    c->depth = -1; /* flag to close the connection */
	    chunk_free(chunk);
	    return;
	}

	/* is there initial data? */
	if (NAD_CDATA_L(chunk->nad, 0) > 0) {
	    initial_data_len = (NAD_CDATA_L(chunk->nad, 0)+3)/4*3 + 1;

	    initial_data = (char*)malloc(initial_data_len);
	    sasl_result = sasl_decode64(NAD_CDATA(chunk->nad, 0), NAD_CDATA_L(chunk->nad, 0), initial_data, initial_data_len, &initial_data_len);
	    if (sasl_result != SASL_OK) {
		_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><incorrect-encoding/></failure></stream:stream>", 97);
		log_write(c->c2s->log, LOG_NOTICE, "Problem decoding BASE64 data: %i", sasl_result);
		c->depth = -1;	/* flag to close the connection */
		chunk_free(chunk);
		if (initial_data != NULL) {
		    free(initial_data);
		    initial_data = NULL;
		}
		return;
	    }
	}

	/* extract mechanism */
	mechanism = (char*)malloc(NAD_AVAL_L(chunk->nad, mech_attr)+1);
	if (mechanism != NULL)
	    mechanism[0] = '\0';
	snprintf(mechanism, NAD_AVAL_L(chunk->nad, mech_attr)+1, "%.*s", NAD_AVAL_L(chunk->nad, mech_attr), NAD_AVAL(chunk->nad, mech_attr));

	/* start SASL authentication */
	sasl_result = sasl_server_start(c->sasl_conn, mechanism, initial_data, initial_data_len, &server_out, &server_out_len);
	if (mechanism != NULL) {
	    free(mechanism);
	    mechanism = NULL;
	}
	if (initial_data != NULL) {
	    free(initial_data);
	    initial_data = NULL;
	}
	switch (sasl_result) {
	    case SASL_CONTINUE:
	    case SASL_OK:
		if (sasl_result == SASL_CONTINUE) {
		    _write_actual(c, c->fd, "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>", 52);
		} else {
		    _write_actual(c, c->fd, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>", 50);
		}
		if (server_out_len > 0) {
		    char *out_data_buffer = NULL;
		    unsigned out_data_buffer_len = (server_out_len+2)/3*4 + 1;
		    int sasl_result2 = 0;

		    out_data_buffer = (char*)malloc(out_data_buffer_len);
		    sasl_result2 = sasl_encode64(server_out, server_out_len, out_data_buffer, out_data_buffer_len, &out_data_buffer_len);
		    if (sasl_result2 == SASL_OK) {
			_write_actual(c, c->fd, out_data_buffer, out_data_buffer_len);
		    }
		    if (out_data_buffer != NULL)
			free(out_data_buffer);
		}
		if (sasl_result == SASL_CONTINUE) {
		    _write_actual(c, c->fd, "</challenge>", 12);
		    c->state = state_SASL;
		} else {
		    _write_actual(c, c->fd, "</success>", 10);
		    c->reset_stream = 1;
		}
		break;
	    case SASL_NOMECH:
		_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-mechanism/></failure></stream:stream>", 96);
		c->depth = -1;	/* flag to close the connection */
		break;
	    case SASL_TRYAGAIN:
	    case SASL_NOTINIT:
	    case SASL_TRANS:
	    case SASL_EXPIRED:
	    case SASL_BADVERS:
	    case SASL_NOVERIFY:
		_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><temporary-auth-failure/></failure></stream:stream>", 101);
		c->depth = -1;	/* flag to close the connection */
		break;
	    case SASL_NOAUTHZ:
		_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><invalid-authzid/></failure></stream:stream>", 94);
		log_write(c->c2s->log, LOG_NOTICE, "SASL authentication failure");
		c->depth = -1;	/* flag to close the connection */
		break;
	    case SASL_TOOWEAK:
	    case SASL_ENCRYPT:
		_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism-too-weak/></failure></stream:stream>", 97);
		log_write(c->c2s->log, LOG_NOTICE, "SASL authentication failure");
		c->depth = -1;	/* flag to close the connection */
		break;
	    default:
		_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure></stream:stream>", 93);
		log_write(c->c2s->log, LOG_NOTICE, "SASL authentication failure");
		c->depth = -1;	/* flag to close the connection */
	}
#else
	_write_actual(c, c->fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><temporary-auth-failure/></failure></stream:stream>", 101);
	c->depth = -1;	/* flag to close the connection */
#endif
	chunk_free(chunk);
	return;
    }

    /* handle resource binding */
    if ((c->sasl_state == state_auth_SASL_DONE) && (j_strncmp(NAD_ENAME(chunk->nad, 0), "iq", NAD_ENAME_L(chunk->nad, 0)) == 0)) {
	/* resource binding, check the request is valid */
	int bind_element = -1;
	int type_attr = -1;

	/* there has to be a <bind/> child element, and the iq type has to be set */
	bind_element = nad_find_elem(chunk->nad, 0, "bind", 1);
	type_attr = nad_find_attr(chunk->nad, 0, "type", "set");
	if (bind_element >= 0 && type_attr >= 0) {
	    int id_attr = -1;
	    int resource_element = -1;
	    const char *jid_str = NULL;

	    /* there might be an id attribute, which should be mirrored */
	    id_attr = nad_find_attr(chunk->nad, 0, "id", NULL);

	    /* optionally there might be a <resource/> element */
	    resource_element = nad_find_elem(chunk->nad, bind_element, "resource", 1);
	    if (resource_element >= 0) {
		char *new_resource = pstrdupx(c->idp, NAD_CDATA(chunk->nad, resource_element), NAD_CDATA_L(chunk->nad, resource_element));
		jid_set(c->authzid, new_resource, JID_RESOURCE);
	    }

	    /* no resource yet? create one ... */
	    if (c->authzid != NULL && c->authzid->resource == NULL) {
		char new_resource[32];
		snprintf(new_resource, sizeof(new_resource), "%X", time(NULL));
		jid_set(c->authzid, new_resource, JID_RESOURCE);
	    }

	    /* still no resource? should not happen */
	    if (c->authzid == NULL || c->authzid != NULL && c->authzid->resource == NULL) {
		conn_error(c, STREAM_ERR_INTERNAL_SERVER_ERROR, "we could not generate a resource for your stream");
		c->depth = -1;
		chunk_free(chunk);
		return;
	    }

	    /* send the client the confirmation */
	    _write_actual(c, c->fd, "<iq type='result'", 17);
	    if (id_attr >= 0) {
		_write_actual(c, c->fd, " id='", 5);
		_write_actual(c, c->fd, NAD_AVAL(chunk->nad, id_attr), NAD_AVAL_L(chunk->nad, id_attr));
		_write_actual(c, c->fd, "'", 1);
	    }
	    _write_actual(c, c->fd, "><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'><jid>", 53);
	    jid_str = jid_full(c->authzid);
	    _write_actual(c, c->fd, jid_str, j_strlen(jid_str));
	    _write_actual(c, c->fd, "</jid></bind></iq>", 18);

	    c->sasl_state = state_auth_BOUND_RESOURCE;

	    log_write(c->c2s->log, LOG_NOTICE, "bound resource: %s", jid_str);

	    chunk_free(chunk);
	    return;
	}
    } else if ((c->sasl_state == state_auth_BOUND_RESOURCE) && (j_strncmp(NAD_ENAME(chunk->nad, 0), "iq", NAD_ENAME_L(chunk->nad, 0)) == 0)) {
	int type_attr = -1;
	int session_element = -1;

	session_element = nad_find_elem(chunk->nad, 0, "session", 1);
	type_attr = nad_find_attr(chunk->nad, 0, "type", "set");
	if (session_element >= 0 && type_attr >= 0) {
	    static unsigned int id_serial = 0;
	    char id_serial_str[32];
	    int id_attr = -1;

	    /* keep id of the client request */
	    id_attr = nad_find_attr(chunk->nad, 0, "id", NULL);
	    if (c->id_session_start != NULL) {
		free(c->id_session_start);
	    }
	    c->id_session_start = (char*)malloc(NAD_AVAL_L(chunk->nad, id_attr)+1);
	    snprintf(c->id_session_start, NAD_AVAL_L(chunk->nad, id_attr)+1, "%.*s", NAD_AVAL_L(chunk->nad, id_attr), NAD_AVAL(chunk->nad, id_attr));

	    /* start the session by sending the sm a notification */

	    /* prepare id data */
	    snprintf(id_serial_str, sizeof(id_serial_str), "%X", id_serial++);

	    /* we do not care anymore about the original stanza */
	    nad_free(chunk->nad);
	    chunk->nad = nad_new(c->c2s->nads);
	    nad_append_elem(chunk->nad, "sc:session", 0);
	    nad_append_attr(chunk->nad, "xmlns:sc", "http://jabberd.jabberstudio.org/ns/session/1.0");
	    nad_append_attr(chunk->nad, "action", "start");
	    nad_append_attr(chunk->nad, "id", id_serial_str);
	    nad_append_attr(chunk->nad, "sc:c2s", c->myid->user);
	    nad_append_attr(chunk->nad, "target", jid_full(c->authzid));

	    /* send to session manager */
	    chunk_write(c->c2s->sm, chunk, c->smid->server, jid_full(c->myid), NULL);
	    return;
	}
    }

    /* send it */
    switch(c->state) {
	/* in SASL exchange */
	case state_SASL:
	    _client_do_sasl_step(c, chunk);
	    chunk_free(chunk);
	    break;

        /* normal packets */
        case state_OPEN:
	    c->in_stanzas++;
	    if (c->sc_sm) {
		nad_set_attr(chunk->nad, 0, "xmlns:sc", "http://jabberd.jabberstudio.org/ns/session/1.0");
		nad_set_attr(chunk->nad, 0, "sc:sm", c->sc_sm);
		nad_set_attr(chunk->nad, 0, "sc:c2s", c->myid->user);
	    }
            chunk_write(c->c2s->sm, chunk, jid_full(c->smid), jid_full(c->myid), NULL);
            break;

        /* anything that goes out before authentication gets flagged type='auth' */
        case state_NONE:
        case state_AUTH:
            chunk_write(c->c2s->sm, chunk, jid_full(c->smid), jid_full(c->myid), "auth");
            break;

        default:
            log_debug(ZONE, "conn in unknown state (%d), dropping chunk", c->state);
            chunk_free(chunk);
            break;
    }
}

/**
 * handle a newly accepted incoming client socket
 *
 * @param m the mio that notified us about the connection
 * @param fd the file descriptor of the new connection
 * @param ip the IP address of the originator of the connection
 * @param c2s the jadc2s instance we are running in
 * @return 1 if we want to drop this connection, 0 else
 */
int _client_io_accept(mio_t m, int fd, const char *ip_port, c2s_t c2s) {
    conn_t c = NULL;
    char *port = NULL;
    int local_port = 0;
    int sasl_result = 0;
    const char *remote_ip_port = ip_port;
#ifdef USE_IPV6
    char ip[INET6_ADDRSTRLEN+6];
    char local_ip[INET6_ADDRSTRLEN];
    char local_ip_port[INET6_ADDRSTRLEN+6];
    struct sockaddr_storage sa;
    char port_string[7] = "\0\0\0\0\0\0";
#else
    char ip[16+6];
    char local_ip_port[16+6];
    struct sockaddr_in sa;
#endif
    socklen_t namelen = sizeof(sa);

    if (j_strncmp(remote_ip_port, "::ffff:", 7) == 0) {
	remote_ip_port = remote_ip_port+7;
    }

    snprintf(ip, sizeof(ip), "%s", remote_ip_port);
    port = strchr(ip, ';');
    if (port != NULL) {
	*port = '\0';
	port++;
    }

    log_debug(ZONE, "new client conn %d from ip %s", fd, ip);

    /* the connection might originate on an address, that connected to often lately */
    if (connection_rate_check(c2s, ip))
    {
	/* We had a bad rate, dump them (send an error?) */
	log_debug(ZONE, "rate limit is bad for %s, closing", ip);
	/* return 1 to get rid of this fd */
	return 1;
    }

    /* get local and remote endpoint of the connection */
    if (getsockname(fd, (struct sockaddr*)&sa, &namelen))
	return 1;
#ifdef USE_IPV6
    switch (sa.ss_family) {
	case AF_INET:
	    if (inet_ntop(AF_INET, &(((struct sockaddr_in*)&sa)->sin_addr), local_ip, sizeof(local_ip)) == NULL) {
		log_debug(ZONE, "could not convert IPv4 address to string representation");
		return 1;
	    }
	    local_port = ntohs(((struct sockaddr_in*)&sa)->sin_port);
	    break;
	case AF_INET6:
	    if (inet_ntop(AF_INET6, &(((struct sockaddr_in6*)&sa)->sin6_addr), local_ip, sizeof(local_ip)) == NULL) {
		log_debug(ZONE, "could not convert IPv6 address to string representation");
		return 1;
	    }
	    if (j_strncmp(local_ip, "::ffff:", 7) == 0)
		strcpy(local_ip, local_ip+7);
	    local_port = ntohs(((struct sockaddr_in6*)&sa)->sin6_port);
	    break;
	default:
	    strcpy(local_ip, "(unknown)");
    }
    snprintf(local_ip_port, sizeof(local_ip_port), "%s;%u", local_ip, local_port); /* this needs to be a ';' for SASL */
#else
    local_port = ntohs(sa.sin_port);
    snprintf(local_ip_port, sizeof(local_ip_port), "%s;%u", inet_ntoa(sa.sin_addr), local_port); /* this needs to be a ';' for SASL */
#endif

    log_write(c2s->log, LOG_NOTICE, "connection from %s to %s", remote_ip_port, local_ip_port);

    /* set up the new client conn */
    c = conn_new(c2s, fd);
    /* get the connection instead of the jadc2s instance for further callbacks */
    mio_app(m, fd, client_io, (void*)c);

#ifdef USE_SSL
    /* figure out if they came in on the ssl port or not, and flag them accordingly */
    if(local_port == c->c2s->local_sslport) {
	/* flag this connection as being able to use SSL/TLS */
	c->autodetect_tls = autodetect_READY;
    }
#endif

    if (c->c2s->sasl_enabled) {
#ifdef WITH_SASL
	if (c->sasl_conn != NULL) {
	    log_write(c2s->log, LOG_ERR, "Internal error: Old SASL connection not disposed");
	    sasl_dispose(&(c->sasl_conn));
	    c->sasl_conn = NULL;
	}
	sasl_result = sasl_server_new(c2s->sasl_service, c2s->sasl_fqdn, c2s->sasl_defaultrealm, local_ip_port, remote_ip_port, NULL, 0, &(c->sasl_conn));
	if (sasl_result != SASL_OK) {
	    log_write(c2s->log, LOG_ERR, "Error initializing SASL context: %i", sasl_result);
	} else {
	    sasl_security_properties_t secprops;
	    secprops.min_ssf = c2s->sasl_min_ssf;
	    secprops.max_ssf = c2s->sasl_max_ssf;
	    secprops.maxbufsize = c2s->sasl_noseclayer ? 0 : 1024;	/* XXX change to support security layer! */
	    secprops.property_names = NULL;
	    secprops.property_values = NULL;
	    secprops.security_flags = c2s->sasl_sec_flags;
	    sasl_result = sasl_setprop(c->sasl_conn, SASL_SEC_PROPS, &secprops);
	    if (sasl_result != SASL_OK) {
		log_write(c2s->log, LOG_ERR, "Error setting SASL security properties: %i", sasl_result);
	    }
	}
#else
	log_write(c2s->log, LOG_ERROR, "Internal error: SASL enabled, but not compiled in - SASL not available");
#endif
    }

    /* put us in the pre-auth hash */
    xhash_put(c->c2s->pending,jid_full(c->myid), (void*)c);

    /* set up expat callbacks */
    XML_SetUserData(c->expat, (void*)c);
    XML_SetElementHandler(c->expat, (void*)_client_startElement, (void*)_client_endElement);
    XML_SetCharacterDataHandler(c->expat, (void*)_client_charData);

    /* we are now waiting for the stream */
    c->state = state_NEGO;

    /* count the number of open client connections */
    c->c2s->num_clients++;

    /* get read events */
    mio_read(m, fd);

    /* keep the IP address of the user */
    c->ip = pstrdup(c->idp, ip);
    if (port != NULL) {
	c->port = atoi(port);
    }

    return 0;
}

#ifdef USE_SSL
/**
 * autodetect if SSL/TLS is used as a layer between the socket and XMPP
 * by having a look at the first incoming bytes
 *
 * used heuristic:
 * - an incoming connection using SSLv3/TLSv1 records should start with
 *   0x16
 * - an incoming connection using SSLv2 records should start with the
 *   record size and as the first record should not be very big we
 *   can expect 0x80 or 0x00 (the MSB is a flag)
 * - unencrypted sessions should start with '<' but everything else is
 *   considered to be unencrypted
 *
 * @param fd the file descriptor of the connection
 * @param c the connection
 * @return 1 on failure, 0 else XXX check if this is right
 */
int _client_autodetect_tls(int fd, conn_t c) {
    char first;

    if (!c->c2s->ssl_enable_autodetect || _peek_actual(c, fd, &first, 1)!=1 || first==0x16 || first==-128 || first==0)
    {
	/* we start SSL/TLS if
	 * - we are not configured to autodetect SSL/TLS
	 * - we think it is SSL/TLS
	 */
	c->autodetect_tls = autodetect_TLS;

	/* enable SSL/TLS on this socket */
	c->ssl = SSL_new(c->c2s->ssl_ctx);
	if (c->ssl == NULL)
	{
	    log_write(c->c2s->log, LOG_WARNING, "failed to create SSL structure for connection on fd %i, closing", fd);
	    log_ssl_errors(c->c2s->log, LOG_WARNING);
	    return 1;
	}
	if (!SSL_set_fd(c->ssl, fd))
	{
	    log_write(c->c2s->log, LOG_WARNING, "failed to connect SSL object with accepted socket on fd %i, closing", fd);
	    log_ssl_errors(c->c2s->log, LOG_WARNING);
	    return 1;
	}
	SSL_accept(c->ssl);
    } else {
	/* it seems this is no Jabber over SSL/TLS connection */
	c->autodetect_tls = autodetect_PLAIN;
    }

    return 0;
}
#endif

/**
 * replace the parser for a connection
 *
 * @param c the connection for which we have to replace expat
 */
void _client_replace_parser(conn_t c) {
    if (c->expat != NULL)
	XML_ParserFree(c->expat);
    c->expat = XML_ParserCreate(NULL);

    /* set up expat callbacks */
    XML_SetUserData(c->expat, (void*)c);
    XML_SetElementHandler(c->expat, (void*)_client_startElement, (void*)_client_endElement);
    XML_SetCharacterDataHandler(c->expat, (void*)_client_charData);
}

#ifdef FLASH_HACK
/**
 * If we are handling a flash client, it has closed the root element of the stream
 * immediatelly and expat thinks we have alread read the complete XML document.
 * Therefore we have to replace the parser after the root element has been read
 * and we give the new expat and additional element so that it does not think
 * that the document has been finished after each stanza.
 *
 * @param c the connection for which we have to replace expat
 */
void _client_replace_parser_flash(conn_t c) {
    log_debug(ZONE,"Flash Hack... get rid of the old Parser, and make a new one... stupid Flash...");
    _client_replace_parser(c);
    XML_Parse(c->expat, "<stream:stream>", 15, 0);

    /* we do not have to replace expat again */
    c->flash_hack = 0;
}
#endif

/**
 * detect the protocol variant that is used for this connection
 *
 * @param fd the file descriptor of the connection
 * @param c the connection for which we should detect the variant
 */
void _client_detect_variant(int fd, conn_t c) {
    int firstlen;
    char first[2];

#ifdef USE_SSL
    /* if SSL/TLS is already active, it's stone-age jabber over
     * SSL/TLS
     *
     * We do not accept anything special on such a connection,
     * no HTTP header and no flash hack.
     */
    if (c->ssl != NULL) {
	/* we finished variant detection and are now waiting for
	 * the stream to start and the client to authenticate and*/
	c->state = state_NONE;

	/* XXX: type_NORMAL is already the default, nothing to set */
	return;
    }
#endif

    /* check if there is an HTTP header */
    log_debug(ZONE,"Check the first char");
    while((firstlen = _peek_actual(c,fd,first,1)) == -1) { }
    log_debug(ZONE,"char(%c)",first[0]);
    
    /* If the first char is G then it's for HTTP (GET ....)
       and if we configured http client forwarding to a real http server */
    if (first[0] == 'G' && c->c2s->http_forward)
    {
	char* http =
		"HTTP/1.0 301 Found\r\n"
		"Location: %s\r\n"
		"Server: jadc2s " VERSION "\r\n"
		"Expires: Fri, 10 Oct 1997 10:10:10 GMT\r\n"
		"Pragma: no-cache\r\n"
		"Cache-control: private\r\n"
		"Connection: close\r\n\r\n";
	char *buf;
	
	buf = malloc((strlen(c->c2s->http_forward) + strlen(http)) * sizeof(char));
	sprintf (buf, http, c->c2s->http_forward);
	
	log_debug(ZONE,"This is an incoming HTTP connection - forwarding to: %s", c->c2s->http_forward);
	
	/* read all incoming data */

	/* XXX this could be used to remotly block jadc2s
	 *     but it would be nice if we read the incoming data before closing the socket
	while(_read_actual(c,fd,first,1) > 0) { }
	 */

	_write_actual(c,fd,buf,strlen(buf));
	
	/* close connection */
        mio_close(c->c2s->mio, c->fd);
	
	free(buf);
	
	return;
    }

    /* If the first char is P then it's for HTTP (PUT ....) */
    if (first[0] == 'P')
    {
	char* http =
		"HTTP/1.0 200 Ok\r\n"
		"Server: jadc2s " VERSION "\r\n"
		"Expires: Fri, 10 Oct 1997 10:10:10 GMT\r\n"
		"Pragma: no-cache\r\n"
		"Cache-control: private\r\n"
		"Connection: close\r\n\r\n";
	char peek[5];
	int search = 1;
	
	peek[4] = '\0';
	
	log_debug(ZONE,"This is an incoming HTTP connection");
	
	_write_actual(c,fd,http,strlen(http));
	
	log_debug(ZONE,"Look for the ending \\r\\n\\r\\n");
	while( search && ((_peek_actual(c,fd,peek,4)) > 0))
	{
	    if (strcmp(peek,"\r\n\r\n") == 0)
	    {
		search = 0;
		_read_actual(c,fd,peek,4);
	    }
	    else
		_read_actual(c,fd,peek,1);
	}

	/* we detected that the client had sent an HTTP header */
	c->type = type_HTTP;

	/* we finished variant detection and are now waiting for
	 * the stream to start and the client to authenticate and*/
	c->state = state_NONE;

	/* XXX: type_NORMAL is already the default, nothing to set */
	return;
    }
   
#ifdef FLASH_HACK
    /* If the first char is a \0 then the other side expects
     * that all packets will end in a \0.  All packets.  This
     * means that we need to make sure that we handle it
     * correctly in all cases.
     */
    if (first[0] == '\0')
    {
	_read_actual(c,fd,first,1);
	c->type = type_FLASH;

	/* we finished variant detection and are now waiting for
	 * the stream to start and the client to authenticate */
	c->state = state_NONE;

	/* XXX: type_NORMAL is already the default, nothing to set */
	return;
    }
#endif

    /* if we did not find anything special, it's normal XML over TCP
     * sub-variants (stone-age, XMPP) are determined later
     * we are now waiting for the stream to start and the client
     * to authenticate */
    c->state = state_NONE;
}

/**
 * handle it if mio told us that there is new data on the client socket, that can be read
 *
 * @param m the mio that notified us
 * @param fd the file descriptor on which new data is available
 * @param c the connection on which new data is available
 * @return 1 if we want to get more events, 0 else
 */
int _client_io_read(mio_t m, int fd, conn_t c) {
    char buf[1024]; /* !!! make static when not threaded? move into conn_st? */
    int read_len, len, ret;

#ifdef USE_SSL
    /* check if we have to autodetect SSL/TLS */
    if (c->autodetect_tls == autodetect_READY)
	if (_client_autodetect_tls(fd, c))
	    return 1;

#endif

#ifdef FLASH_HACK
    /* flash clients close the stream root immediatelly,
     * expat things the complete document has been read.
     * We need a new instance of it. */
    if (c->flash_hack == 1)
	_client_replace_parser_flash(c);
#endif

    if (c->reset_stream > 0) {
	c->reset_stream = 0;
	c->state = state_NONE;
	c->type = type_NORMAL;
	c->root_element = root_element_NONE;
	c->local_id = NULL;
	if (c->sid != NULL)
	    free(c->sid);
	c->sid = NULL;
	_client_replace_parser(c);
	c->depth = 0;
    }
    
    log_debug(ZONE,"io action_READ with fd %d in state %d", fd, c->state);

    /* we act differently when reading data from the client based on
     * it's auth state
     */
    switch(c->state) {
	/* detect the protocol variant we are using */
	case state_NEGO:
	    _client_detect_variant(fd, c);
	    return 1;

	/* we are waiting for the client to authenticate */
	case state_NONE:
	case state_SASL:
	    /* before the client is authorized, we tip-toe through the data to find the auth packets */
	    while(c->state == state_NONE || c->state == state_SASL)
	    {
		/* read data from the scoket taking care of the
		 * security layers we put on the connection
		 */
		len = _read_actual(c, fd, buf, 10);
		/* process what has been read */
		if((ret = conn_read(c, buf, len)) == 0) return 0;
		/* come back again if no more data */
		if(ret == 2 || len < 10) return 1;
	    }
	    return 0;
	   
	/* the session manager has to accept the authentication or start the session */
	case state_AUTH:
	case state_SESS:
	    return 0;

	/* the session has been started, bandwidth is limited */
	case state_OPEN:
	    /* read a chunk at a time */
	    read_len = conn_max_read_len(c);

	    /* Naughty, naughty, ate their karma */
	    if (read_len == 0)
	    {
		log_debug(ZONE, "User ate karma");
		return 0;
	    }

	    /* we shouldn't read more than the size of our buffer */
	    if (read_len > sizeof(buf)) {
		read_len = sizeof(buf);
	    }

	    /* read data from the socket taking care of the
	     * security layers we put on the connection
	     */
	    len = _read_actual(c, fd, buf, read_len);

	    /* process what has been read */
	    return conn_read(c, buf, len);

	/* to make gcc happy */
	default:
	    return 0;
    }
}

/**
 * mio told us that a connection has been idle and we should check if it
 * is still there
 *
 * @param fd the file descriptor of the connection
 * @param c the connection
 * @return 1 if we want to close it, 0 if we want to keep it
 */
int _client_io_idle(int fd, conn_t c) {
    if (_write_actual(c, fd, " ", 1) != 1) {
	if (errno == EAGAIN || errno == EINTR)
	    return 0;
	return 1;
    }
    return 0;
}

/**
 * mio told us that a connection has gone
 *
 * @param fd the file descriptor of the connection
 * @param c the connection
 */
void _client_io_close(int fd, conn_t c) {
    chunk_t chunk;

    log_debug(ZONE, "_client_io_close(%i, %x)", fd, c);

    /* Process on a valid conn */
    if(c->state == state_OPEN) {
	chunk_t cur, next;

	log_debug(ZONE, "... in state_OPEN, sc_sm=%s", c->sc_sm);

	/* if there was a nad being created, ditch it */
	if(c->nad != NULL) {
	    nad_free(c->nad);
	    c->nad = NULL;
	}

	/* bounce write queue back to sm and close session */
	if(c->writeq != NULL) {
	    for(cur = c->writeq; cur != NULL; cur = next) {
		next = cur->next;
		chunk_write(c->c2s->sm, cur, jid_full(c->smid), jid_full(c->myid), "error");
	    }
	} else {
	    /* always send some sort of error */
	    if (c->sc_sm == NULL) {
		chunk = chunk_new(c);
		chunk_write(c->c2s->sm, chunk, jid_full(c->smid), jid_full(c->myid), "error");
		chunk = NULL;
	    }
	}

	/* close session using the new protocol */
	if (c->sc_sm != NULL) {
	    log_debug(ZONE, "trying to close using new protocol");
	    chunk = chunk_new(c);
	    chunk->nad = nad_new(c->c2s->nads);
	    nad_append_elem(chunk->nad, "sc:session", 0);
	    nad_append_attr(chunk->nad, "xmlns:sc", "http://jabberd.jabberstudio.org/ns/session/1.0");
            nad_append_attr(chunk->nad, "action", "end");
            nad_append_attr(chunk->nad, "sc:c2s", c->myid->user);
	    nad_append_attr(chunk->nad, "sc:sm", c->sc_sm);
	    chunk_write(c->c2s->sm, chunk, c->authzid->server, jid_full(c->myid), NULL);
	    chunk = NULL;
	}
    } else {
	/* XXX free write queue */
	/* remove from preauth hash */
	xhash_zap(c->c2s->pending,jid_full(c->myid));
    }

    /* count the number of open client connections */
    c->c2s->num_clients--;

    /* report closed connection */
    if (c->ip && c->userid) {
	/* if the user never authenticated, we still have to write its IP */
	if (c->state != state_OPEN)
	    log_write(c->c2s->log, LOG_NOTICE, c->c2s->iplog ? "user %s on fd %i, ip=%s never authenticated" : "user %s never authenticated", jid_full(c->userid), c->fd, c->ip);

	/* write it to the logfile */
	log_write(c->c2s->log, LOG_NOTICE, "user %s on fd %i disconnected, in=%lu B, out=%lu B, stanzas_in=%u, stanzas_out=%u", jid_full(c->userid), c->fd, c->in_bytes, c->out_bytes, c->in_stanzas, c->out_stanzas);

	/* send a notification message if requested */
	connectionstate_send(c->c2s->config, c->c2s->sm, c, 0);
    }

    conn_free(c);

}


/**
 * callback function where mio can notify us about events on an
 * incoming client connection
 *
 * @param m the mio that notifies us
 * @param a what happened
 * @param fd on which file descriptor something happened
 * @param data for action_ACCEPT the IP address of the originator
 * @param arg data we asked to get passed
 * @return if we want to get more events
 */
int client_io(mio_t m, mio_action_t a, int fd, void *data, void *arg)
{
    log_debug(ZONE,"io action %d with fd %d",a,fd);

    switch(a) {
	case action_ACCEPT:
	    return _client_io_accept(m, fd, (char*)data, (c2s_t)arg);

	case action_READ:
	    return _client_io_read(m, fd, (conn_t)arg);
	    
	case action_WRITE:
	    return conn_write((conn_t)arg);

	case action_IDLE:
	    return _client_io_idle(fd, (conn_t)arg);

	case action_CLOSE:
	    _client_io_close(fd, (conn_t)arg);
	    return 0;

	default:
	    return 0;
    }
}
