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
 * check if the host is valid to connect to or a valid alias
 *
 * @param config a configuration element containing valid hosts or valid aliases
 * @param host the host which should be checked
 * @return -1 if host invalid, if valid the index in the configuration is returned
 * */
int _client_check_valid_host(config_elem_t config, const char* host)
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
    id = _client_check_valid_host(c->c2s->local_id, value);
    if (id != -1)
    {
	c->local_id = c->c2s->local_id->values[id];
	log_debug(ZONE, "matched local id '%s''", c->local_id);
    }

    /* if host not yet confirmed, check if there is an alias */
    if (c->local_id == NULL)
    {
	id = _client_check_valid_host(c->c2s->local_alias, value);
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
 * send our own stream root element to the client
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

    /* generate if for flash or not? */
#ifdef FLASH_HACK
    if (c->type == type_FLASH) {
	header = malloc( strlen(header_start_flash) + strlen(header_from) + strlen(header_id) + 3);
	sprintf(header,"%s%s%s/>",header_start_flash,header_from,header_id);
	c->root_element = root_element_FLASH;
    } else {
#endif
	header = malloc( strlen(header_start) + strlen(header_from) + strlen(header_id) + 2);
	sprintf(header,"%s%s%s>",header_start,header_from,header_id);
	c->root_element = root_element_NORMAL;
#ifdef FLASH_HACK
    }
#endif

    /* sent it to the client */
    _write_actual(c,c->fd,header,strlen(header));

    /* free the memory we allocated */
    free(header);
    free(header_from);

    /* set up smid based on to="" host */
    c->userid = c->smid = jid_new(c->idp,c->local_id);
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
	    log_debug(ZONE, "auth packet with no username, dropping it");
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
    if((c->state != state_OPEN) && (j_strncmp(NAD_ENAME(chunk->nad, 0), "iq", 2) == 0)) {
	if (_client_process_stoneage_auth(c, chunk))
	    return;
    }

    /* send it */
    switch(c->state) {
        /* normal packets */
        case state_OPEN:
	    c->in_stanzas++;
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
int _client_io_accept(mio_t m, int fd, const char *ip, c2s_t c2s) {
    conn_t c;
#ifdef USE_SSL
    struct sockaddr_in sa;
    int namelen = sizeof(struct sockaddr_in);
#endif

    log_debug(ZONE, "new client conn %d from ip %s", fd, ip);

    /* the connection might originate on an address, that connected to often lately */
    if (connection_rate_check(c2s, ip))
    {
	/* We had a bad rate, dump them (send an error?) */
	log_debug(ZONE, "rate limit is bad for %s, closing", ip);
	/* return 1 to get rid of this fd */
	return 1;
    }

    /* set up the new client conn */
    c = conn_new(c2s, fd);
    /* get the connection instead of the jadc2s instance for further callbacks */
    mio_app(m, fd, client_io, (void*)c);


#ifdef USE_SSL
    /* figure out if they came in on the ssl port or not, and flag them accordingly */
    getsockname(fd, (struct sockaddr *)&sa, &namelen);
    if(ntohs(sa.sin_port) == c->c2s->local_sslport) {

	/* flag this connection as being able to use SSL/TLS */
	c->autodetect_tls = autodetect_READY;

    }
#endif

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
void _client_replace_parser(conn_t c) {
    log_debug(ZONE,"Flash Hack... get rid of the old Parser, and make a new one... stupid Flash...");
    XML_ParserFree(c->expat);
    c->expat = XML_ParserCreate(NULL);

    /* set up expat callbacks */
    XML_SetUserData(c->expat, (void*)c);
    XML_SetElementHandler(c->expat, (void*)_client_startElement, (void*)_client_endElement);
    XML_SetCharacterDataHandler(c->expat, (void*)_client_charData);

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
    
    /* If the first char is P then it's for HTTP (PUT ....) */
    if (first[0] == 'P')
    {
	char* http = "HTTP/1.0 200 Ok\r\nServer: jadc2s " VERSION "\r\nExpires: Fri, 10 Oct 1997 10:10:10 GMT\r\nPragma: no-cache\r\nCache-control: private\r\nConnection: close\r\n\r\n";
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
	_client_replace_parser(c);
#endif
    
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
	    /* before the client is authorized, we tip-toe through the data to find the auth packets */
	    while(c->state == state_NONE)
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

	    /* read data from the socket taking care of the
	     * security layers we put on the connection
	     */
	    len = _read_actual(c, fd, buf, read_len);

	    /* process what has been read */
	    return conn_read(c, buf, len);
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

    /* Process on a valid conn */
    if(c->state == state_OPEN) {
	chunk_t cur, next;

	/* bounce write queue back to sm and close session */
	if(c->writeq != NULL) {
	    for(cur = c->writeq; cur != NULL; cur = next) {
		next = cur->next;
		chunk_write(c->c2s->sm, cur, jid_full(c->smid), jid_full(c->myid), "error");
	    }
	} else {
	    /* if there was a nad being created, ditch it */
	    if(c->nad != NULL) {
		nad_free(c->nad);
		c->nad = NULL;
	    }
	    /* always send some sort of error */
	    chunk = chunk_new(c);
	    chunk_write(c->c2s->sm, chunk, jid_full(c->smid), jid_full(c->myid), "error");
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
    }
}
