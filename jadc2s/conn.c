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

#include "jadc2s.h"

/* this file contains some simple utils for the conn_t data type */

/* create a new blank conn (!caller must set expat callbacks and mio afterwards) */
conn_t conn_new(c2s_t c2s, int fd)
{
    conn_t c;
    char buf[16];

    c = &c2s->conns[fd];
    memset(c, 0, sizeof(struct conn_st));

    /* set up some basic defaults */
    c->c2s = c2s;
    c->fd = fd;
    c->last_read = 0;
    c->read_bytes = 0;
    c->sid = NULL;
    c->root_element = root_element_NONE;
    c->local_id = NULL;
    c->state = state_NONE;
    c->sasl_state = state_auth_NONE;
    c->type = type_NORMAL;
    c->start = time(NULL);
    c->expat = XML_ParserCreate(NULL);
    c->qtail = c->writeq = NULL;

    /* set up our id */
    c->idp = pool_heap(128);
    c->myid = jid_new(c->idp, c2s->jid_environment, c2s->sm_id);
    snprintf(buf,16,"%d",fd);
    jid_set(c->myid, buf, JID_USER);
   
#ifdef FLASH_HACK
    c->flash_hack = 0;
#endif

    c->in_bytes = 0;
    c->out_bytes = 0;
    c->in_stanzas = 0;
    c->out_stanzas = 0;

#ifdef USE_SSL
    c->autodetect_tls = autodetect_NONE;
#endif

    return c;
}

/* free up memory (!caller must process anything in the writeq) */
void conn_free(conn_t c)
{
    /* free allocated strings */
    if (c->sid != NULL) {
	free(c->sid);
	c->sid = NULL;
    }
    if (c->sc_sm != NULL) {
	free(c->sc_sm);
	c->sc_sm = NULL;
    }
    if (c->id_session_start != NULL) {
	free(c->id_session_start);
	c->id_session_start = NULL;
    }
    XML_ParserFree(c->expat);
#ifdef WITH_SASL
    if (c->sasl_conn != NULL) {
	sasl_dispose(&(c->sasl_conn));
    }
    c->sasl_conn = NULL;
#endif
#ifdef USE_SSL
    SSL_free(c->ssl);
#endif
    pool_free(c->idp);

    /* flag it as unused */
    c->fd = -1;
}

/* write a stream error */
void conn_error(conn_t c, char *condition, char *err)
{
    if (c == NULL || (condition == NULL && err == NULL))
	return;

    /* do we still have to open the stream? */
    if (c->root_element == root_element_NONE)
    {
#ifdef FLASH_HACK
	if (c->type == type_FLASH) {
	    _write_actual(c, c->fd, "<flash:stream xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", 77);
	    c->root_element = root_element_FLASH;
	} else {
#endif
	    _write_actual(c, c->fd, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", 77);
	    c->root_element = root_element_NORMAL;
#ifdef FLASH_HACK
	}
#endif
    }

    log_debug(ZONE,"sending stream error: %s %s", condition, err);
    _write_actual(c, c->fd, "<stream:error>",14);

    /* send the condition (should be present!) */
    if(condition != NULL)
	_write_actual(c, c->fd, condition, strlen(condition));

    if(err != NULL)
    {
	char *description;
	description = (char*)malloc(strlen(err)+58);
	sprintf(description,"<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>%s</text>", err);
	_write_actual(c, c->fd, description, strlen(description));
	free(description);
    }

    _write_actual(c, c->fd, "</stream:error>",15);
}

#ifdef USE_SSL
int _log_ssl_io_error(log_t l, SSL *ssl, int retcode, int fd);
#endif

/**
 * get the textual representation of the root element name
 *
 * @param root_element the used root element
 * @return the textual representation
 */
const char* _conn_root_element_name(root_element_t root_element) {
    return root_element == root_element_FLASH ? "flash:stream" :
	root_element == root_element_NORMAL ? "stream:stream" :
	"";
}

/* write errors out and close streams */
void conn_close(conn_t c, char *condition, char *err)
{
    if(c != NULL && c->fd != -1)
    {
	char *footer;
	const char *root_element_name;

	/* send the stream error */
	conn_error(c, condition, err);

	root_element_name = _conn_root_element_name(c->root_element);
	footer = malloc(4 + strlen(root_element_name));
	sprintf(footer, "</%s>", root_element_name);
	
	_write_actual(c, c->fd, footer, strlen(footer));
	free(footer);

#ifdef USE_SSL
	/* For SSLv3 and TLS we have to send a close notify */
	if (c->ssl != NULL) {
	    int sslret = 0;

	    log_write(c->c2s->log, LOG_DEBUG, "Closing SSL/TLS security layer on fd %i", c->fd);
	    sslret = SSL_shutdown(c->ssl);
	    if (sslret < 0)
		_log_ssl_io_error(c->c2s->log, c->ssl, sslret, c->fd);
	}
#endif

        mio_close(c->c2s->mio, c->fd); /* remember, c is gone after this, re-entrant */
    }
}

/* create a new chunk, using the nad from this conn */
chunk_t chunk_new(conn_t c) {
    return chunk_new_packet(c, 0);
}

chunk_t chunk_new_packet(conn_t c, int packet_elem) {
    chunk_t chunk = (chunk_t) malloc(sizeof(struct chunk_st));
    memset(chunk, 0, sizeof(struct chunk_st));

    chunk->next = NULL;

    /* nad gets tranferred from the conn to the chunk */
    chunk->nad = c->nad;
    c->nad = NULL;

    /* remember the packet element */
    chunk->packet_elem = packet_elem;

    return chunk;
}

/* free a chunk */
void chunk_free(chunk_t chunk)
{
    nad_free(chunk->nad);

    free(chunk);
}

/* write a chunk to a conn */
void chunk_write(conn_t c, chunk_t chunk, const char *to, const char *from, const char *type)
{
    int elem;

    /* make an empty nad if there isn't one */
    if (chunk->nad == NULL) {
        chunk->nad = nad_new(c->c2s->nads);
	chunk->packet_elem = 0;
    }

    elem = chunk->packet_elem;

    /* prepend optional route data */
    if (to != NULL) {
	if (chunk->nad->ecur <= chunk->packet_elem) {
	    elem = nad_append_elem(chunk->nad, "route", 1);
	} else {
	    nad_wrap_elem(chunk->nad, chunk->packet_elem, "route");
	    elem = chunk->packet_elem;
	}

        nad_set_attr(chunk->nad, elem, "to", to);
        nad_set_attr(chunk->nad, elem, "from", from);

        if(type != NULL)
            nad_set_attr(chunk->nad, elem, "type", type);
    }

    /* turn the nad into xml */
    nad_print(chunk->nad, elem, &chunk->wcur, &chunk->wlen);

    /* append to the outgoing write queue, if any */
    if (c->qtail == NULL) {
        c->qtail = c->writeq = chunk;
    } else {
        c->qtail->next = chunk;
        c->qtail = chunk;
    }

    /* ensure that this chunk is alone */
    chunk->next = NULL;

    /* tell mio to process write events on this fd */
    mio_write(c->c2s->mio, c->fd);
}

/***
* See how many more bytes this user may read in relation to the transfer speed
* cap
* @param c The conn to check
* @return int the number of bytes that may be read
*/
int conn_max_read_len(conn_t c)
{
    c2s_t c2s = c->c2s;
    int max_bits_per_sec = j_atoi(config_get_one(c2s->config, "io.max_bps", 0),
            1024);
    time_t now;
    int bytes;
    bad_conn_t bad_conn;

    /* They have disabled this */
    if (max_bits_per_sec <= 0)
        return 1024;
    /* See if we can reset them */
    if ((time(&now) - c->last_read) > 1)
    {
        c->last_read = now;
        c->read_bytes = 0;
        bytes = max_bits_per_sec / 8;
    }
    else
    {
        bytes = (max_bits_per_sec / 8) - c->read_bytes;
    }

    /* See if the user ate all their karma */
    if (bytes > 0)
	return bytes;

    /* Create a new bad conn */
    bad_conn = malloc(sizeof(struct bad_conn_st));
    bad_conn->c = c;
    bad_conn->last = now;
    bad_conn->next = NULL;
    /* Append it to the end of the bad conns list */
    if (c2s->bad_conns == NULL)
	c2s->bad_conns = bad_conn;
    else
	c2s->bad_conns_tail->next = bad_conn;
    /* Update the tail */
    c2s->bad_conns_tail = bad_conn;
    
    /* Reset the resolution */
    c2s->timeout = 1;

    return 0;
}

/* process the xml data that's been read */
int conn_read(conn_t c, char *buf, int len)
{
    char *err = NULL;
    int cur_len = 0;

    log_debug(ZONE,"conn_read: len(%d)",len);

    /* client gone */
    if(len == 0)
    {
        mio_close(c->c2s->mio, c->fd);
        return 0;
    }

    /* deal with errors */
    if(len < 0)
    {
        log_debug(ZONE,"conn_read: errno(%d : %s)",errno,strerror(errno));

        if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
            return 2; /* flag that we're blocking now */
	
        mio_close(c->c2s->mio, c->fd);
        return 0;
    }

    /* Stupid us for not thinking of this from the beginning...
     * Some libaries (Flash) like to \0 terminate all of their packets
     * before sending them.  Which is normally ok, unless they send two
     * packets at the same time.  <iq/>\0<iq/>\0  That hoses the XML_Parse
     * call.  So, we need to loop when we see this and only pass it the
     * real strings.  We know how much we read, so we know where to stop.
     * Loop until we've parsed that much and only parse strings.
     *
     * Thanks to temas for cleaning up my very poor first pass.
     *
     * reatmon@jabber.org
     */
    
    while(cur_len < len)
    {
        /* Look for a shorter buffer based on \0 */
        char* new_buf = &buf[cur_len];
        int max_len = strlen(new_buf);
        if ((len - cur_len) < max_len)
            max_len = (len - cur_len);
        
        log_debug(ZONE,"processing read data from %d: %.*s", c->fd, max_len, new_buf);

        /* Update how much has been read */
        c->read_bytes += max_len;
    
        /* parse the xml baby */
        if(!XML_Parse(c->expat, new_buf, max_len, 0))
        {
            err = (char *)XML_ErrorString(XML_GetErrorCode(c->expat));
        }
        else if(c->depth > MAXDEPTH)
        {
            err = MAXDEPTH_ERR;
        }

        /* oh darn */
#ifdef FLASH_HACK
        if((err != NULL) && (c->flash_hack == 0))
#else
        if(err != NULL)
#endif
        {
            conn_close(c, STREAM_ERR_INVALID_XML, err);
            return 0;
        }
        
        /* if we got </stream:stream>, this is set */
        if(c->depth < 0) {
	    conn_close(c, NULL, NULL);
            return 0;
        }

        /* Update the current length we've parsed so that we know when to stop. */
        cur_len += max_len+1;
    }

    /* get more read events */
    return 1;
}

/* write chunks to this conn */
int conn_write(conn_t c)
{
    int len;
    chunk_t cur;

    /* try to write as much as we can */
    while((cur = c->writeq) != NULL)
    {
        log_debug(ZONE, "writing data to %d: %.*s", c->fd, cur->wlen, (char*)cur->wcur);

        /* write a bit from the current buffer */
        len = _write_actual(c, c->fd, cur->wcur, cur->wlen);

        /* we had an error on the write */
        if(len < 0)
        {
            if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
                return 2; /* flag that we're blocking now */
	   
            mio_close(c->c2s->mio, c->fd);
            return 0;
        }
        else if(len < cur->wlen) /* we didnt' write it all, move the current buffer up */
        { 
            cur->wcur += len;
            cur->wlen -= len;
            return 1;
        }
        else /* we wrote the entire node, kill it and move on */
        {    
            c->writeq = cur->next;

            if(c->writeq == NULL)
                c->qtail = NULL;

            chunk_free(cur);
        }
    } 
    return 0;
}

#ifdef USE_SSL
int _log_ssl_io_error(log_t l, SSL *ssl, int retcode, int fd) {
    int ssl_error;

    ssl_error = SSL_get_error(ssl, retcode);

    if (ssl_error == SSL_ERROR_WANT_READ ||
	    ssl_error == SSL_ERROR_WANT_WRITE ||
    	    (ssl_error == SSL_ERROR_SYSCALL && errno == 0))
	return;

    log_write(l, LOG_NOTICE, "SSL_read() on fd %i returned %i", fd, retcode);
    switch (ssl_error) {
	case SSL_ERROR_ZERO_RETURN:
	    log_write(l, LOG_NOTICE, "TLS/SSL connection has been closed.");
	    break;
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	    log_write(l, LOG_DEBUG, "SSL/TLS needs more data from BIO to connect/accept");
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    log_write(l, LOG_DEBUG, "want X509 lookup (shout not happen");
	    break;
	case SSL_ERROR_SYSCALL:
	    log_write(l, LOG_NOTICE, "syscall error occurred");
	    if (ERR_peek_error() == 0) {
		log_write(l, LOG_NOTICE, "%s", strerror(errno));
	    } else {
		log_ssl_errors(l, LOG_NOTICE);
	    }
	    break;
	case SSL_ERROR_SSL:
	    log_ssl_errors(l, LOG_NOTICE);
    }
}
#endif

int _read_actual(conn_t c, int fd, char *buf, size_t count)
{
    int bytes_read;

#ifdef USE_SSL
    if(c->ssl != NULL)
    {
	int ssl_init_finished = SSL_is_init_finished(c->ssl);
	bytes_read = SSL_read(c->ssl, buf, count);
	if (bytes_read > 0)
	    c->in_bytes += bytes_read;	/* XXX counting decrypted bytes */
	if (!ssl_init_finished && SSL_is_init_finished(c->ssl))
	    log_write(c->c2s->log, LOG_NOTICE, "ssl/tls established on fd %i: %s %s", c->fd, SSL_get_version(c->ssl), SSL_get_cipher(c->ssl));
	if (bytes_read <= 0)
	    _log_ssl_io_error(c->c2s->log, c->ssl, bytes_read, c->fd);

#ifdef WITH_SASL
	if (bytes_read > 0 && c->sasl_conn != NULL && c->sasl_state != state_auth_NONE) {
	    int sasl_result = 0;
	    const char *decoded_data = NULL;
	    size_t decoded_len = 0;

	    sasl_result = sasl_decode(c->sasl_conn, buf, bytes_read, &decoded_data, &decoded_len);
	    if (sasl_result != SASL_OK) {
		errno = EIO;
		return -1;
	    }
	    memcpy(buf, decoded_data, decoded_len < count ? decoded_len : count);
	    return decoded_len < count ? decoded_len : count;
	}
#endif
        return bytes_read;
    }
#endif
    bytes_read = read(fd, buf, count);
    if (bytes_read > 0)
	c->in_bytes += bytes_read;
#ifdef WITH_SASL
    if (bytes_read > 0 && c->sasl_conn != NULL && c->sasl_state != state_auth_NONE) {
	int sasl_result = 0;
	const char *decoded_data = NULL;
	size_t decoded_len = 0;

	sasl_result = sasl_decode(c->sasl_conn, buf, bytes_read, &decoded_data, &decoded_len);
	if (sasl_result != SASL_OK) {
	    errno = EIO;
	    return -1;
	}
	memcpy(buf, decoded_data, decoded_len < count ? decoded_len : count);
	return decoded_len < count ? decoded_len : count;
    }
#endif
 
    return bytes_read;
}

/* XXX cannot be used after a SASL security layer has been established! */
int _peek_actual(conn_t c, int fd, char *buf, size_t count)
{
    int bytes_read;
   
#ifdef USE_SSL
    if(c->ssl != NULL) {
	bytes_read = SSL_peek(c->ssl, buf, count);
	if (bytes_read <= 0)
	    _log_ssl_io_error(c->c2s->log, c->ssl, bytes_read, c->fd);

        return bytes_read;
    }
#endif

    return recv(fd, buf, count, MSG_PEEK);
}


int _write_actual(conn_t c, int fd, const char *buf, size_t count)
{
    int written;
    const char *output_buffer = buf;
    size_t output_len = count;
    int truncated_write = 0;

    log_debug(ZONE, "writing: %.*s", count, buf);

#ifdef WITH_SASL
    if (c->sasl_conn && c->sasl_state != state_auth_NONE) {
	int sasl_result = 0;

	log_debug(ZONE, "c->sasl_conn = %X, buf = %.*s, count = %i", c->sasl_conn, count, buf, count);
	output_buffer = NULL;
	/* check that we do not try to encode to much data using sasl_encode() */
	if (c->sasl_outbuf_size != NULL && *c->sasl_outbuf_size > 0 && *c->sasl_outbuf_size < count) {
	    count = *c->sasl_outbuf_size;
	    truncated_write = 1;
	}
	sasl_result = sasl_encode(c->sasl_conn, buf, count, &output_buffer, &output_len);
	log_debug(ZONE, "SASL result: %i", sasl_result);
	if (sasl_result != SASL_OK) {
	    errno = EIO;
	    return -1;
	}
    }
#endif

    log_debug(ZONE, "after SASL encoding (%i): %.*s", output_len, output_len, output_buffer);
    
#ifdef USE_SSL
    if(c->ssl != NULL) {
        written = SSL_write(c->ssl, output_buffer, output_len);
	if (written > 0) {
#ifdef FLASH_HACK
	    if (c->type == type_FLASH) {
		SSL_write(c->ssl, "\0", 1);
		c->out_bytes += written+1; /* XXX counting before encryption */
		return truncated_write ? *c->sasl_outbuf_size : written; /* XXX we currently do not handle SASL blocks that are only accepted half */
	    }
#endif

	    c->out_bytes += written;
	}
	else
	    _log_ssl_io_error(c->c2s->log, c->ssl, written, c->fd);

        return truncated_write ? *c->sasl_outbuf_size : written; /* XXX we currently do not handle SASL blocks, that are only half written to the socket */
    }
#endif
        
    written = write(fd, output_buffer, output_len);
    if (written > 0)
    {
#ifdef FLASH_HACK
	if ((c->type == type_FLASH)) {
	    write(fd, "\0", 1);
	    c->out_bytes += written+1;
	    return truncated_write ? *c->sasl_outbuf_size : written; /* XXX we currently do not handle SASL blocks, that are only half written to the socket */
	}
#endif

	c->out_bytes += written;
    }
    return truncated_write ? *c->sasl_outbuf_size : written; /* XXX we currently do not handle SASL blocks, that are only half written to the socket */
}

void connectionstate_fillnad(nad_t nad, char *from, char *to, char *user, int is_login, char *ip, const char *ssl_version, const char *ssl_cipher, char *ssl_size_secret, char *ssl_size_algorithm)
{
    nad_append_elem(nad, "message", 0);
    nad_append_attr(nad, "from", from);
    nad_append_attr(nad, "to", to);
    nad_append_elem(nad, "update", 1);
    nad_append_attr(nad, "xmlns", "http://amessage.info/protocol/connectionstate");
    nad_append_elem(nad, "jid", 2);
    nad_append_cdata(nad, user, j_strlen(user), 3);
    if (is_login)
	nad_append_elem(nad, "login", 2);
    else
	nad_append_elem(nad, "logout", 2);
    nad_append_elem(nad, "ip", 2);
    nad_append_cdata(nad, ip, j_strlen(ip), 3);
    if (ssl_version != NULL && ssl_cipher != NULL)
    {
	char *tls_version = strdup(ssl_version);
	char *tls_cipher = strdup(ssl_cipher);
	nad_append_elem(nad, "tls", 2);
	nad_append_elem(nad, "version", 3);
	nad_append_cdata(nad, tls_version, j_strlen(ssl_version), 4);
	nad_append_elem(nad, "cipher", 3);
	nad_append_cdata(nad, tls_cipher, j_strlen(ssl_cipher), 4);
	nad_append_elem(nad, "bits", 3);
	nad_append_attr(nad, "secret", ssl_size_secret);
	nad_append_attr(nad, "algorithm", ssl_size_algorithm);
	free(tls_version);
	free(tls_cipher);
    }
}

void connectionstate_send(config_t config, conn_t c, conn_t client, int is_login)
{
    char *receiver;
    chunk_t chunk;
    int i;

    /* send the connection state update to each configured destination */
    for (i=0; (receiver=config_get_one(config, "io.notifies", i)); i++)
    {
	const char *ssl_version = NULL;
	const char *ssl_cipher = NULL;
	char ssl_size_secret[11] = "0";
	char ssl_size_algorithm[11] = "0";

#ifdef USE_SSL
	if (client->ssl != NULL)
	{
	    int bits_secret, bits_algorithm;

	    ssl_version = SSL_get_version(client->ssl);
	    ssl_cipher = SSL_get_cipher(client->ssl);
	    bits_secret = SSL_get_cipher_bits(client->ssl, &bits_algorithm);
	    snprintf(ssl_size_secret, sizeof(ssl_size_secret), "%i", bits_secret);
	    snprintf(ssl_size_algorithm, sizeof(ssl_size_algorithm), "%i", bits_algorithm);
	}
#endif

	c->nad = nad_new(c->c2s->nads);
	connectionstate_fillnad(c->nad, jid_full(client->myid), receiver, jid_full(client->userid), is_login, client->ip, ssl_version, ssl_cipher, ssl_size_secret, ssl_size_algorithm);
	chunk = chunk_new(c);
	chunk_write(c, chunk, NULL, NULL, NULL);
    }
}
