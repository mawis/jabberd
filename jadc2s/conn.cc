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

#include <sstream>

/* this file contains some simple utils for the conn_t data type */

/* forward declaration */
static int _write_actual(conn_t c, int fd, const char *buf, size_t count);

/* create a new blank conn (!caller must set expat callbacks and mio afterwards) */
conn_t conn_new(xmppd::pointer<c2s_st> c2s, int fd)
{
    conn_t c;
    std::ostringstream fd_stream;

    DBG("conn_new() called");

    c = c2s->conns[fd];
    c->reset();

    DBG("reset the connection");

    /* set up some basic defaults */
    c->c2s = c2s;
    c->fd = fd;
    c->last_read = 0;
    c->read_bytes = 0;
    c->sid = "";
    c->root_element = root_element_NONE;
    c->local_id = "";
    c->state = state_NONE;
    c->sasl_state = state_auth_NONE;
    c->type = type_NORMAL;
    c->start = time(NULL);
    c->expat = XML_ParserCreate(NULL);
    c->qtail = c->writeq = NULL;

    /* set up our id */
    c->myid = new xmppd::jid(c2s->used_jid_environment, c2s->sm_id);
    fd_stream << fd;
    c->myid->set_node(fd_stream.str());
   
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

    DBG("set the defaults");

    return c;
}

/* free up memory (!caller must process anything in the writeq) */
void conn_free(conn_t c)
{
    /* free allocated strings */
    c->sid = "";
    c->sc_sm = "";
    c->id_session_start = "";
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

    /* flag it as unused */
    c->fd = -1;
}

/* write a stream error */
void conn_error(conn_t c, const Glib::ustring& condition, const Glib::ustring& err) {
    chunk_t error = NULL;

    if (c == NULL)
	return;

    /* do we still have to open the stream? */
    if (c->root_element == root_element_NONE)
    {
	chunk_t root_element = NULL;
	root_element = chunk_new_free(c->c2s->nads);
	nad_append_elem(root_element->nad, c->type == type_FLASH ? "flash:stream" : "stream:stream", 0);
	nad_append_attr(root_element->nad, "xmlns:stream", "http://etherx.jabber.org/streams");
	if (c->type == type_FLASH)
	    nad_append_attr(root_element->nad, "xmlns:flash", "http://www.jabber.com/streams/flash");
	nad_append_attr(root_element->nad, "from", c->c2s->local_id.empty() ? "invalid" : c->c2s->local_id.begin()->value.c_str());
	nad_append_attr(root_element->nad, "version", "1.0");
	chunk_write_typed(c, root_element, "", "", "", c->type == type_FLASH ? chunk_NORMAL : chunk_OPEN);
    }

    DBG("sending stream error: " << condition << " " << err);
    error = chunk_new_free(c->c2s->nads);
    nad_append_elem(error->nad, "stream:error", 0);

    /* send the condition (should be present!) */
    if(condition.length() > 0) {
	nad_append_elem(error->nad, condition.c_str(), 1);
	nad_append_attr(error->nad, "xmlns", "urn:ietf:params:xml:ns:xmpp-streams");
    }

    if(err.length() > 0) {
	nad_append_elem(error->nad, "text", 1);
	nad_append_attr(error->nad, "xmlns", "urn:ietf:params:xml:ns:xmpp-streams");
	nad_append_cdata(error->nad, err.c_str(), err.length(), 2);
    }

    chunk_write(c, error, "", "", "");
    DBG("stream error sent");
}

#ifdef USE_SSL
static void _log_ssl_io_error(xmppd::logging *l, SSL *ssl, int retcode, int fd, const Glib::ustring& used_func);
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
void conn_close(conn_t c, const Glib::ustring& condition, const Glib::ustring& err) {
    if(c != NULL && c->fd != -1)
    {
	chunk_t footer = NULL;

	/* send the stream error */
	conn_error(c, condition, err);

	try {
	    if (c && c->c2s->nads) {
		footer = chunk_new_free(c->c2s->nads);
		nad_append_elem(footer->nad, "stream:stream", 0);
		chunk_write_typed(c, footer, "", "", "", chunk_CLOSE);
	    }
	} catch (Glib::ustring msg) {
	}

	/* did the connection close in the meantime? */
	if (c->fd < 0)
	    return;

#ifdef USE_SSL
	/* For SSLv3 and TLS we have to send a close notify */
	if (c->ssl != NULL) {
	    int sslret = 0;

	    c->c2s->log->level(LOG_DEBUG) << "Closing SSL/TLS security layer on fd " << c->fd;
	    sslret = SSL_shutdown(c->ssl);
	    if (sslret < 0)
		_log_ssl_io_error(c->c2s->log, c->ssl, sslret, c->fd, "SSL_shutdown");
	}
#endif

        mio_close(c->c2s->mio, c->fd); /* remember, c is gone after this, re-entrant */
    }
}

/* create a new chunk, using the nad from this conn */
chunk_t chunk_new(conn_t c) {
    return chunk_new_packet(c, 0);
}

chunk_t chunk_new_free(nad_cache_t nads) {
    chunk_t chunk = chunk_new(NULL);
    if (chunk == NULL)
	return NULL;

    chunk->nad = nad_new(nads);
    return chunk;
}

chunk_t chunk_new_packet(conn_t c, int packet_elem) {
    chunk_t chunk = new chunk_st();

    chunk->next = NULL;

    /* nad gets tranferred from the conn to the chunk */
    if (c != NULL) {
	chunk->nad = c->nad;
	c->nad = NULL;
    }

    /* remember the packet element */
    chunk->packet_elem = packet_elem;

    return chunk;
}

/* free a chunk */
void chunk_free(chunk_t chunk)
{
    nad_free(chunk->nad);

    if (chunk->to_free != NULL)
	free(chunk->to_free);

    delete chunk;
}

/* write a chunk to a conn */
void chunk_write(conn_t c, chunk_t chunk, const Glib::ustring& to, const Glib::ustring& from, const Glib::ustring& type) {
    chunk_write_typed(c, chunk, to, from, type, chunk_NORMAL);
}

void chunk_write_typed(conn_t c, chunk_t chunk, const Glib::ustring& to, const Glib::ustring& from, const Glib::ustring& type, chunk_type_enum chunk_type) {
    int elem;

    /* make an empty nad if there isn't one */
    if (chunk->nad == NULL && chunk->wlen == 0) {
        chunk->nad = nad_new(c->c2s->nads);
	chunk->packet_elem = 0;
    }

    elem = chunk->packet_elem;

    /* prepend optional route data */
    if (to.length() > 0 && chunk->nad != NULL) {
	if (chunk->nad->ecur <= chunk->packet_elem) {
	    elem = nad_append_elem(chunk->nad, "route", 1);
	} else {
	    nad_wrap_elem(chunk->nad, chunk->packet_elem, "route");
	    elem = chunk->packet_elem;
	}

        nad_set_attr(chunk->nad, elem, "to", to.c_str());
        nad_set_attr(chunk->nad, elem, "from", from.c_str());

        if(type.length() > 0)
            nad_set_attr(chunk->nad, elem, "type", type.c_str());
    }

    /* turn the nad into xml */
    if (chunk->nad != NULL) {
	nad_print(chunk->nad, elem, &chunk->wcur, &chunk->wlen);

	/* only write start or end tag? */
	switch (chunk_type) {
	    case chunk_NORMAL:
		break;
	    case chunk_OPEN:
		if (chunk->wlen > 2) {
		    chunk->wcur[chunk->wlen - 2] = '>';
		    chunk->wlen--;
		}
		break;
	    case chunk_CLOSE:
		if (chunk->wlen > 2) {
		    int i = 0;

		    for (i = 1; i < chunk->wlen - 1; i++) {
			if (chunk->wcur[i] == ' ' || chunk->wcur[i] == '\t' || chunk->wcur[i] == '/') {
			    chunk->wcur[i+1] = '>';
			    break;
			}
		    }
		    chunk->wlen = i+2;
		    for (; i>1; i--) {
			chunk->wcur[i] = chunk->wcur[i-1];
		    }
		    chunk->wcur[1] = '/';
		}
		break;
	}
    }

    /* need to SASL encode? */
#ifdef WITH_SASL
    if (c->sasl_conn && c->sasl_state != state_auth_NONE && c->sasl_outbuf_size && *(c->sasl_outbuf_size) > 0) {
	int sasl_result = 0;
	char *encoded_data = NULL;
	size_t encoded_len = 0;

	DBG("chunk_write_typed() is encoding data using sasl_encode()");

	/* we may have to encode using multiple calls, there is a maximum size we can pass to sasl_encode */
	while (chunk->wlen > 0) {
	    unsigned encoding_now = chunk->wlen;
	    const char *encoded_step_data = NULL;
	    unsigned encoded_step_len = 0;

	    if (encoding_now > *(c->sasl_outbuf_size))
		encoding_now = *(c->sasl_outbuf_size);

	    sasl_result = sasl_encode(c->sasl_conn, chunk->wcur, encoding_now, &encoded_step_data, &encoded_step_len);
	    if (sasl_result != SASL_OK) {
		c->c2s->log->level(LOG_ERR) << "Could not encode data using sasl_encode() on fd " << c->fd;
		break;
	    }
	    chunk->wlen -= encoding_now;
	    chunk->wcur += encoding_now;

	    /* append or new data? */
	    if (encoded_data == NULL) {
		encoded_data = strdup(encoded_step_data);
		encoded_len = encoded_step_len;
	    } else {
		char *old_encoded_data = encoded_data;

		/* to append we need a bigger buffer and append the new data in the new buffer */
		encoded_data = static_cast<char*>(malloc(encoded_len + encoded_step_len));
		memcpy(encoded_data, old_encoded_data, encoded_len);
		memcpy(encoded_data+encoded_len, encoded_step_data, encoded_step_len);
		encoded_len += encoded_step_len;

		/* free the old buffer that got to small */
		free(old_encoded_data);
	    }
	}

	/* could all data be encoded or was there an error? */
	if (chunk->wlen <= 0) {
	    chunk->wcur = encoded_data;
	    chunk->to_free = chunk->wcur;
	    chunk->wlen = encoded_len;
	} else {
	    if (encoded_data != NULL)
		free(encoded_data);
	}
    }
#endif /* WITH_SASL */

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
    xmppd::pointer<c2s_st> c2s = c->c2s;
    int max_bits_per_sec = 1024;
    try {
	max_bits_per_sec = j_atoi(c2s->config->get_string("io.max_bps").c_str(), 1024);
    } catch (Glib::ustring) {
	DBG("No explicit definition of io.max_bps in configuration");
    }
    // START OLDCODE
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
    bad_conn = new bad_conn_st;
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

    DBG("conn_read: len(" << len << ")");

    /* client gone */
    if(len == 0)
    {
        mio_close(c->c2s->mio, c->fd);
        return 0;
    }

    /* deal with errors */
    if(len < 0)
    {
        DBG("conn_read: errno(" << errno << " : " << strerror(errno) << ")");

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
    
    while(cur_len < len && c->fd >= 0)
    {
        /* Look for a shorter buffer based on \0 */
        char* new_buf = &buf[cur_len];
        int max_len = strlen(new_buf);
        if ((len - cur_len) < max_len)
            max_len = (len - cur_len);
        
        DBG("processing read data from " << c->fd << ": " << std::string(new_buf, max_len));

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

	if (c->fd < 0)
	    return 0;

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
	    conn_close(c, "", "");
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

    DBG("conn_write()");

    /* try to write as much as we can */
    while((cur = c->writeq) != NULL)
    {
        DBG("writing data to " << c->fd << ": " << std::string(cur->wcur, cur->wlen));

        /* write a bit from the current buffer */
        len = _write_actual(c, c->fd, cur->wcur, cur->wlen);

	DBG("written to socket, wlen=" << cur->wlen << ", len=" << len << ", errno=" << errno);

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

    DBG("end of conn_write()");
    return 0;
}

#ifdef USE_SSL
static void _log_ssl_io_error(xmppd::logging *l, SSL *ssl, int retcode, int fd, const Glib::ustring& used_func) {
    int ssl_error;

    ssl_error = SSL_get_error(ssl, retcode);

    if (ssl_error == SSL_ERROR_WANT_READ ||
	    ssl_error == SSL_ERROR_WANT_WRITE ||
    	    (ssl_error == SSL_ERROR_SYSCALL && errno == 0))
	return;

    l->level(LOG_NOTICE) << used_func << " on fd " << fd << " returned " << retcode;
    switch (ssl_error) {
	case SSL_ERROR_ZERO_RETURN:
	    l->level(LOG_NOTICE) << "SSL/TLS connection has been closed";
	    break;
	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
	    l->level(LOG_DEBUG) << "SSL/TLS needs more data from BIO to connect/accept";
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    l->level(LOG_DEBUG) << "want X509 lookup (shout not happen)";
	    break;
	case SSL_ERROR_SYSCALL:
	    l->level(LOG_NOTICE) << "syscall error occurred";
	    if (ERR_peek_error() == 0) {
		l->level(LOG_NOTICE) << strerror(errno);
	    } else {
		l->level(LOG_NOTICE).ssl_errors();
	    }
	    break;
	case SSL_ERROR_SSL:
	    l->level(LOG_NOTICE).ssl_errors();
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
	    c->c2s->log->level(LOG_NOTICE) << "SSL/TLS established on fd " << c->fd << ": " << SSL_get_version(c->ssl) << " " << SSL_get_cipher(c->ssl);
	if (bytes_read <= 0)
	    _log_ssl_io_error(c->c2s->log, c->ssl, bytes_read, c->fd, "SSL_read");

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
	    _log_ssl_io_error(c->c2s->log, c->ssl, bytes_read, c->fd, "SSL_peek");

        return bytes_read;
    }
#endif

    return recv(fd, buf, count, MSG_PEEK);
}


static int _write_actual(conn_t c, int fd, const char *buf, size_t count)
{
    int written;
    int truncated_write = 0;

    DBG("writing: " << std::string(buf, count));

#ifdef WITH_SASL
    if (c->sasl_conn && c->sasl_state != state_auth_NONE) {
    }
#endif

#ifdef USE_SSL
    if(c->ssl != NULL) {
        written = SSL_write(c->ssl, buf, count);
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
	    _log_ssl_io_error(c->c2s->log, c->ssl, written, c->fd, "SSL_write");

	DBG("written using OpenSSL");
        return truncated_write ? *c->sasl_outbuf_size : written; /* XXX we currently do not handle SASL blocks, that are only half written to the socket */
    }
#endif
        
    written = write(fd, buf, count);
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
    DBG("written - unencrypted");
    return truncated_write ? *c->sasl_outbuf_size : written; /* XXX we currently do not handle SASL blocks, that are only half written to the socket */
}

void connectionstate_fillnad(nad_t nad, Glib::ustring from, Glib::ustring to, Glib::ustring user, int is_login, const Glib::ustring &ip, const char *ssl_version, const char *ssl_cipher, const char *ssl_size_secret, const char *ssl_size_algorithm)
{
    nad_append_elem(nad, "message", 0);
    nad_append_attr(nad, "from", from.c_str());
    nad_append_attr(nad, "to", to.c_str());
    nad_append_elem(nad, "update", 1);
    nad_append_attr(nad, "xmlns", "http://amessage.info/protocol/connectionstate");
    nad_append_elem(nad, "jid", 2);
    nad_append_cdata(nad, user.c_str(), user.length(), 3);
    if (is_login)
	nad_append_elem(nad, "login", 2);
    else
	nad_append_elem(nad, "logout", 2);
    nad_append_elem(nad, "ip", 2);
    nad_append_cdata(nad, ip.c_str(), ip.length(), 3);
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

void connectionstate_send(xmppd::pointer<xmppd::configuration> config, conn_t c, conn_t client, int is_login) {
    chunk_t chunk;
    int i;

    // anyone that gets a notification?
    if (config->find("io.notifies") == config->end())
	return;

    /* send the connection state update to each configured destination */
    std::list<xmppd::configuration_entry>::const_iterator p;
    for (p=(*config)["io.notifies"].begin(); p!=(*config)["io.notifies"].end(); ++p) {
	const char *ssl_version = NULL;
	const char *ssl_cipher = NULL;
	std::ostringstream ssl_size_secret;
	std::ostringstream ssl_size_algorithm;

#ifdef USE_SSL
	if (client->ssl != NULL)
	{
	    int bits_secret, bits_algorithm;

	    ssl_version = SSL_get_version(client->ssl);
	    ssl_cipher = SSL_get_cipher(client->ssl);
	    bits_secret = SSL_get_cipher_bits(client->ssl, &bits_algorithm);
	    ssl_size_secret << bits_secret;
	    ssl_size_algorithm << bits_algorithm;
	}
#endif

	c->nad = nad_new(c->c2s->nads);
	connectionstate_fillnad(c->nad, client->myid->full(), p->value, client->userid->full(), is_login, client->ip, ssl_version, ssl_cipher, ssl_size_secret.str().c_str(), ssl_size_algorithm.str().c_str());
	chunk = chunk_new(c);
	chunk_write(c, chunk, "", "", "");
    }
}

conn_st::conn_st(xmppd::pointer<c2s_st> c2s) : c2s(c2s), fd(-1), port(0),
    read_bytes(0), last_read(0), state(state_NONE), type(type_NORMAL), start(0),
    root_element(root_element_NONE), writeq(NULL), qtail(NULL), expat(NULL), depth(0), nad(NULL),
    myid(NULL), smid(NULL), userid(NULL), authzid(NULL)
#ifdef USE_SSL
    , ssl(NULL), autodetect_tls(autodetect_NONE)
#endif
{
}

void conn_st::reset() {
    c2s = NULL;
    fd = -1;
    ip = "";
    port = 0;
    read_bytes = 0;
    last_read = 0;
    state = state_NONE;
    type = type_NORMAL;
    start = 0;
    root_element = root_element_NONE;
    local_id = "";
#ifdef USE_SSL
    ssl = NULL;
    autodetect_tls = autodetect_NONE;
#endif
    sid = "";
    sc_sm = "";
    id_session_start = "";
    myid = NULL;
    smid = NULL;
    userid = NULL;
    authzid = NULL;
    writeq = NULL;
    qtail = NULL;
    expat = NULL;
    depth = 0;
    nad = NULL;
#ifdef FLASH_HACK
    flash_hack = 0;
#endif
    in_bytes = 0;
    out_bytes = 0;
    in_stanzas = 0;
    out_stanzas = 0;
    reset_stream = 0;
#ifdef WITH_SASL
    sasl_conn = NULL;
    sasl_outbuf_size = NULL;
#endif
    sasl_state = state_auth_NONE;
}
