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
    c->root_name = NULL;
    c->local_id = NULL;
    c->state = state_NONE;
    c->type = type_NORMAL;
    c->start = time(NULL);
    c->expat = XML_ParserCreate(NULL);
    c->qtail = c->writeq = NULL;

    /* set up our id */
    c->idp = pool_heap(128);
    c->myid = jid_new(c->idp, c2s->sm_id);
    snprintf(buf,16,"%d",fd);
    jid_set(c->myid, buf, JID_USER);
    
    c->flash_hack = 0;

    return c;
}

/* free up memory (!caller must process anything in the writeq) */
void conn_free(conn_t c)
{
    if (c->sid != NULL) free(c->sid);
    if (c->root_name != NULL) free(c->root_name);
    XML_ParserFree(c->expat);
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
    if(c != NULL || (condition == NULL && err == NULL))
    {
	/* do we still have to open the stream? */
	if (c->root_name == NULL)
	{
	    if (c->flash_hack) {
		_write_actual(c, c->fd, "<flash:stream xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", 77);
		c->root_name = strdup("flash:stream");
	    } else {
		_write_actual(c, c->fd, "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>", 77);
		c->root_name = strdup("stream:stream");
	    }
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
}

/* write errors out and close streams */
void conn_close(conn_t c, char *condition, char *err)
{
    if(c != NULL)
    {
	char* footer;

	/* send the stream error */
	conn_error(c, condition, err);

	footer = malloc( 4 + strlen(c->root_name) );
	sprintf(footer,"</%s>",c->root_name);
	
	_write_actual(c, c->fd, footer, strlen(footer));
	free(footer);

        mio_close(c->c2s->mio, c->fd); /* remember, c is gone after this, re-entrant */
    }
}

/* create a new chunk, using the nad from this conn */
chunk_t chunk_new(conn_t c)
{
    chunk_t chunk = (chunk_t) malloc(sizeof(struct chunk_st));
    memset(chunk, 0, sizeof(struct chunk_st));

    chunk->next = NULL;

    /* nad gets tranferred from the conn to the chunk */
    chunk->nad = c->nad;
    c->nad = NULL;

    return chunk;
}

/* free a chunk */
void chunk_free(chunk_t chunk)
{
    nad_free(chunk->nad);

    free(chunk);
}

/* write a chunk to a conn */
void chunk_write(conn_t c, chunk_t chunk, char *to, char *from, char *type)
{
    int elem;

    /* make an empty nad if there isn't one */
    if(chunk->nad == NULL)
        chunk->nad = nad_new(c->c2s->nads);

    elem = chunk->packet_elem;

    /* prepend optional route data */
    if(to != NULL)
    {
        if(chunk->nad->ecur <= chunk->packet_elem)
            elem = nad_append_elem(chunk->nad, "route", 1);

        else {
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
    if(c->qtail == NULL)
    {
        c->qtail = c->writeq = chunk;
    }else{
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

    log_debug(ZONE,"processing read data from %d: %.*s", c->fd, len, buf);

    /* We can't parse \0... */
    if (buf[len-1] == '\0')
        len--;

    /* Update how much has been read */
    c->read_bytes += len;

    
    /* parse the xml baby */
    if(!XML_Parse(c->expat, buf, len, 0))
    {
        err = (char *)XML_ErrorString(XML_GetErrorCode(c->expat));
    }else if(c->depth > MAXDEPTH){
        err = MAXDEPTH_ERR;
    }

    /* oh darn */
    if((err != NULL) && (c->flash_hack == 0))
    {
        conn_close(c, STREAM_ERR_INVALID_XML, err);
        return 0;
    }

    /* if we got </stream:stream>, this is set */
    if(c->depth < 0)
    {
        size_t footersz;
        char* footer;
        footersz = 3 + strlen(c->root_name);
        footer = malloc(footersz+1);
        snprintf(footer, footersz+1, "</%s>", c->root_name);
        _write_actual(c, c->fd, footer, footersz);
        free(footer);
        mio_close(c->c2s->mio, c->fd);
        return 0;
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


int _read_actual(conn_t c, int fd, char *buf, size_t count)
{

#ifdef USE_SSL
    if(c->ssl != NULL)
    {
	int ssl_init_finished = SSL_is_init_finished(c->ssl);
	int bytes_read = SSL_read(c->ssl, buf, count);
	if (!ssl_init_finished && SSL_is_init_finished(c->ssl))
	    log_write(c->c2s->log, LOG_NOTICE, "ssl/tls established on fd %i: %s %s", c->fd, SSL_get_version(c->ssl), SSL_get_cipher(c->ssl));
        return bytes_read;
    }
#endif
    return read(fd, buf, count);
}


int _peek_actual(conn_t c, int fd, char *buf, size_t count)
{
    
#ifdef USE_SSL
    if(c->ssl != NULL)
        return SSL_peek(c->ssl, buf, count);
#endif

    return recv(fd, buf, count, MSG_PEEK);
}


int _write_actual(conn_t c, int fd, const char *buf, size_t count)
{
    int written;
    
#ifdef USE_SSL
    if(c->ssl != NULL)
    {
        written = SSL_write(c->ssl, buf, count);
        if (written > 0 && (c->type == type_FLASH))
            SSL_write(c->ssl, "\0", 1);
        return written;
    }
#endif
        
    written = write(fd, buf, count);
    if (written > 0 && (c->type == type_FLASH))
        write(fd, "\0", 1);
    return written;
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
