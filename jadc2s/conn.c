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
    static int up = 0;

    c = (conn_t)malloc(sizeof(struct conn_st));
    memset(c, 0, sizeof(struct conn_st));

    /* set up some basic defaults */
    c->c2s = c2s;
    c->fd = fd;
    c->last_read = 0;
    c->read_bytes = 0;
    c->sid = NULL;
    c->root_name = NULL;
    c->state = state_NONE;
    c->type = type_NORMAL;
    c->start = time(NULL);
    c->expat = XML_ParserCreate(NULL);

    /* set up our id and put us in the conn hash */
    c->idp = pool_heap(128);
    c->myid = jid_new(c->idp, c2s->sm_id);
    snprintf(buf,16,"%d",up++);
    jid_set(c->myid, buf, JID_USER);
    xhash_put(c2s->conns,jid_full(c->myid), (void*)c);
    
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
    xhash_zap(c->c2s->conns,jid_full(c->myid));
    pool_free(c->idp);
    free(c);
}

/* write errors out and close streams */
void conn_close(conn_t c, char *err)
{
    if(c != NULL)
    {
        char* footer;
        footer = malloc( 3 + strlen(c->root_name) );
        sprintf(footer,"</%s>",c->root_name);
    
        log_debug(ZONE,"closing stream with error: %s",err);
        _write_actual(c, c->fd, "<stream:error>",14);
        if(err != NULL)
            _write_actual(c, c->fd, err, strlen(err));
        else
            _write_actual(c, c->fd, "Unknown Error", 13);
        _write_actual(c, c->fd, "</stream:error>",15);
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

    /* nad gets tranferred from the conn to the chunk */
    chunk->nad = c->nad;
    chunk->nads = c->c2s->nads;
    c->nad = NULL;

    return chunk;
}

/* free a chunk */
void chunk_free(chunk_t chunk)
{
    if(chunk->to != NULL) free(chunk->to);
    if(chunk->from != NULL) free(chunk->from);

    nad_free(chunk->nads, chunk->nad);

    free(chunk);
}

/* write a chunk to a conn */
void chunk_write(conn_t c, chunk_t chunk, char *to, char *from, char *type)
{
    /* make an empty nad if there isn't one */
    if(chunk->nad == NULL)
        chunk->nad = nad_new(c->c2s->nads);

    /* prepend optional route data */
    if(to != NULL)
    {
        nad_wrap_elem(chunk->nad, chunk->packet_elem, "route");
        nad_set_attr(chunk->nad, chunk->packet_elem, "to", to);
        nad_set_attr(chunk->nad, chunk->packet_elem, "from", from);
        if(type != NULL)
            nad_set_attr(chunk->nad, chunk->packet_elem, "type", type);
    }

    /* turn the nad into xml */
    nad_print(chunk->nad, chunk->packet_elem, &chunk->wcur, &chunk->wlen);

    /* append to the outgoing write queue, if any */
    if(c->qtail == NULL)
    {
        c->qtail = c->writeq = chunk;
    }else{
        c->qtail->next = chunk;
        c->qtail = chunk;
    }

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
    int max_bits_per_sec = j_atoi(xhash_get(c2s->config, "max_bps"), 0);
    time_t now;
    int bytes;

    /* They have disabled this */
    if (max_bits_per_sec <= 0)
        return 1024;
    /* See if we can reset them */
    if ((time(&now) - c->last_read) > 1)
    {
        c->last_read = now;
        c->read_bytes = 0;
        bytes = max_bits_per_sec * 8;
    }
    else
    {
        bytes = (max_bits_per_sec * 8) - c->read_bytes;
    }

    /* See if the user ate all their karma */
    if (bytes == 0)
    {
        /* Create a new bad conn */
        bad_conn_t bad_conn;
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
    }

    return bytes;
}

/* process the xml data that's been read */
int conn_read(conn_t c, char *buf, int len)
{
    char *err = NULL;

    log_debug(ZONE,"conn_read: len(%d)",len);
    log_debug(ZONE,"conn_read: errno(%d : %s)",errno,strerror(errno));

    /* client gone */
    if(len == 0)
    {
        mio_close(c->c2s->mio, c->fd);
        return 0;
    }

    /* deal with errors */
    if(len < 0)
    {
        if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
            return 2; /* flag that we're blocking now */
        mio_close(c->c2s->mio, c->fd);
        return 0;
    }

    log_debug(ZONE,"processing read data from %d: %.*s", c->fd, len, buf);

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
    if(err != NULL)
    {
        conn_close(c, err);
        return 0;
    }

    /* if we got </stream:stream>, this is set */
    if(c->depth < 0)
    {
        char* footer;
        footer = malloc( 3 + strlen(c->root_name) );
        sprintf(footer,"</%s>",c->root_name);
        _write_actual(c, c->fd, footer, strlen(footer));
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
        return SSL_read(c->ssl, buf, count);
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
    char realbuf[count+1];

    strncpy(realbuf,buf,count);
    if (c->type == type_FLASH)
    {
        realbuf[count] = '\0';
        count++;
    }
            
#ifdef USE_SSL
    if(c->ssl != NULL)
        return SSL_write(c->ssl, realbuf, count);
#endif

    return write(fd, realbuf, count);
}

