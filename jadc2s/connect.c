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

/* handle new elements */
void _connect_startElement(void *arg, const char* name, const char** atts)
{
    conn_t c = (conn_t)arg;
    int i = 0;
    char buf[128];

    /* track how far down we are in the xml */
    c->depth++;

    /* process stream header first */
    if(c->depth == 1)
    {
        /* Extract stream ID and generate a key to hash */
        snprintf(buf, 128, "%s", shahash(spools(c->idp, j_attr(atts, "id"), c->c2s->sm_secret, c->idp)));

        /* create a new nad */
        c->nad = nad_new(c->c2s->nads);
        nad_append_elem(c->nad, "handshake", 1);
        nad_append_cdata(c->nad, buf, strlen(buf), 2);

        log_debug(ZONE,"handshaking with sm");

        /* create a chunk and write it */
        chunk_write(c, chunk_new(c), NULL, NULL, NULL);

        return;
    }

    /* make a new nad if we don't already have one */
    if(c->nad == NULL)
        c->nad = nad_new(c->c2s->nads);

    /* append new element data to nad */
    nad_append_elem(c->nad, (char *) name, c->depth - 1);
    i = 0;
    while(atts[i] != '\0')
    {
        nad_append_attr(c->nad, (char *) atts[i], (char *) atts[i + 1]);
        i += 2;
    }
}

/* prototype */
void _connect_process(conn_t c);

void _connect_endElement(void *arg, const char* name)
{
    conn_t c = (conn_t)arg;

    /* going up for air */
    c->depth--;

    if(c->depth == 1)
    {
        _connect_process(c);
        if(c->nad != NULL)
        {
            nad_free(c->c2s->nads, c->nad);
            c->nad = NULL;
        }
    }

    /* if we processed the closing stream root, flag to close l8r */
    if(c->depth == 0)
        c->depth = -1; /* we can't close here, expat gets free'd on close :) */
}


void _connect_charData(void *arg, const char *str, int len)
{
    conn_t c = (conn_t)arg;

    /* no nad? no cdata */
    if(c->nad == NULL) return;

    nad_append_cdata(c->nad, (char *) str, len, c->depth);
}

/* process completed nads */
void _connect_process(conn_t c) {
    chunk_t chunk;
    int attr;
    char str[770], cid[770]; /* see jep29, 256(node) + 1(@) + 255(domain) + 1(/) + 256(resource) + 1(\0) */
    conn_t target;

    log_debug(ZONE, "got packet from sm, processing");

    /* always check for the return handshake :) */
    if(c->state != state_OPEN)
    {
        if(j_strncmp(NAD_ENAME(c->nad, 0), "handshake", 9) == 0)
        {
            c->state = state_OPEN;
            log_debug(ZONE,"handshake accepted, we're connected to the sm");
        }
        return;
    }

    /* just ignore anything except route packets */
    if(j_strncmp(NAD_ENAME(c->nad, 0), "route", 5) != 0) return;

    /* every route must have a target client id */
    if((attr = nad_find_attr(c->nad, 0, "to", NULL)) == -1) return;

    snprintf(cid, 770, "%.*s", NAD_AVAL_L(c->nad, attr), NAD_AVAL(c->nad, attr));
    target = xhash_get(c->c2s->conns, cid);

    log_debug(ZONE, "processing route to %s with target %X", cid, target);

    attr = nad_find_attr(c->nad, 0, "type", NULL);
    if(attr >= 0 && j_strncmp(NAD_AVAL(c->nad, attr), "error", 5) == 0)
    {
        /* disconnect if they come from a target with matching sender */
        /* simple auth responses that don't have a client connected get dropped */
        attr = nad_find_attr(c->nad, 0, "from", NULL);
        if(target != NULL && j_strncmp(jid_full(target->smid), NAD_AVAL(c->nad, attr), NAD_AVAL_L(c->nad, attr)))
        {
            attr = nad_find_attr(c->nad, 0, "error", NULL);
            snprintf(str, 770, "%.*s", NAD_AVAL_L(c->nad, attr), NAD_AVAL(c->nad, attr));
            conn_close(target, str);
        }
        return;
    }

    attr = nad_find_attr(c->nad, 0, "from", NULL);
    snprintf(str, 770, "%.*s", NAD_AVAL_L(c->nad, attr), NAD_AVAL(c->nad, attr));

    /* look for session creation responses and change client accordingly 
     * (note: if no target drop through w/ chunk since it'll error in endElement) */
    if (target != NULL)
    {
        attr = nad_find_attr(c->nad, 0, "type", NULL);
        if(attr >= 0 && j_strncmp(NAD_AVAL(c->nad, attr), "session", 7) == 0)
        {
            log_debug(ZONE, "client %d now has a session %s", target->fd, str);
            target->state = state_OPEN;
            xhash_zap(c->c2s->pending, jid_full(target->myid));
            target->smid = jid_new(target->idp, str);
            mio_read(c->c2s->mio, target->fd); /* start reading again now */
        }
    }

    /* the rest of them we just need a chunk to store until they get sent to the client */
    chunk = chunk_new(c);
    chunk->to = strdup(cid);
    chunk->from = strdup(str);

    /* its a route, so the packet proper starts at element 1 */
    chunk->packet_elem = 1;

    /* look for iq results for auths */
    if((target = xhash_get(c->c2s->pending, chunk->to)) != NULL && target->state == state_AUTH)
    {
        /* got a result, start a session */
        attr = nad_find_attr(chunk->nad, 1, "type", NULL);
        if(attr >= 0 && j_strncmp(NAD_AVAL(chunk->nad, attr), "result", 6) == 0)
        {
            /* auth was ok, send session request */
            log_debug(ZONE,"client %d authorized, requesting session",target->fd);
            chunk_write(c, chunk, jid_full(target->smid), jid_full(target->myid), "session");
            target->state = state_SESS;

            return;
        }else{ /* start over */
            target->state = state_NONE;
        }
    }

    /* now we have to do something with our chunk */
    log_debug(ZONE,"sm sent us a chunk for %s",chunk->to);

    /* either bounce or send the chunk to the client */
    if((target = xhash_get(c->c2s->conns,chunk->to)) != NULL)
        chunk_write(target, chunk, NULL, NULL, NULL);
    else
        chunk_write(c, chunk, chunk->from, chunk->to, "error");
}

/* internal handler to read incoming data from the sm and parse/process it */
int _connect_io(mio_t m, mio_action_t a, int fd, void *data, void *arg)
{
    char buf[1024]; /* !!! make static when not threaded? move into conn_st? */
    int len, ret, x, retries;
    conn_t c = (conn_t)arg;
    c2s_t c2s;

    log_debug(ZONE,"io action %d with fd %d",a,fd);

    switch(a)
    {
    case action_READ:

        /* read as much data as we can from the sm */
        while(1)
        {
            len = read(fd, buf, 1024);
            if((ret = conn_read(c, buf, len)) != 1 || len < 1024) break;
        }
        return 1;

    case action_WRITE:

        /* let's break this into another function, it's a bit messy */
        return conn_write(c);

    case action_CLOSE:

        /* if we're closing before we're open, we've got issues */
        if(c->state != state_OPEN)
        {
            /* !!! handle this better */
            log_write(c2s->log, LOG_ERR, "secret is wrong or sm kicked us off for some other reason");
            exit(1);
        }

        log_debug(ZONE,"reconnecting to sm");

        /* try to connect again */
        c2s = c->c2s;
        retries = j_atoi(xhash_get(c2s->config, "sm.retries"), 5);
        for (x = 0; x < retries; x++)
        {
            if (connect_new(c2s))
                break;
            /* XXX: Make this an option? */
            sleep(5);
        }

        /* See if we were able to reconnect */
        if (x == retries)
        {
            log_write(c2s->log, LOG_ERR, "Unable to reconnect to the SM.");
            exit(1);
        }

        /* copy over old write queue if any */
        if(c->writeq != NULL)
        {
            c2s->sm->writeq = c->writeq;
            c2s->sm->qtail = c->qtail;
            mio_write(c2s->mio, c2s->sm->fd);
        }

        conn_free(c);
        break;

    case action_ACCEPT:
        break;
    }
    return 0;
}


int connect_new(c2s_t c2s)
{
    int fd;
    unsigned long int ip = 0;
    struct hostent *h;
    char iphost[16];
    struct sockaddr_in sa;
    conn_t c;
    char dummy[] = "<stream:stream xmlns='jabber:component:accept' xmlns:stream='http://etherx.jabber.org/streams' to='";

    log_write(c2s->log, LOG_NOTICE, "attempting connection to sm at %s:%d as %s", c2s->sm_host, c2s->sm_port, c2s->sm_id);

    /* get the ip to connect to */
    if(c2s->sm_host != NULL) {
        h = gethostbyname(c2s->sm_host);
        if(h == NULL) {
            log_write(c2s->log, LOG_ERR, "dns lookup for %s failed: %s", c2s->sm_host, hstrerror(h_errno));
            exit(1);
        }
        inet_ntop(AF_INET, h->h_addr_list[0], iphost, 16);
        ip = inet_addr(iphost);

        log_debug(ZONE, "resolved: %s = %s", c2s->sm_host, iphost);
    }

    /* attempt to create a socket */
    if((fd = socket(AF_INET,SOCK_STREAM,0)) < 0)
    {
        log_write(c2s->log, LOG_ERR, "failed to connect to sm: %s", strerror(errno));
        return 0;
    }

    /* set up and bind address info */
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(c2s->sm_port);
    if(ip > 0) sa.sin_addr.s_addr = ip;

    /* connect to the sm please */
    if(connect(fd,(struct sockaddr*)&sa,sizeof(sa)) < 0)
    {
        log_write(c2s->log, LOG_ERR, "failed to connect to sm: %s", strerror(errno));
        close(fd);
        return 0;
    }

    /* make sure mio will take this fd */
    if(mio_fd(c2s->mio, fd, NULL, NULL) < 0)
    {
        log_write(c2s->log, LOG_ERR, "failed to connect to sm: %s", strerror(errno));
        close(fd);
        return 0;
    }

    /* make our conn_t from this */
    c2s->sm = c = conn_new(c2s, fd);
    mio_app(c2s->mio, fd, _connect_io, (void*)c);
    mio_read(c2s->mio,fd);

    /* set up expat callbacks */
    XML_SetUserData(c->expat, (void*)c);
    XML_SetElementHandler(c->expat, (void*)_connect_startElement, (void*)_connect_endElement);
    XML_SetCharacterDataHandler(c->expat, (void*)_connect_charData);

    /* send stream header */
    write(fd,dummy,strlen(dummy));
    write(fd,c2s->sm_id,strlen(c2s->sm_id));
    write(fd,"'>",2);

    /* loop reading until it's open or dead */
    while(c->state != state_OPEN) _connect_io(c2s->mio, action_READ, fd, NULL, (void*)c);    

    log_write(c2s->log, LOG_NOTICE, "connection to sm completed");

    return 1;
}



