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

static char header_start[] = "<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams'";

/* handle new elements */
void _client_startElement(void *arg, const char* name, const char** atts)
{
    conn_t c = (conn_t)arg;
    int i = 0, error;
    char *header, *header_from, header_id[30], header_end[3];
    char sid[24];

    if (c->flash_hack == 1)
        return;

    c->root_name = strdup(name);
    if (j_strcmp(name, "flash:stream") == 0)
    {
        c->type = type_FLASH;
        c->flash_hack = 1;
    }

    /* process stream header first */
    if(c->depth == 0)
    {
        /* Iterate over the attributes and test them
         * error tracks the required attributes in the header */
        error = 3;
        while (atts[i] != '\0')
        {
            /* We have the primary namespace */
            if (j_strcmp(atts[i], "xmlns") == 0)
            {
                log_debug(ZONE, "checking xmlns: %s", atts[i+1]);
                if (j_strcmp(atts[i+1], "jabber:client") != 0)
                {
                    _write_actual(c, c->fd, "<stream:error>Invalid namespace, should be using jabber:client</stream:error>", 77);
                    c->depth = -1;
                    return;
                }

                error--;
            }

            /* to attribute */
            if (j_strcmp(atts[i], "to") == 0)
            {
                int id;
                log_debug(ZONE, "checking to: %s", atts[i+1]);
                for( id = 0; id < c->c2s->local_id->nvalues ; id++ )
                {
                    if (j_strcmp(atts[i+1], c->c2s->local_id->values[id]) == 0)
                    {
                        c->local_id = c->c2s->local_id->values[id];

                        log_debug(ZONE, "matched local id '%s''", c->local_id);
                        id = c->c2s->local_id->nvalues;
                    }
                }

                if (c->local_id == NULL)
                {
                    _write_actual(c, c->fd, "<stream:error>Invalid to address</stream:error>", 47);
                    c->depth = -1;
                    return;
                }

                error--;
            }

            /* stream namespace */
            /* If the root tag is flash:stream then this is a Flash connection */
            if (j_strcmp(name, "flash:stream") == 0)
            {
                if (j_strcmp(atts[i], "xmlns:flash") == 0)
                {
                    log_debug(ZONE, "checking xmlns:flash: %s", atts[i+1]);
                    if (j_strcasecmp(atts[i+1], 
                                     "http://www.jabber.com/streams/flash") != 0)
                    {
                        /* XXX error */
                        _write_actual(c, c->fd, "<stream:error>Invalid stream namespace</stream:error>", 53);
                        c->depth = -1;
                        return;
                    }

                    error--;
                }
            }
            /* This is a normal stream:stream tag... */
            else if (j_strcmp(atts[i], "xmlns:stream") == 0)
            {
                log_debug(ZONE, "checking xmlns:stream: %s", atts[i+1]);
                if (j_strcasecmp(atts[i+1], 
                                 "http://etherx.jabber.org/streams") != 0)
                {
                    /* XXX error */
                    _write_actual(c, c->fd, "<stream:error>Invalid stream namespace</stream:error>", 53);
                    c->depth = -1;
                    return;
                }

                error--;
            }

            i+=2;
        }
        
        if (error > 0)
        {
            log_debug(ZONE, "Required header attributes were not specified: %d",
                    error);
            c->depth = -1;
            return;
        }

        /* XXX fancier algo for id generation? */
        snprintf(sid, 24, "%d", rand());

        header_from = malloc( 9 + strlen( c->local_id ) );
        sprintf(header_from, " from='%s'", c->local_id);

        sprintf(header_id, " id='%s'", sid);

        if (c->type == type_FLASH)
            strcpy(header_end,"/>");
        else
            strcpy(header_end,">");

        header = malloc( strlen(header_start) + strlen(header_from) + strlen(header_id) + strlen(header_end) + 1);
        sprintf(header,"%s%s%s%s",header_start,header_from,header_id,header_end);
        
        _write_actual(c,c->fd,header,strlen(header));
        free(header);
        free(header_from);

        c->sid = strdup(sid);
        /* set up smid based on to="" host */
        c->smid = jid_new(c->idp,j_attr(atts,"to"));
        c->depth++;

        /* The flash:stream ends in a /> so we need to hack around this... */
        if (c->type == type_FLASH)
            c->depth++;

        return;
    }

    /* make a new nad if we don't already have one */
    if(c->nad == NULL)
        c->nad = nad_new(c->c2s->nads);

    /* append new element data to nad */
    nad_append_elem(c->nad, (char *) name, c->depth);
    i = 0;
    while(atts[i] != '\0')
    {
        nad_append_attr(c->nad, (char *) atts[i], (char *) atts[i+1]);
        i += 2;
    }

    /* going deeper */
    c->depth++;
}

/* prototype */
void _client_process(conn_t c);

void _client_endElement(void *arg, const char* name)
{
    conn_t c = (conn_t)arg;

    /* going up for air */
    c->depth--;

    if(c->depth == 1)
    {
        _client_process(c);
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

void _client_charData(void *arg, const char *str, int len)
{
    conn_t c = (conn_t)arg;

    /* if we're in the root of the stream the CDATA is irrelevant */
    if(c->nad == NULL) return;

    nad_append_cdata(c->nad, (char *) str, len, c->depth);
}

/* process completed nads */
void _client_process(conn_t c) {
    chunk_t chunk;
    int elem, attr, attr2;
    char str[770]; /* see jep29, 256(node) + 1(@) + 255(domain) + 1(/) + 256(resource) + 1(\0) */

    log_debug(ZONE, "got packet from client, processing");

    chunk = chunk_new(c);

    if (chunk->nad == NULL)
        return;
    
    log_debug(ZONE, "tag(%s)",NAD_ENAME(chunk->nad, 0));

    /* handle auth requests */
    if((c->state != state_OPEN) && 
       (j_strncmp(NAD_ENAME(chunk->nad, 0), "iq", 2) == 0))
    {
        attr = nad_find_attr(chunk->nad, 1, "xmlns", NULL);
        attr2 = nad_find_attr(chunk->nad, 0, "type", NULL);
        if (attr >= 0 &&
            (
             (j_strncmp(NAD_AVAL(chunk->nad, attr), "jabber:iq:auth", 14) == 0) ||
             (
              (j_strncmp(NAD_AVAL(chunk->nad, attr), "jabber:iq:register", 18) == 0) &&
              (j_strncmp(NAD_AVAL(chunk->nad, attr2), "set", 3) == 0)
             )
            )
           )
        {
            /* sort out the username */
            elem = nad_find_elem(chunk->nad, 0, "username", 2);
            if(elem == -1)
            {
                log_debug(ZONE, "auth packet with no username, dropping it");
                chunk_free(chunk);
                return;
            }
            
            snprintf(str, 770, "%.*s", NAD_CDATA_L(chunk->nad, elem), NAD_CDATA(chunk->nad, elem));
            jid_set(c->smid, str, JID_USER);
        }

        
        if (attr >= 0 &&
            (j_strncmp(NAD_AVAL(chunk->nad, attr), "jabber:iq:auth", 14) == 0))
        {

            /* and the resource, for sets */
            attr2 = nad_find_attr(chunk->nad, 0, "type", NULL);
            if(attr2 >= 0 && 
               j_strncmp(NAD_AVAL(chunk->nad, attr2), "set", 3) == 0 &&
               j_strncmp(NAD_AVAL(chunk->nad, attr), "jabber:iq:auth", 14) == 0)
            {
                elem = nad_find_elem(chunk->nad, 0, "resource", 2);
                if(elem == -1)
                {
                    log_debug(ZONE, "auth packet with no resource, dropping it");
                    chunk_free(chunk);
                    return;
                }
                
                snprintf(str, 770, "%.*s", NAD_CDATA_L(chunk->nad, elem), NAD_CDATA(chunk->nad, elem));
                jid_set(c->smid, str, JID_RESOURCE);

                /* add the stream id to digest packets */
                elem = nad_find_elem(chunk->nad, 0, "digest", 2);
                if(elem >= 0 && c->sid != NULL)
                    nad_set_attr(chunk->nad, elem, "sid", c->sid);
                
                /* we're in the auth state */
                c->state = state_AUTH;
            }
        }
    }

    /* send it */
    switch(c->state) {
        /* normal packets */
        case state_OPEN:
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

/* handle the incoming client mio events */
int client_io(mio_t m, mio_action_t a, int fd, void *data, void *arg)
{
    char buf[1024]; /* !!! make static when not threaded? move into conn_st? */
    int len, ret;
    conn_t c = (conn_t)arg;
#ifdef USE_SSL
    struct sockaddr_in sa;
    int namelen = sizeof(struct sockaddr_in);
#endif
    chunk_t chunk;
    int firstlen;
    char first[2];

    log_debug(ZONE,"io action %d with fd %d",a,fd);

    switch(a)
    {
    case action_ACCEPT:
        log_debug(ZONE,"new client conn %d from ip %s",fd,(char*)data);

        if (connection_rate_check((c2s_t)arg, (char*)data))
        {
            /* We had a bad rate, dump them (send an error?) */
            log_debug(ZONE, "rate limit is bad for %s, closing", (char*)data);
            /* return 1 to get rid of this fd */
            return 1;
        }

        /* set up the new client conn */
        c = conn_new((c2s_t)arg, fd);
        mio_app(m, fd, client_io, (void*)c);


#ifdef USE_SSL
        /* figure out if they came in on the ssl port or not, and flag them accordingly */
        getsockname(fd, (struct sockaddr *)&sa, &namelen);
        if(ntohs(sa.sin_port) == c->c2s->local_sslport) {

            /* !!! better error checking */
            c->ssl = SSL_new(c->c2s->ssl_ctx);
            SSL_set_fd(c->ssl, fd);
            SSL_accept(c->ssl);
        }
#endif

        /* put us in the pre-auth hash */
        xhash_put(c->c2s->pending,jid_full(c->myid), (void*)c);

        /* set up expat callbacks */
        XML_SetUserData(c->expat, (void*)c);
        XML_SetElementHandler(c->expat, (void*)_client_startElement, (void*)_client_endElement);
        XML_SetCharacterDataHandler(c->expat, (void*)_client_charData);

#ifdef USE_SSL
        /* Ok... we only check for HTTP connections on non-ssl connections. */
        if (c->ssl == NULL)
        {
#endif
            /* Read the first character... It means something */
            log_debug(ZONE,"Check the first char");
            while((firstlen = _peek_actual(c,fd,first,1)) == -1) { }
            log_debug(ZONE,"char(%c)",first[0]);

            /* If the first char is P then it's for HTTP (PUT ....) */
            if (first[0] == 'P')
            {
                char* http = "HTTP/1.0 200 Ok\r\nServer: jabber/xmlstream-hack-0.1\r\nExpires: Fri, 10 Oct 1997 10:10:10 GMT\r\nPragma: no-cache\r\nCache-control: private\r\nConnection: close\r\n\r\n";
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
                c->type = type_HTTP;
            }

            /* If the first char is a \0 then the other side expects that all
             * packets will end in a \0.  All packets.  This means that we
             * need to make sure that we handle it correctly in all cases.
             */
            if (first[0] == '\0')
            {
                _read_actual(c,fd,first,1);
                c->type = type_FLASH;
            }
            
#ifdef USE_SSL
        }
#endif

        /* count the number of open client connections */
        c->c2s->num_clients++;

        /* get read events */
        mio_read(m, fd);
        break;

    case action_READ:

        /* Big hack time... Flash sucks by the way */
        if (c->flash_hack == 1)
        {
            log_debug(ZONE,"Flash Hack... get rid of the old Parser, and make a new one... stupid Flash...");
            XML_ParserFree(c->expat);
            c->expat = XML_ParserCreate(NULL);

            /* set up expat callbacks */
            XML_SetUserData(c->expat, (void*)c);
            XML_SetElementHandler(c->expat, (void*)_client_startElement, (void*)_client_endElement);
            XML_SetCharacterDataHandler(c->expat, (void*)_client_charData);

            XML_Parse(c->expat, "<stream:stream>", 15, 0);

            c->flash_hack = 0;
        }
        
        log_debug(ZONE,"io action %d with fd %d in state %d",a,fd,c->state);

        /* we act differently when reading data from the client based on it's auth state */
        switch(c->state)
        {
        case state_OPEN:
            /* read a chunk at a time */
            len = _read_actual(c, fd, buf, conn_max_read_len(c));
            return conn_read(c, buf, len);

        case state_NONE:
            /* before the client is authorized, we tip-toe through the data to find the auth packets */
            while(c->state == state_NONE)
            {
                len = _read_actual(c, fd, buf, 10);
                if((ret = conn_read(c, buf, len)) == 0) return 0;
                /* come back again if no more data */
                if(ret == 2 || len < 10) return 1;
            }
            return 0;

        case state_AUTH:
        case state_SESS:
            return 0;
        }

    case action_WRITE:

        /* let's break this into another function, it's a bit messy */
        return conn_write(c);

    case action_CLOSE:

        /* Process on a valid conn */
        if(c->state == state_OPEN)
        {
            chunk_t cur, next;

            /* bounce write queue back to sm and close session */
            if(c->writeq != NULL)
            {
                for(cur = c->writeq; cur != NULL; cur = next)
                {
                    next = cur->next;
                    chunk_write(c->c2s->sm, cur, jid_full(c->smid), jid_full(c->myid), "error");
                }
            }else{
                /* if there was a nad being created, ditch it */
                if(c->nad != NULL)
                {
                    nad_free(c->c2s->nads, c->nad);
                    c->nad = NULL;
                }
                /* always send some sort of error */
                chunk = chunk_new(c);
                chunk_write(c->c2s->sm, chunk, jid_full(c->smid), jid_full(c->myid), "error");
                chunk = NULL;
            }

        }else{
            /* !!! free write queue */
            /* remove from preauth hash */
            xhash_zap(c->c2s->pending,jid_full(c->myid));
        }

        /* count the number of open client connections */
        c->c2s->num_clients--;

        conn_free(c);
        break;
    }
    return 0;
}


