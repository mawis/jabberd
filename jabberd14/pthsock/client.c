/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

/*
    <service id="pthsock client">
      <host>pth-csock.127.0.0.1</host> <!-- Can be anything -->
      <load>
	    <pthsock_client>../load/pthsock_client.so</pthsock_client>
      </load>
      <pthcsock xmlns='jabber:config:pth-csock'>
        <listen>5222</listen>            <!-- Port to listen on -->
        <!-- allow 25 connects per 5 seconts -->
        <rate time="5" points="25"/> 
      </pthcsock>
    </service>
*/

#include <jabberd.h>
#define DEFAULT_AUTH_TIMEOUT 0

/* socket manager instance */
typedef struct smi_st
{
    instance i;
    int auth_timeout;
    HASHTABLE aliases;
    HASHTABLE users;
    xmlnode cfg;
    char *host;
} *smi, _smi;

typedef enum { state_UNKNOWN, state_AUTHD } user_state;
typedef struct cdata_st
{
    smi si;
    jid session_id;
    user_state state;
    char *client_id, *sid, *res, *auth_id;
    time_t connect_time;
    mio m;
    pth_msgport_t pre_auth_mp;
} _cdata,*cdata;

/* makes a route packet, intelligently */
xmlnode pthsock_make_route(xmlnode x, char *to, char *from, char *type)
{
    xmlnode new;
    new = x ? xmlnode_wrap(x, "route") : xmlnode_new_tag("route");

    if(type != NULL) 
        xmlnode_put_attrib(new, "type", type);

    if(to != NULL) 
        xmlnode_put_attrib(new, "to", to);

    if(from != NULL) 
        xmlnode_put_attrib(new, "from", from);

    return new;
}

/* incoming jabberd deliver()ed packets */
result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    smi s__i = (smi)arg;
    cdata cdcur;
    mio m;
    int fd = 0;

    if(p->id->user != NULL)
        fd = atoi(p->id->user); 
    
    if(p->type != p_ROUTE || fd == 0 || (cdcur = ghash_get(s__i->users, xmlnode_get_attrib(p->x, "to"))) == NULL)
    { /* we only want <route/> packets or ones with a valid connection */
        log_warn(p->host, "pthsock_client bouncing invalid %s packet from %s", xmlnode_get_name(p->x), xmlnode_get_attrib(p->x,"from"));
        deliver_fail(p, "invalid client packet");
        return r_DONE;
    }

    if (fd != cdcur->m->fd || cdcur->m->state != state_ACTIVE)
        m = NULL;
    else if (j_strcmp(p->id->resource,cdcur->res) != 0)
        m = NULL;
    else
        m = cdcur->m;

    if(m == NULL)
    { 
        if (j_strcmp(xmlnode_get_attrib(p->x, "type"), "error") == 0)
        { /* we got a 510, but no session to end */
            log_notice(p->host, "C2S received Session close for non-existant session: %s", xmlnode_get_attrib(p->x, "from"));
            xmlnode_free(p->x);
            return r_DONE;
        }

        log_notice(p->host, "C2S connection not found for %s, closing session", xmlnode_get_attrib(p->x, "from"));

        jutil_tofrom(p->x);
        xmlnode_put_attrib(p->x, "type", "error");

        deliver(dpacket_new(p->x), s__i->i);
        return r_DONE;
    }

    log_debug(ZONE, "C2S: %s has an active session, delivering packet", xmlnode_get_attrib(p->x, "from"));
    if (j_strcmp(xmlnode_get_attrib(p->x, "type"), "error") == 0)
    { /* <route type="error" means we were disconnected */
        log_notice(p->host, "C2S closing down session %s at request of session manager", xmlnode_get_attrib(p->x, "from"));
        mio_write(m, NULL, "<stream:error>Disconnected</stream:error></stream:stream>", -1);
        mio_close(m);
        xmlnode_free(p->x);
        return r_DONE;
    }
    else if(cdcur->state == state_UNKNOWN && j_strcmp(xmlnode_get_attrib(p->x, "type"), "auth") == 0)
    { /* look for our auth packet back */
        char *type = xmlnode_get_attrib(xmlnode_get_firstchild(p->x), "type");
        char *id   = xmlnode_get_attrib(xmlnode_get_tag(p->x, "iq"), "id");
        if((j_strcmp(type, "result") == 0) && j_strcmp(cdcur->auth_id, id) == 0)
        { /* update the cdata status if it's a successfull auth */
            xmlnode x;
            log_debug(ZONE, "auth for user successful");
            /* notify SM to start a session */
            x = pthsock_make_route(NULL, jid_full(cdcur->session_id), cdcur->client_id, "session");
            log_notice(p->host, "C2S requesting Session Start for %s", xmlnode_get_attrib(p->x, "from"));
            deliver(dpacket_new(x), s__i->i);
        } 
        else 
        {
            log_record(jid_full(jid_user(cdcur->session_id)), "login", "fail", "%s %s %s", mio_ip(cdcur->m), xmlnode_get_attrib(xmlnode_get_tag(p->x, "iq/error"),"code"), cdcur->session_id->resource);
        }
    } 
    else if(cdcur->state == state_UNKNOWN && j_strcmp(xmlnode_get_attrib(p->x, "type"), "session") == 0)
    { /* got a session reply from the server */
        mio_wbq q;

        cdcur->state = state_AUTHD;
        log_record(jid_full(jid_user(cdcur->session_id)), "login", "ok", "%s %s", mio_ip(cdcur->m), cdcur->session_id->resource);
        /* change the host id */
        cdcur->session_id = jid_new(m->p, xmlnode_get_attrib(p->x, "from"));
        xmlnode_free(p->x);
        /* if we have packets in the queue, write them */
        while((q = (mio_wbq)pth_msgport_get(cdcur->pre_auth_mp)) != NULL)
        {
            q->x = pthsock_make_route(q->x, jid_full(cdcur->session_id), cdcur->client_id, NULL);
            deliver(dpacket_new(q->x), s__i->i);
        }
        pth_msgport_destroy(cdcur->pre_auth_mp);
        cdcur->pre_auth_mp = NULL;
        return r_DONE;
    }


    if(xmlnode_get_firstchild(p->x) == NULL)
    {
        xmlnode_free(p->x);
    }
    else
    {
        log_debug(ZONE, "Writing packet to MIO: %s", xmlnode2str(xmlnode_get_firstchild(p->x)));
        mio_write(m, xmlnode_get_firstchild(p->x), NULL, 0);
    }

    return r_DONE;
}

cdata pthsock_client_cdata(mio m, smi s__i)
{
    cdata cd;
    char *buf;

    cd               = pmalloco(m->p, sizeof(_cdata));
    cd->pre_auth_mp  = pth_msgport_create("pre_auth_mp");
    cd->state        = state_UNKNOWN;
    cd->connect_time = time(NULL);
    cd->m            = m;
    cd->si           = s__i;

    buf = pmalloco(m->p, 100);

    /* HACK to fix race conditon */
    snprintf(buf, 99, "%X", m);
    cd->res = pstrdup(m->p, buf);

    /* we use <fd>@host to identify connetions */
    snprintf(buf, 99, "%d@%s/%s", m->fd, s__i->host, cd->res);
    cd->client_id = pstrdup(m->p, buf);

    return cd;
}

void pthsock_client_read(mio m, int flag, void *arg, xmlnode x)
{
    cdata cd = (cdata)arg;
    xmlnode h;
    char *alias, *to;

    if(cd == NULL) 
        return;

    log_debug(ZONE, "pthsock_client_read called with: m:%X flag:%d arg:%X", m, flag, arg);
    switch(flag)
    {
    case MIO_CLOSED:

        log_debug(ZONE, "io_select Socket %d close notification", m->fd);
        if(cd->state == state_AUTHD)
        {
            h = pthsock_make_route(NULL, jid_full(cd->session_id), cd->client_id, "error");
            deliver(dpacket_new(h), cd->si->i);
        }

        if(cd->pre_auth_mp != NULL)
        { /* if there is a pre_auth queue still */
            mio_wbq q;

            while((q = (mio_wbq)pth_msgport_get(cd->pre_auth_mp)) != NULL)
            {
                log_debug(ZONE, "freeing unsent packet due to disconnect with no auth: %s", xmlnode2str(q->x));
                xmlnode_free(q->x);
            }

            pth_msgport_destroy(cd->pre_auth_mp);
            cd->pre_auth_mp = NULL;
        } 
        break;
    case MIO_ERROR:
        while((h = mio_cleanup(m)) != NULL)
            deliver_fail(dpacket_new(h), "Socket Error to Client");

        break;
    case MIO_XML_ROOT:
        log_debug(ZONE, "root received for %d", m->fd);
        to = xmlnode_get_attrib(x, "to");

        /* check for a matching alias or use default alias */
        alias = ghash_get(cd->si->aliases, to);
        alias = alias ? alias : ghash_get(cd->si->aliases, "default");

        /* set host to that alias, or to the given host */
        cd->session_id = alias ? jid_new(m->p, alias) : jid_new(m->p, to);

        h = xstream_header("jabber:client", NULL, jid_full(cd->session_id));
        cd->sid = pstrdup(m->p, xmlnode_get_attrib(h, "id"));
        mio_write(m, NULL, xstream_header_char(h), -1);

        xmlnode_free(h);

        if(j_strcmp(xmlnode_get_attrib(x, "xmlns"), "jabber:client") != 0)
        { /* if they sent something other than jabber:client */
            mio_write(m, NULL, "<stream:error>Invalid Namespace</stream:error></stream:stream>", -1);
            mio_close(m);
        }
        else if(cd->session_id == NULL)
        { /* they didn't send a to="" and no valid alias */
            mio_write(m, NULL, "<stream:error>Did not specify a valid to argument</stream:error></stream:stream>", -1);
            mio_close(m);
        }
        else if(j_strncasecmp(xmlnode_get_attrib(x, "xmlns:stream"), "http://etherx.jabber.org/streams", 32) != 0)
        {
            mio_write(m, NULL, "<stream:error>Invalid Stream Namespace</stream:error></stream:stream>", -1);
            mio_close(m);
        }

        xmlnode_free(x);
        break;
    case MIO_XML_NODE:
        cd = (cdata)arg;
        if (cd->state == state_UNKNOWN)
        { /* only allow auth and registration queries at this point */
            xmlnode q = xmlnode_get_tag(x, "query");
            if (!NSCHECK(q, NS_AUTH) && !NSCHECK(q, NS_REGISTER))
            {
                mio_wbq q;
                /* queue packet until authed */
                q = pmalloco(xmlnode_pool(x), sizeof(_mio_wbq));
                q->x = x;
                pth_msgport_put(cd->pre_auth_mp, (void*)q);
                return;
            }
            else if (NSCHECK(q, NS_AUTH))
            {
                if(j_strcmp(xmlnode_get_attrib(x, "type"), "set") == 0)
                { /* if we are authing against the server */
                    xmlnode_put_attrib(xmlnode_get_tag(q, "digest"), "sid", cd->sid);
                    cd->auth_id = pstrdup(m->p, xmlnode_get_attrib(x, "id"));
                    if(cd->auth_id == NULL) 
                    {
                        cd->auth_id = pstrdup(m->p, "pthsock_client_auth_ID");
                        xmlnode_put_attrib(x, "id", "pthsock_client_auth_ID");
                    }
                    jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:auth"), "username")), JID_USER);
                    jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:auth"), "resource")), JID_RESOURCE);

                    x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, "auth");
                    deliver(dpacket_new(x), cd->si->i);
                }
                else if(j_strcmp(xmlnode_get_attrib(x, "type"), "get") == 0)
                { /* we are just doing an auth get */
                    /* just deliver the packet */
                    jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:auth"), "username")), JID_USER);
                    x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, "auth");
                    deliver(dpacket_new(x), cd->si->i);
                }
            }
            else if (NSCHECK(q, NS_REGISTER))
            {
                jid_set(cd->session_id, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:register"), "username")), JID_USER);
                x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, "auth");
                deliver(dpacket_new(x), cd->si->i);
            }
        }
        else
        {   /* normal delivery of packets after authed */
            x = pthsock_make_route(x, jid_full(cd->session_id), cd->client_id, NULL);
            deliver(dpacket_new(x), cd->si->i);
        }
        break;
    }
}


void pthsock_client_listen(mio m, int flag, void *arg, xmlnode x)
{
    smi s__i = (void*)arg;
    cdata cd;

    if(flag != MIO_NEW)
        return;

    s__i = (smi)arg;
    cd = pthsock_client_cdata(m, s__i);
    ghash_put_pool(cd->m->p, cd->si->users, cd->client_id, cd);
    mio_reset(m, pthsock_client_read, (void*)cd);
}


int _pthsock_client_timeout(void *arg, const void *key, void *data)
{
    time_t timeout;
    cdata cd = (cdata)data;
    if(cd->state == state_AUTHD) 
        return 1;

    timeout = time(NULL) - cd->si->auth_timeout;
    log_debug(ZONE, "timeout: %d, connect time %d: fd %d", timeout, cd->connect_time, cd->m->fd);

    if(cd->connect_time < timeout)
    {
        mio_write(cd->m, NULL, "<stream:error>Timeout waiting for authentication</stream:error></stream:stream>", -1);
        ghash_remove(cd->si->users, mio_ip(cd->m));
        mio_close(cd->m);
    }
    return 1;
}

/* auth timeout beat function */
result pthsock_client_timeout(void *arg)
{
    smi s__i = (smi)arg;
    ghash_walk(s__i->users, _pthsock_client_timeout, NULL);
    return r_DONE;
}

int _pthsock_client_shutdown(void *arg, const void *key, void *data)
{
    cdata cd = (cdata)data;
    log_debug(ZONE, "C2S closing down user %s from ip: %s", jid_full(cd->session_id), mio_ip(cd->m));
    mio_close(cd->m);
    return 1;
}

/* cleanup function */
void pthsock_client_shutdown(void *arg)
{
    smi s__i = (smi)arg;
    xmlnode_free(s__i->cfg);
    log_debug(ZONE, "C2S Shutting Down");
    ghash_walk(s__i->users, _pthsock_client_shutdown, NULL);
}

/* everything starts here */
void pthsock_client(instance i, xmlnode x)
{
    smi s__i;
    xdbcache xc;
    xmlnode cur;
    int rate_time = 0, rate_points = 0;
    char *host;
    struct karma k;

    log_debug(ZONE, "pthsock_client loading");

    s__i               = pmalloco(i->p, sizeof(_smi));
    s__i->auth_timeout = DEFAULT_AUTH_TIMEOUT;
    s__i->i            = i;
    s__i->aliases      = ghash_create_pool(i->p, 7, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);
    s__i->users        = ghash_create_pool(i->p, 503, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);

    /* get the config */
    xc = xdb_cache(i);
    s__i->cfg = xdb_get(xc, jid_new(xmlnode_pool(x), "config@-internal"), "jabber:config:pth-csock");

    s__i->host = host = i->id;

    k.val     =KARMA_INIT;
    k.bytes   = 0;
    k.max     = KARMA_MAX;
    k.inc     = KARMA_INC;
    k.dec     = KARMA_DEC;
    k.restore = KARMA_RESTORE;
    k.penalty = KARMA_PENALTY;

    for(cur = xmlnode_get_firstchild(s__i->cfg); cur != NULL; cur = cur->next)
    {
        if(cur->type != NTYPE_TAG) 
            continue;
        
        if(j_strcmp(xmlnode_get_name(cur), "alias") == 0)
        {
           char *host, *to;
           if((to = xmlnode_get_attrib(cur, "to")) == NULL) 
               continue;

           host = xmlnode_get_data(cur);
           if(host != NULL)
           {
               ghash_put_pool(s__i->i->p, s__i->aliases, host, to);
           }
           else
           {
               ghash_put_pool(s__i->i->p, s__i->aliases, "default", to);
           }
        }
        else if(j_strcmp(xmlnode_get_name(cur), "authtime") == 0)
        {
            s__i->auth_timeout = j_atoi(xmlnode_get_data(cur), 0);
        }
        else if(j_strcmp(xmlnode_get_name(cur), "rate") == 0)
        {
            char *t, *p;
            t = xmlnode_get_attrib(cur, "time");
            p = xmlnode_get_attrib(cur, "points");
            if(t != NULL && p != NULL)
            {
                rate_time   = atoi(t);
                rate_points = atoi(p);
            }
        }
        else if(j_strcmp(xmlnode_get_name(cur), "karma") == 0)
        {
            k.max     = j_atoi(xmlnode_get_tag_data(cur, "max"), KARMA_MAX);
            k.inc     = j_atoi(xmlnode_get_tag_data(cur, "inc"), KARMA_INC);
            k.dec     = j_atoi(xmlnode_get_tag_data(cur, "dec"), KARMA_DEC);
            k.restore = j_atoi(xmlnode_get_tag_data(cur, "restore"), KARMA_RESTORE);
            k.penalty = j_atoi(xmlnode_get_tag_data(cur, "penalty"), KARMA_PENALTY);
        }
    }

    /* start listening */
    if((cur = xmlnode_get_tag(s__i->cfg, "ip")) != NULL)
    {
        for(; cur != NULL; xmlnode_hide(cur), cur = xmlnode_get_tag(s__i->cfg, "ip"))
        {
            mio m;
            m = mio_listen(j_atoi(xmlnode_get_attrib(cur, "port"), 5222), xmlnode_get_data(cur), pthsock_client_listen, (void*)s__i, MIO_LISTEN_XML);
            if(m == NULL)
                return;
            /* XXX see below -- same applies for rate */
            if(rate_time != 0 && rate_points != 0)
                mio_rate(m, rate_time, rate_points);
            /* XXX note, this isn't quite what i had in mind for karma
             * since it's not taking the default from <io/> over the 
             * internal defaults... it should take the c2s config first
             * any values not there should come from <io/> and any other
             * non-matched values should use the internal defaults */
            mio_karma2(m, &k);
        }
    }
    else /* no special config, use defaults */
    {
        mio m;
        m = mio_listen(5222, NULL, pthsock_client_listen, (void*)s__i, MIO_LISTEN_XML);
        if(m == NULL)
            return;
        if(rate_time != 0 && rate_points != 0)
            mio_rate(m, rate_time, rate_points);
        mio_karma2(m, &k);
    }

    /* register data callbacks */
    register_phandler(i, o_DELIVER, pthsock_client_packets, (void*)s__i);
    pool_cleanup(i->p, pthsock_client_shutdown, (void*)s__i);
    if(s__i->auth_timeout)
        register_beat(5, pthsock_client_timeout, (void*)s__i);
}

