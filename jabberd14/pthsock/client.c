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
#define DEFAULT_AUTH_TIMEOUT 60

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

smi s__i = NULL;

typedef enum { state_UNKNOWN, state_AUTHD } user_state;
typedef struct cdata_st
{
    jid host;
    user_state state;
    char *id, *sid, *res, *auth_id;
    time_t connect_time;
    void *arg;
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
            x = pthsock_make_route(NULL, jid_full(cdcur->host), cdcur->id, "session");
            log_notice(p->host, "C2S requesting Session Start for %s", xmlnode_get_attrib(p->x, "from"));
            deliver(dpacket_new(x), s__i->i);
        } else log_record(jid_full(jid_user(cdcur->host)), "login", "fail", "%s %s %s", mio_ip(cdcur->m), xmlnode_get_attrib(xmlnode_get_tag(p->x, "iq/error"),"code"), cdcur->host->resource);
    } else if(cdcur->state == state_UNKNOWN && j_strcmp(xmlnode_get_attrib(p->x, "type"), "session") == 0)
    { /* got a session reply from the server */
        mio_wbq q;

        cdcur->state = state_AUTHD;
        log_record(jid_full(jid_user(cdcur->host)), "login", "ok", "%s %s", mio_ip(cdcur->m), cdcur->host->resource);
        /* change the host id */
        cdcur->host = jid_new(m->p, xmlnode_get_attrib(p->x, "from"));
        xmlnode_free(p->x);
        /* if we have packets in the queue, write them */
        while((q = (mio_wbq)pth_msgport_get(cdcur->pre_auth_mp)) != NULL)
        {
            q->x = pthsock_make_route(q->x, jid_full(cdcur->host), cdcur->id, NULL);
            deliver(dpacket_new(q->x), s__i->i);
        }
        pth_msgport_destroy(cdcur->pre_auth_mp);
        cdcur->pre_auth_mp = NULL;
        return r_DONE;
    }

    log_debug(ZONE, "Writing packet to MIO: %s", xmlnode2str(p->x));

    if(xmlnode_get_firstchild(p->x) == NULL)
        xmlnode_free(p->x);
    else
        mio_write(m, xmlnode_get_firstchild(p->x), NULL, 0);
    return r_DONE;
}

cdata pthsock_client_cdata(mio m)
{
    cdata cd;
    char *buf;

    cd               = pmalloco(m->p, sizeof(_cdata));
    cd->pre_auth_mp  = pth_msgport_create("pre_auth_mp");
    cd->state        = state_UNKNOWN;
    cd->connect_time = time(NULL);
    cd->m            = m;

    buf = pmalloco(m->p, 100);

    /* HACK to fix race conditon */
    snprintf(buf, 99, "%X", m);
    cd->res = pstrdup(m->p, buf);

    /* we use <fd>@host to identify connetions */
    snprintf(buf, 99, "%d@%s/%s", m->fd, s__i->host, cd->res);
    cd->id = pstrdup(m->p, buf);

    return cd;
}

void pthsock_client_read(mio m, int flag, void *arg, xmlnode x)
{
    cdata cd = (cdata)arg;
    xmlnode h;
    char *alias, *to;

    log_debug(ZONE, "pthsock_client_read called with: m:%X flag:%d arg:%X", m, flag, arg);
    switch(flag)
    {
    case MIO_NEW:
        cd = pthsock_client_cdata(m);
        mio_reset(m, pthsock_client_read, (void*)cd);
        break;
    case MIO_CLOSED:
        if(cd == NULL) break;
        log_debug(ZONE, "io_select Socket %d close notification", m->fd);
        if(cd->state == state_AUTHD)
        {
            h = pthsock_make_route(NULL, jid_full(cd->host), cd->id, "error");
            deliver(dpacket_new(h), s__i->i);
        }
        else
        {
            mio_wbq q;
            if(cd != NULL && cd->pre_auth_mp != NULL)
            { /* if there is a pre_auth queue still */
                while((q = (mio_wbq)pth_msgport_get(cd->pre_auth_mp)) != NULL)
                    xmlnode_free(q->x);
                pth_msgport_destroy(cd->pre_auth_mp);
            } 
        }
        break;
    case MIO_ERROR:
        if(m->queue == NULL) break;

        while((h = mio_cleanup(m)) != NULL)
            deliver_fail(dpacket_new(h), "Socket Error to Client");
        break;
    case MIO_XML_ROOT:
        ghash_put_pool(cd->m->p, s__i->users, cd->id,cd);
        log_debug(ZONE, "root received for %d", m->fd);
        to = xmlnode_get_attrib(x, "to");

        alias = ghash_get(s__i->aliases, xmlnode_get_attrib(x, "to"));
        alias = alias ? alias : ghash_get(s__i->aliases, "default");

        cd->host = alias ? jid_new(m->p, alias) : jid_new(m->p, to);

        h = xstream_header("jabber:client", NULL, jid_full(cd->host));
        cd->sid = pstrdup(m->p, xmlnode_get_attrib(h, "id"));
        mio_write(m, NULL, xstream_header_char(h), -1);

        if(j_strcmp(xmlnode_get_attrib(x, "xmlns"), "jabber:client") != 0)
        { /* if they sent something other than jabber:client */
            mio_write(m, NULL, "<stream:error>Invalid Namespace</stream:error></stream:stream>", -1);
            mio_close(m);
        }
        else if(cd->host == NULL)
        { /* they didn't send a to="" and no valid alias */
            mio_write(m, NULL, "<stream:error>Did not specify a valid to argument</stream:error></stream:stream>", -1);
            mio_close(m);
        }
        else if(j_strcmp(xmlnode_get_attrib(x, "xmlns:stream"), "http://etherx.jabber.org/streams") != 0)
        {
            mio_write(m, NULL, "<stream:error>Invalid Stream Namespace</stream:error></stream:stream>", -1);
            mio_close(m);
        }
        xmlnode_free(h);
        xmlnode_free(x);
        break;
    case MIO_XML_NODE:
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
                    jid_set(cd->host, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:auth"), "username")), JID_USER);
                    jid_set(cd->host, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:auth"), "resource")), JID_RESOURCE);

                    x = pthsock_make_route(x, jid_full(cd->host), cd->id, "auth");
                    deliver(dpacket_new(x), s__i->i);
                }
                else if(j_strcmp(xmlnode_get_attrib(x, "type"), "get") == 0)
                { /* we are just doing an auth get */
                    /* just deliver the packet */
                    jid_set(cd->host, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:auth"), "username")), JID_USER);
                    x = pthsock_make_route(x, jid_full(cd->host), cd->id, "auth");
                    deliver(dpacket_new(x), s__i->i);
                }
            }
            else if (NSCHECK(q, NS_REGISTER))
            {
                jid_set(cd->host, xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x, "query?xmlns=jabber:iq:register"), "username")), JID_USER);
                x = pthsock_make_route(x, jid_full(cd->host), cd->id, "auth");
                deliver(dpacket_new(x), s__i->i);
            }
        }
        else
        {   /* normal delivery of packets after authed */
            x = pthsock_make_route(x, jid_full(cd->host), cd->id, NULL);
            deliver(dpacket_new(x), s__i->i);
        }
        break;
    }
}

/* cleanup function */
void pthsock_client_shutdown(void *arg)
{
    xmlnode_free(s__i->cfg);
}

/* everything starts here */
void pthsock_client(instance i, xmlnode x)
{
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
    s__i->users        = ghash_create_pool(i->p, 7, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);

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
            int timeout;

            timeout = j_atoi(xmlnode_get_data(cur), -1);

            /* XXX take a look at this again */
            if(timeout != 0)
                s__i->auth_timeout = timeout;
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
            m = mio_listen(j_atoi(xmlnode_get_attrib(cur, "port"), 5222), xmlnode_get_data(cur), pthsock_client_read, NULL, MIO_LISTEN_XML);
            if(m == NULL)
                return;
            mio_rate(m, rate_time, rate_points);
            mio_karma2(m, &k);
        }
    }
    else /* no special config, use defaults */
    {
        mio m;
        m = mio_listen(5222, NULL, pthsock_client_read, NULL, MIO_LISTEN_XML);
        if(m == NULL)
            return;
        mio_rate(m, rate_time, rate_points);
        mio_karma2(m, &k);
    }

    /* register data callbacks */
    register_phandler(i, o_DELIVER, pthsock_client_packets, NULL);
    pool_cleanup(i->p, pthsock_client_shutdown, (void*)s__i);
}

