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

#include "io.h"
#define DEFAULT_AUTH_TIMEOUT 60

/* socket manager instance */
typedef struct smi_st
{
    instance i;
    int auth_timeout;
    xmlnode cfg;
    HASHTABLE aliases;
    pth_msgport_t wmp;
    char *host;
} *smi, _smi;

typedef enum { state_UNKNOWN, state_AUTHD } user_state;
typedef struct cdata_st
{
    smi i;
    jid host;
    user_state state;
    char *id, *sid, *res, *auth_id;
    time_t connect_time;
    void *arg;
    pth_msgport_t pre_auth_mp;
} _cdata,*cdata;

xmlnode pthsock_make_route(xmlnode x,char *to,char *from,char *type)
{
    xmlnode new;
    if(x!=NULL)
        new=xmlnode_wrap(x,"route");
    else
        new=xmlnode_new_tag("route");
    if(type!=NULL) xmlnode_put_attrib(new,"type",type);
    if(to!=NULL) xmlnode_put_attrib(new,"to",to);
    if(from!=NULL) xmlnode_put_attrib(new,"from",from);
    return new;
}

result pthsock_client_packets(instance id, dpacket p, void *arg)
{
    smi si=(smi)arg;
    cdata cdcur;
    sock cur;
    int fd=0;
    xmlnode x;

    if(p->id->user!=NULL)fd = atoi(p->id->user); 
    if(p->type!=p_ROUTE||fd==0)
    { /* we only want <route/> packets */
        log_warn(p->host,"pthsock_client bouncing invalid %s packet from %s",xmlnode_get_name(p->x),xmlnode_get_attrib(p->x,"from"));
        deliver_fail(p,"invalid client packet");
        return r_DONE;
    }

    for (cur=io_select_get_list();cur!=NULL;cur=cur->next)
    { /* find sock for this connection */
        cdcur=((cdata)cur->arg);
        if (fd == cur->fd && cur->state == state_ACTIVE) /* we can't match a closing socket! */
            if (j_strcmp(p->id->resource,cdcur->res) == 0)
                break;
    }

    if(cur==NULL)
    { 
        if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error")==0)
        { /* we got a 510, but no session to end */
            xmlnode_free(p->x);
            return r_DONE;
        }

        log_debug(ZONE,"pthsock_client connection not found");

        jutil_tofrom(p->x);
        xmlnode_put_attrib(p->x,"type","error");

        deliver(dpacket_new(p->x),si->i);
        return r_DONE;
    }

    log_debug(ZONE,"Found the sock for this user");
    if (j_strcmp(xmlnode_get_attrib(p->x,"type"),"error")==0)
    { /* <route type="error" means we were disconnected */
        x = xmlnode_new_tag("stream:error");
        xmlnode_insert_cdata(x,"Disconnected",-1);
        io_write(cur,x);
        io_close(cur);
        xmlnode_free(p->x);
        return r_DONE;
    }
    else if(cdcur->state==state_UNKNOWN&&j_strcmp(xmlnode_get_attrib(p->x,"type"),"auth")==0)
    { /* look for our auth packet back */
        char *type=xmlnode_get_attrib(xmlnode_get_firstchild(p->x),"type");
        char *id=xmlnode_get_attrib(xmlnode_get_tag(p->x,"iq"),"id");
        if((j_strcmp(type,"result")==0)&&j_strcmp(cdcur->auth_id,id)==0)
        { /* update the cdata status if it's a successfull auth */
            xmlnode x;
            log_debug(ZONE,"auth for user successful");
            /* notify SM to start a session */
            x=pthsock_make_route(NULL,jid_full(cdcur->host),cdcur->id,"session");
            deliver(dpacket_new(x),si->i);
        } else log_debug(ZONE,"Auth not successfull");
    } else if(cdcur->state==state_UNKNOWN&&j_strcmp(xmlnode_get_attrib(p->x,"type"),"session")==0)
    { /* got a session reply from the server */
        wbq q;
        cdcur->state = state_AUTHD;
        /* change the host id */
        cdcur->host = jid_new(cur->p,xmlnode_get_attrib(p->x,"from"));
        log_debug(ZONE,"Session Started");
        xmlnode_free(p->x);
        /* if we have packets in the queue, write them */
        while((q=(wbq)pth_msgport_get(cdcur->pre_auth_mp))!=NULL)
        {
            q->x=pthsock_make_route(q->x,jid_full(cdcur->host),cdcur->id,NULL);
            deliver(dpacket_new(q->x),si->i);
        }
        pth_msgport_destroy(cdcur->pre_auth_mp);
        cdcur->pre_auth_mp=NULL;
        return r_DONE;
    }

    io_write(cur,xmlnode_get_firstchild(p->x));
    return r_DONE;
}

/* callback for xstream */
void pthsock_client_stream(int type, xmlnode x, void *arg)
{
    sock c = (sock)arg;
    cdata cd=(cdata)c->arg;
    char *alias,*to;
    xmlnode h;

    switch(type)
    {
    case XSTREAM_ROOT:
        log_debug(ZONE,"root received for %d",c->fd);
        to=xmlnode_get_attrib(x,"to");
        alias=ghash_get(cd->i->aliases,xmlnode_get_attrib(x,"to"));
        if(alias==NULL) alias=ghash_get(cd->i->aliases,"default");
        if(alias!=NULL)
            cd->host=jid_new(c->p,alias);
        else
            cd->host=jid_new(c->p,to);
        h = xstream_header("jabber:client",NULL,jid_full(cd->host));
        cd->sid = pstrdup(c->p,xmlnode_get_attrib(h,"id"));
        io_write_str(c,xstream_header_char(h));
        if(j_strcmp(xmlnode_get_attrib(x,"xmlns"),"jabber:client")!=0)
        { /* if they sent something other than jabber:client */
            io_write_str(c,"<stream:error>Invalid Namespace</stream:error>");
            io_close(c);
        }
        else if(cd->host==NULL)
        { /* they didn't send a to="" and no valid alias */
            io_write_str(c,"<stream:error>Did not specify a valid to argument</stream:error>");
            io_close(c);
        }
        else if(j_strcmp(xmlnode_get_attrib(x,"xmlns:stream"),"http://etherx.jabber.org/streams")!=0)
        {
            io_write_str(c,"<stream:error>Invalid Stream Namespace</stream:error>");
            io_close(c);
        }
        xmlnode_free(h);
        xmlnode_free(x);
        break;
    case XSTREAM_NODE:
        if (cd->state == state_UNKNOWN)
        { /* only allow auth and registration queries at this point */
            xmlnode q = xmlnode_get_tag(x,"query");
            if (!NSCHECK(q,NS_AUTH)&&!NSCHECK(q,NS_REGISTER))
            {
                wbq q;
                /* queue packet until authed */
                q=pmalloco(xmlnode_pool(x),sizeof(_wbq));
                q->x=x;
                pth_msgport_put(cd->pre_auth_mp,(void*)q);
                return;
            }
            else if (NSCHECK(q,NS_AUTH))
            {
                if(j_strcmp(xmlnode_get_attrib(x,"type"),"set")==0)
                { /* if we are authing against the server */
                    xmlnode_put_attrib(xmlnode_get_tag(q,"digest"),"sid",cd->sid);
                    cd->auth_id = pstrdup(c->p,xmlnode_get_attrib(x,"id"));
                    if(cd->auth_id==NULL) 
                    {
                        cd->auth_id = pstrdup(c->p,"pthsock_client_auth_ID");
                        xmlnode_put_attrib(x,"id","pthsock_client_auth_ID");
                    }
                    jid_set(cd->host,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x,"query?xmlns=jabber:iq:auth"),"username")),JID_USER);
                    jid_set(cd->host,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x,"query?xmlns=jabber:iq:auth"),"resource")),JID_RESOURCE);
                    x=pthsock_make_route(x,jid_full(cd->host),cd->id,"auth");
                    deliver(dpacket_new(x),((smi)cd->i)->i);
                }
                else if(j_strcmp(xmlnode_get_attrib(x,"type"),"get")==0)
                { /* we are just doing an auth get */
                    /* just deliver the packet */
                    jid_set(cd->host,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x,"query?xmlns=jabber:iq:auth"),"username")),JID_USER);
                    x=pthsock_make_route(x,jid_full(cd->host),cd->id,"auth");
                    deliver(dpacket_new(x),((smi)cd->i)->i);
                }
            }
            else if (NSCHECK(q,NS_REGISTER))
            {
                jid_set(cd->host,xmlnode_get_data(xmlnode_get_tag(xmlnode_get_tag(x,"query?xmlns=jabber:iq:register"),"username")),JID_USER);
                x=pthsock_make_route(x,jid_full(cd->host),cd->id,"auth");
                deliver(dpacket_new(x),((smi)cd->i)->i);
            }
        }
        else
        {   /* normal delivery of packets after authed */
            x=pthsock_make_route(x,jid_full(cd->host),cd->id,NULL);
            deliver(dpacket_new(x),((smi)cd->i)->i);
        }
        break;
    case XSTREAM_ERR:
        log_debug(ZONE,"bad xml: %s",xmlnode2str(x));
        h=xmlnode_new_tag("stream:error");
        xmlnode_insert_cdata(h,"You sent malformed XML",-1);
        io_write(c,h);
    case XSTREAM_CLOSE:
        log_debug(ZONE,"closing XSTREAM");
        io_close(c);
        xmlnode_free(x);
    }
}


cdata pthsock_client_cdata(smi si,sock c)
{
    cdata cd;
    char *buf;

    cd = pmalloco(c->p, sizeof(_cdata));
    cd->pre_auth_mp=pth_msgport_create("pre_auth_mp");
    cd->i = si;
    c->xs = xstream_new(c->p,(void*)pthsock_client_stream,(void*)c);
    cd->state = state_UNKNOWN;
    cd->arg=(void*)c;

    buf=pmalloco(c->p,100);

    /* HACK to fix race conditon */
    snprintf(buf,99,"%X",c);
    cd->res = pstrdup(c->p,buf);

    /* we use <fd>@host to identify connetions */
    snprintf(buf,99,"%d@%s/%s",c->fd,si->host,cd->res);
    cd->id = pstrdup(c->p,buf);

    return cd;
}

void pthsock_client_read(sock c,char *buffer,int bufsz,int flags,void *arg)
{
    smi si=(smi)arg;
    cdata cd;
    wbq q;
    xmlnode x;
    int ret;

    switch(flags)
    {
    case IO_INIT:
        break;
    case IO_NEW:
        log_debug(ZONE,"io_select NEW socket connected at %d",c->fd);
        cd=pthsock_client_cdata(si,c);
        cd->connect_time=time(NULL);
        c->arg=(void*)cd;
        break;
    case IO_NORMAL:
        ret=xstream_eat(c->xs,buffer,bufsz);
        break;
    case IO_CLOSED:
        cd=(cdata)c->arg;
        log_debug(ZONE,"io_select Socket %d close notification",c->fd);
        if(cd->state==state_AUTHD)
        {
            x=pthsock_make_route(NULL,jid_full(cd->host),cd->id,"error");
            deliver(dpacket_new(x),((smi)cd->i)->i);
        }
        else
        {
            wbq q;
            if(cd->pre_auth_mp!=NULL)
            { /* if there is a pre_auth queue still */
                while((q=(wbq)pth_msgport_get(cd->pre_auth_mp))!=NULL)
                    xmlnode_free(q->x);
                pth_msgport_destroy(cd->pre_auth_mp);
            } 
        }
        break;
    case IO_ERROR:
        if(c->xbuffer==NULL) break;

        if(((int)c->xbuffer)!=-1)
            deliver_fail(dpacket_new(c->xbuffer),"Socket Error to Client");
        else
            pool_free(c->pbuffer); 
        c->xbuffer=NULL;
        c->wbuffer=c->cbuffer=NULL;
        c->pbuffer=NULL;
        while((q=(wbq)pth_msgport_get(c->queue))!=NULL)
        {
            if(q->type==queue_XMLNODE)
                deliver_fail(dpacket_new(q->x),"Socket Error to Client");
            else
                pool_free(q->p);
        }
    }
}

result pthsock_client_heartbeat(void *arg)
{
    smi si=(smi)arg;
    sock c;
    cdata cd;
    for(c=io_select_get_list();c!=NULL;c=c->next)
    {
        if(c->state!=state_ACTIVE) continue;
        cd=(cdata)c->arg;
        if(cd==NULL||cd->state==state_AUTHD) continue;
        if(si->auth_timeout!=-1&&(time(NULL)-cd->connect_time)>si->auth_timeout)
        {
            io_write_str(c,"<stream:error>Auth Timeout</stream:error>");
            io_close(c);
        }
    }
    return r_DONE;
}

/* everything starts here */
void pthsock_client(instance i, xmlnode x)
{
    smi si;
    xdbcache xc;
    xmlnode cur;
    int rate_time=0,rate_points=0;
    char *host, *port=0;
    struct karma k;

    log_debug(ZONE,"pthsock_client loading");

    si = pmalloco(i->p,sizeof(_smi));
    si->auth_timeout=DEFAULT_AUTH_TIMEOUT;
    si->i = i;
    si->aliases=ghash_create(20,(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);


    /* write mp */
    si->wmp = pth_msgport_create("pthsock_client_wmp");

    /* get the config */
    xc = xdb_cache(i);
    si->cfg = xdb_get(xc,NULL,jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:pth-csock");

    si->host = host = i->id;

    k.val=KARMA_INIT;
    k.bytes=0;
    k.max=KARMA_MAX;
    k.inc=KARMA_INC;
    k.dec=KARMA_DEC;
    k.restore=KARMA_RESTORE;
    k.penalty=KARMA_PENALTY;

    for(cur=xmlnode_get_firstchild(si->cfg);cur!=NULL;cur=cur->next)
    {
        if(cur->type!=NTYPE_TAG) continue;
        if(j_strcmp(xmlnode_get_name(cur),"listen")==0&&xmlnode_get_data(cur)!=NULL)
        {
            port = xmlnode_get_data(cur);
        }
        else if(j_strcmp(xmlnode_get_name(cur),"alias")==0)
        {
           char *host,*to;
           if((to=xmlnode_get_attrib(cur,"to"))==NULL) continue;
           host=xmlnode_get_data(cur);
           if(host!=NULL)
           {
               ghash_put(si->aliases,host,to);
           }
           else
           {
               ghash_put(si->aliases,"default",to);
           }
        }
        else if(j_strcmp(xmlnode_get_name(cur),"authtime")==0)
        {
            int timeout=0;
            if(xmlnode_get_data(cur)!=NULL)
                timeout=atoi(xmlnode_get_data(cur));
            else timeout=-1;
            if(timeout!=0)si->auth_timeout=timeout;
        }
        else if(j_strcmp(xmlnode_get_name(cur),"rate")==0)
        {
            char *t,*p;
            t=xmlnode_get_attrib(cur,"time");
            p=xmlnode_get_attrib(cur,"points");
            if(t!=NULL&&p!=NULL)
            {
                rate_time=atoi(t);
                rate_points=atoi(p);
            }
        }
        else if(j_strcmp(xmlnode_get_name(cur),"karma")==0)
        {
            xmlnode kcur=xmlnode_get_firstchild(cur);
            for(;kcur!=NULL;kcur=xmlnode_get_nextsibling(kcur))
            {
                if(kcur->type!=NTYPE_TAG) continue;
                if(xmlnode_get_data(kcur)==NULL) continue;
                if(j_strcmp(xmlnode_get_name(kcur),"max")==0)
                    k.max=atoi(xmlnode_get_data(kcur));
                else if(j_strcmp(xmlnode_get_name(kcur),"inc")==0)
                    k.inc=atoi(xmlnode_get_data(kcur));
                else if(j_strcmp(xmlnode_get_name(kcur),"dec")==0)
                    k.dec=atoi(xmlnode_get_data(kcur));
                else if(j_strcmp(xmlnode_get_name(kcur),"restore")==0)
                    k.restore=atoi(xmlnode_get_data(kcur));
                else if(j_strcmp(xmlnode_get_name(kcur),"penalty")==0)
                    k.penalty=atoi(xmlnode_get_data(kcur));
            }
        }
    }

    if (host == NULL || port == NULL)
    {
        log_error(ZONE,"pthsock_client invaild config");
        return;
    }

    /* register data callbacks */
    io_select_listen_ex(atoi(port),NULL,pthsock_client_read,(void*)si,rate_time,rate_points,&k);
    register_phandler(i,o_DELIVER,pthsock_client_packets,(void*)si);
    register_beat(1,pthsock_client_heartbeat,(void*)si);
}
