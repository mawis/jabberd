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
#include "jsm.h"

int _mod_admin_who(void *arg, const void *key, void *data)
{
    xmlnode who = (xmlnode)arg;
    udata u = (udata)data;
    session s;
    xmlnode x;
    time_t t;
    char buff[10];

    t = time(NULL);

    /* loop through all the sessions */
    for(s = u->sessions; s != NULL; s = s->next)
    {
        /* make a presence entry for each one with a custom extension */
        x = xmlnode_insert_tag_node(who,s->presence);
        x = xmlnode_insert_tag(x,"x");
        xmlnode_put_attrib(x,"xmlns","jabber:mod_admin:who");

        /* insert extended data */
        sprintf(buff,"%d", (int)(t - s->started));
        xmlnode_put_attrib(x,"timer",buff);
        sprintf(buff,"%d", s->c_in);
        xmlnode_put_attrib(x,"from",buff);
        sprintf(buff,"%d", s->c_out);
        xmlnode_put_attrib(x,"to",buff);
    }

    return 1;
}

/* callback for walking the host hash tree */
int _mod_admin_who_host(void *arg, const void *key, void *data)
{
    HASHTABLE ht = (HASHTABLE)data;

    ghash_walk(ht,_mod_admin_who,arg);

    return 1;
}

/* who */
mreturn  mod_admin_who(jsmi si, jpacket p)
{
    xmlnode who = xmlnode_get_tag(p->iq,"who");

    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling who GET");

        /* walk the users */
        ghash_walk(si->hosts,_mod_admin_who_host,(void *)who);
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling who SET");

        /* kick them? */
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(si,p);
    return M_HANDLED;
}

/* config */
mreturn mod_admin_config(jsmi si, jpacket p)
{
    xmlnode config = xmlnode_get_tag(p->iq,"config");
    xmlnode cur;

    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling config GET");

        /* insert the loaded config file */
        xmlnode_insert_node(config,xmlnode_get_firstchild(si->config));
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling config SET");

        /* XXX FIX ME, like do init stuff for the new config, etc */
        si->config = xmlnode_dup(config);


        /* empty the iq result */
        for(cur = xmlnode_get_firstchild(p->x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            xmlnode_hide(cur);
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(si,p);
    return M_HANDLED;
}

/* user */
mreturn mod_admin_user(jsmi si, jpacket p)
{
    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling user GET");
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling user SET");
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(si,p);
    return M_HANDLED;
}

/* monitor */
mreturn mod_admin_monitor(jsmi si, jpacket p)
{
    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling monitor GET");
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling monitor SET");
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(si,p);
    return M_HANDLED;
}

/* dispatch */
mreturn mod_admin_dispatch(mapi m, void *arg)
{
    int f_read = 0, f_write = 0;
    xmlnode cur;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_ADMIN)) return M_PASS;

    log_debug("mod_admin","checking admin request from %s",jid_full(m->packet->from));

    for(cur = xmlnode_get_firstchild(js_config(m->si,"admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"read") == 0 && jid_cmpx(jid_new(xmlnode_pool(m->packet->x),xmlnode_get_data(cur)),m->packet->from,JID_USER|JID_SERVER) == 0)
            f_read = 1;
        if(j_strcmp(xmlnode_get_name(cur),"write") == 0 && jid_cmpx(jid_new(xmlnode_pool(m->packet->x),xmlnode_get_data(cur)),m->packet->from,JID_USER|JID_SERVER) == 0)
            f_read = f_write = 1;
    }

    if(f_read)
    {
        if(xmlnode_get_tag(m->packet->iq,"who") != NULL) return mod_admin_who(m->si, m->packet);
        if(0 && xmlnode_get_tag(m->packet->iq,"monitor") != NULL) return mod_admin_monitor(m->si, m->packet);
    }

    if(f_write)
    {
        if(0 && xmlnode_get_tag(m->packet->iq,"user") != NULL) return mod_admin_user(m->si, m->packet);
        if(xmlnode_get_tag(m->packet->iq,"config") != NULL) return mod_admin_config(m->si, m->packet);
    }

    js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
    return M_HANDLED;
}


/* message */
mreturn mod_admin_message(mapi m, void *arg)
{
    jpacket p;
    xmlnode cur;
    char *subject;

    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;
    if(m->packet->to->resource != NULL) return M_PASS;

    log_debug("mod_admin","delivering admin message from %s",jid_full(m->packet->from));
    /* XXX in the future, this should just be x:envelope, when
     * it has more support, so that the subject is preserved */
    subject=spools(m->packet->p,"Admin Message sent to: ",m->packet->to->server,m->packet->p);
    xmlnode_hide(xmlnode_get_tag(m->packet->x,"subject"));
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->x,"subject"),subject,-1);


    for(cur = xmlnode_get_firstchild(js_config(m->si,"admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(xmlnode_get_name(cur) == NULL || xmlnode_get_data(cur) == NULL) continue;

        p = jpacket_new(xmlnode_dup(m->packet->x));
        jutil_delay(p->x,"admin");
        p->to = jid_new(p->p,xmlnode_get_data(cur));
        xmlnode_put_attrib(p->x,"to",jid_full(p->to));
        js_deliver(m->si,p);
    }

    xmlnode_free(m->packet->x);
    return M_HANDLED;
}

void mod_admin(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_admin_dispatch,NULL);
    js_mapi_register(si,e_SERVER,mod_admin_message,NULL);
}


