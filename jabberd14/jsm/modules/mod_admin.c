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

/* who */
mreturn  mod_admin_who(jpacket p)
{
    xmlnode who = xmlnode_get_tag(p->iq,"who");

    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling who GET");

        /* walk the users */
        ghash_walk(js__users,_mod_admin_who,(void *)who);
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling who SET");

        /* kick them? */
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(p);
    return M_HANDLED;
}

/* monitor */
mreturn mod_admin_monitor(jpacket p)
{
    xmlnode config = xmlnode_get_tag(p->iq,"config");
    xmlnode cur;

    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling config GET");

        /* insert the loaded config file */
        xmlnode_insert_node(config,xmlnode_get_firstchild(js__config));
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling config SET");

        /* set the new config file */
        js__config = xmlnode_dup(config);

        /* !!! like do init stuff for the new config */

        /* empty the iq result */
        for(cur = xmlnode_get_firstchild(p->x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            xmlnode_hide(cur);
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(p);
    return M_HANDLED;
}

/* user */
mreturn mod_admin_user(jpacket p)
{
    xmlnode config = xmlnode_get_tag(p->iq,"config");
    xmlnode cur;

    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling config GET");

        /* insert the loaded config file */
        xmlnode_insert_node(config,xmlnode_get_firstchild(js__config));
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling config SET");

        /* set the new config file */
        js__config = xmlnode_dup(config);

        /* !!! like do init stuff for the new config */

        /* empty the iq result */
        for(cur = xmlnode_get_firstchild(p->x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            xmlnode_hide(cur);
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(p);
    return M_HANDLED;
}

/* config */
mreturn mod_admin_config(jpacket p)
{
    xmlnode config = xmlnode_get_tag(p->iq,"config");
    xmlnode cur;

    if(jpacket_subtype(p) == JPACKET__GET)
    {
        log_debug("mod_admin","handling config GET");

        /* insert the loaded config file */
        xmlnode_insert_node(config,xmlnode_get_firstchild(js__config));
    }

    if(jpacket_subtype(p) == JPACKET__SET)
    {
        log_debug("mod_admin","handling config SET");

        /* set the new config file */
        js__config = xmlnode_dup(config);

        /* !!! like do init stuff for the new config */

        /* empty the iq result */
        for(cur = xmlnode_get_firstchild(p->x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
            xmlnode_hide(cur);
    }

    jutil_tofrom(p->x);
    xmlnode_put_attrib(p->x,"type","result");
    jpacket_reset(p);
    js_deliver(p);
    return M_HANDLED;
}

/* dispatch */
mreturn mod_admin_dispatch(mapi m, void *arg)
{
    int f_read = 0, f_write = 0;
    xmlnode cur;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_ADMIN)) return M_PASS;

    /* ensure that the user is local */
    if(js_config("admin") == NULL || m->packet->from == NULL || m->packet->from->user == NULL || j_strcmp(m->packet->from->server,js__hostname) != 0)
    {
        js_bounce(m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_admin","checking admin request from %s",jid_full(m->packet->from));

    for(cur = xmlnode_get_firstchild(js_config("admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"read") == 0 && xmlnode_get_data(cur) != NULL && strcasecmp(m->packet->from->user,xmlnode_get_data(cur)) == 0)
            f_read = 1;
        if(j_strcmp(xmlnode_get_name(cur),"write") == 0 && xmlnode_get_data(cur) != NULL && strcasecmp(m->packet->from->user,xmlnode_get_data(cur)) == 0)
            f_read = f_write = 1;
    }

    if(f_read)
    {
        if(xmlnode_get_tag(m->packet->iq,"who") != NULL) return mod_admin_who(m->packet);
        if(0 && xmlnode_get_tag(m->packet->iq,"monitor") != NULL) return mod_admin_monitor(m->packet);
    }

    if(f_write)
    {
        if(0 && xmlnode_get_tag(m->packet->iq,"user") != NULL) return mod_admin_user(m->packet);
        if(xmlnode_get_tag(m->packet->iq,"config") != NULL) return mod_admin_config(m->packet);
    }

    js_bounce(m->packet->x,TERROR_NOTALLOWED);
    return M_HANDLED;
}


/* message */
mreturn mod_admin_message(mapi m, void *arg)
{
    jpacket p;
    xmlnode cur;

    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;
    if(m->packet->to->resource != NULL) return M_PASS;

    log_debug("mod_admin","delivering admin message from %s",jid_full(m->packet->from));
    xmlnode_put_attrib(m->packet->x,"type","headline");

    for(cur = xmlnode_get_firstchild(js_config("admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(xmlnode_get_name(cur) == NULL || xmlnode_get_data(cur) == NULL) continue;

        p = jpacket_new(xmlnode_dup(m->packet->x));
        jutil_delay(p->x,"admin");
        jid_set(p->to,xmlnode_get_data(cur),JID_USER);
        xmlnode_put_attrib(p->x,"to",jid_full(p->to));
        jpacket_reset(p);
        js_deliver(p);
    }

    xmlnode_free(m->packet->x);
    return M_HANDLED;
}

void mod_admin(jsmi i)
{
    js_mapi_register(P_SERVER,mod_admin_dispatch,NULL);
    js_mapi_register(P_SERVER,mod_admin_message,NULL);
}


