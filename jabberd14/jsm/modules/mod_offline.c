#include "jsm.h"

/* THIS MODULE will soon be depreciated by mod_filter */

/* mod_offline must go before mod_presence */

/* get the user's offline options */
xmlnode mod_offline_get(udata u)
{
    xmlnode ret;

    log_debug("mod_offline","getting %s's offline options",u->user);

    /* get the existing options */
    ret = js_xdb_get(u, NS_OFFLINE);
    if(ret == NULL)
    {
        log_debug("mod_offline","creating options container");
        ret = xmlnode_new_tag("offline");
        xmlnode_put_attrib(ret,"xmlns",NS_OFFLINE);
        js_xdb_set(u,NS_OFFLINE,ret);
    }

    return ret;
}

/* handle an offline message */
mreturn mod_offline_message(mapi m)
{
    xmlnode opts, cur;
    int max = 0;
    session top;

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__NONE:
    case JPACKET__ERROR:
    case JPACKET__CHAT:
        break;
    default:
        return M_PASS;
    }

    log_debug("mod_offline","handling message for %s",m->user->user);

    /* get user offline options */
    opts = mod_offline_get(m->user);

    if((top = js_session_primary(m->user)) != NULL){
        /* there's an existing session, just give it to them */
        js_session_to(top,m->packet);
    }else{

        /* ugly, max offline messages stored is 100, finish mod_filter right away */
        for(cur = xmlnode_get_firstchild(opts); cur != NULL; cur = xmlnode_get_nextsibling(cur)) max++;
        if(max > 100) return M_PASS;

        /* alone am I */
        jutil_delay(m->packet->x,"Offline Storage");
        xmlnode_insert_tag_node(opts,m->packet->x);
        js_xdb_set(m->user,NS_OFFLINE,opts);
        xmlnode_free(m->packet->x);
    }

    return M_HANDLED;
}

/* just breaks out to our message/presence offline handlers */
mreturn mod_offline_handler(mapi m, void *arg)
{
    if(m->packet->type == JPACKET_MESSAGE) return mod_offline_message(m);

    return M_IGNORE;
}

/* watches for when the user is available and sends out offline messages */
void mod_offline_out_available(mapi m)
{
    xmlnode opts, cur;

    log_debug("mod_offline","avability established, check for messages");

    opts = mod_offline_get(m->user);

    /* check for msgs */
    for(cur = xmlnode_get_firstchild(opts); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"message") != 0) continue;

        js_session_to(m->s,jpacket_new(xmlnode_dup(cur)));
        xmlnode_hide(cur);
    }

    /* messages are gone, save the new sun-dried opts container */
    js_xdb_set(m->user, NS_OFFLINE, opts);
}

mreturn mod_offline_out(mapi m, void *arg)
{
    if(m->packet->type != JPACKET_PRESENCE) return M_IGNORE;

    if(jpacket_subtype(m->packet) == JPACKET__AVAILABLE && m->s->priority < 0 && m->packet->to == NULL)
        mod_offline_out_available(m);

    return M_PASS;
}

/* sets up the per-session listeners */
mreturn mod_offline_session(mapi m, void *arg)
{
    log_debug(ZONE,"session init");

    js_mapi_session(es_OUT, m->s, mod_offline_out, NULL);

    return M_PASS;
}

void mod_offline(jsmi si)
{
    log_debug("mod_offline","init");
    js_mapi_register(si,e_OFFLINE, mod_offline_handler, NULL);
    js_mapi_register(si,e_SESSION, mod_offline_session, NULL);
}

