#include "jserver.h"

int _mod_announce_avail(void *arg, const void *key, void *data)
{
    xmlnode msg = (xmlnode)arg;
    udata u = (udata)data;
    session s = js_session_primary(u);

    if(s == NULL) return 1;

    msg = xmlnode_dup(msg);
    xmlnode_put_attrib(msg,"to",jid_full(s->id));
    js_session_to(s,jpacket_new(msg));

    return 1;
}

mreturn mod_announce_avail(jpacket p)
{
    xmlnode_put_attrib(p->x,"from",js__hostname);
    ghash_walk(js__users,_mod_announce_avail,(void *)(p->x));
    return M_HANDLED;
}

mreturn mod_announce_all(jpacket p)
{
    /* store the message in XDB, and feed to all online.
     * mark off users that got it, feed to new ones that come online
     * have a timeout/lifetime on the announcement
     */
    return M_PASS;
}

mreturn mod_announce_dispatch(mapi m, void *arg)
{
    int admin = 0;
    xmlnode cur;

    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;
    if(j_strncmp(m->packet->to->resource,"announce/",9) != 0) return M_PASS;

    /* ensure that the user is local */
    if(js_config("admin") == NULL || m->packet->from == NULL || m->packet->from->user == NULL || j_strcmp(m->packet->from->server,js__hostname) != 0)
    {
        js_bounce(m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_announce","handling announce message from %s",jid_full(m->packet->from));

    for(cur = xmlnode_get_firstchild(js_config("admin")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
    {
        if(j_strcmp(xmlnode_get_name(cur),"write") == 0 && xmlnode_get_data(cur) != NULL && strcasecmp(m->packet->from->user,xmlnode_get_data(cur)) == 0)
            admin = 1;
    }

    if(admin)
    {
        if(j_strncmp(m->packet->to->resource,"announce/online",15) == 0) return mod_announce_avail(m->packet);
        if(j_strncmp(m->packet->to->resource,"announce/all",12) == 0) return mod_announce_all(m->packet);
    }

    js_bounce(m->packet->x,TERROR_NOTALLOWED);
    return M_HANDLED;
}

void mod_announce(void)
{
    js_mapi_register(P_SERVER,mod_announce_dispatch,NULL);
}


