#include "jsm.h"

mreturn mod_agents_agents(mapi m)
{
    xmlnode ret, retq, agents;

    /* get data from the config file */
    agents = js_config(m->si,"agents");

    /* if we don't have anything to say, bounce */
    if(agents == NULL)
        return M_PASS;

    log_debug("mod_agents","handling agents query");

    /* build the result IQ */
    ret = jutil_iqresult(m->packet->x);
    retq = xmlnode_insert_tag(ret,"query");
    xmlnode_put_attrib(retq,"xmlns",NS_AGENTS);

    /* copy in the agents */
    xmlnode_insert_node(retq,xmlnode_get_firstchild(agents));

    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

mreturn mod_agents_agent(mapi m)
{
    xmlnode ret, retq, info, agents, reg;

    /* get data from the config file */
    info = js_config(m->si,"info");
    agents = js_config(m->si,"agents");
    reg = js_config(m->si,"register");

    /* if we don't have anything to say, bounce */
    if(info == NULL && agents == NULL && reg == NULL)
        return M_PASS;

    log_debug("mod_agent","handling agent query");

    /* build the result IQ */
    ret = jutil_iqresult(m->packet->x);
    retq = xmlnode_insert_tag(ret,"query");
    xmlnode_put_attrib(retq,"xmlns",NS_AGENT);

    /* copy in the info */
    xmlnode_insert_node(retq,xmlnode_get_firstchild(info));
    xmlnode_insert_cdata(xmlnode_insert_tag(retq,"service"),"jabber",6);

    /* set the flags */
    if(agents != NULL)
        xmlnode_insert_tag(retq,"agents");
    if(reg != NULL)
        xmlnode_insert_tag(retq,"register");

    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

mreturn mod_agents_handler(mapi m, void *arg)
{
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;

    if(jpacket_subtype(m->packet) != JPACKET__GET) return M_PASS;

    if(NSCHECK(m->packet->iq,NS_AGENT)) return mod_agents_agent(m);
    if(NSCHECK(m->packet->iq,NS_AGENTS)) return mod_agents_agents(m);

    return M_PASS;
}

void mod_agents(jsmi si)
{
    log_debug("mod_agents","init");
    js_mapi_register(si,e_SERVER, mod_agents_handler, NULL);
}
