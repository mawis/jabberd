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
