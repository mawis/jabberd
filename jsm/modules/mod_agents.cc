/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include "jsm.h"

/**
 * @file mod_agents.cc
 * @brief handling jabber:iq:agents (XEP-0094) and jabber:iq:agent (undocumented) iq requests - DEPRICATED
 *
 * This module implements the jabber:iq:agents functionallity in the session manager.
 * jabber:iq:agents is used by very old Jabber clients to get the list of transports
 * available on a Jabber server. Usage depricated - use service discovery (XEP-0030) instead.
 *
 * This module also implements the jabber:iq:agent functionallity to get information about
 * the session manager (the server) itself. Usage depricated - use service discovery (XEP-0030) instead.
 */

/**
 * Handle an iq get stanza with a request in the jabber:iq:agents namespace.
 *
 * Generates a result containing information about the connected agents (transports).
 * The information is collected from the <browse/> element in the session manager configuration.
 *
 * @param m the mapi structure (contains the request)
 * @return M_HANDLED if a reply could be generated, M_PASS if no information was available
 */
static mreturn mod_agents_agents(mapi m) {
    xmlnode ret, retq, agents, cur, a, cur2;

    /* get data from the config file */
    agents = js_config(m->si, "browse:browse", xmlnode_get_lang(m->packet->x));

    /* if we don't have anything to say, bounce */
    if(agents == NULL)
        return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling agents query");

    /* build the result IQ */
    ret = jutil_iqresult(m->packet->x);
    retq = xmlnode_insert_tag_ns(ret, "query", NULL, NS_AGENTS);

    /* parse the new browse data into old agents format */
    for (cur = xmlnode_get_firstchild(agents); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        if(xmlnode_get_type(cur) != NTYPE_TAG) continue;

        /* generic <agent> part */
        a = xmlnode_insert_tag_ns(retq, "agent", NULL, NS_AGENTS);
        xmlnode_put_attrib_ns(a, "jid", NULL, NULL, xmlnode_get_attrib_ns(cur, "jid", NULL));
        xmlnode_insert_cdata(xmlnode_insert_tag_ns(a, "name", NULL, NS_AGENTS), xmlnode_get_attrib_ns(cur, "name", NULL), -1);
        xmlnode_insert_cdata(xmlnode_insert_tag_ns(a, "service", NULL, NS_AGENTS), xmlnode_get_attrib_ns(cur, "type", NULL), -1);

        if (j_strcmp(xmlnode_get_localname(cur), "conference") == 0)
            xmlnode_insert_tag_ns(a, "groupchat", NULL, NS_AGENTS);

        /* map the included <ns>'s in browse to the old agent flags */
        for (cur2 = xmlnode_get_firstchild(cur); cur2 != NULL; cur2 = xmlnode_get_nextsibling(cur2)) {
            if (j_strcmp(xmlnode_get_localname(cur2),"ns") != 0 || j_strcmp(xmlnode_get_namespace(cur2), NS_BROWSE) != 0)
		continue;
            if (j_strcmp(xmlnode_get_data(cur2),"jabber:iq:register") == 0)
                xmlnode_insert_tag_ns(a, "register", NULL, NS_AGENTS);
            if (j_strcmp(xmlnode_get_data(cur2),"jabber:iq:search") == 0)
                xmlnode_insert_tag_ns(a, "search", NULL, NS_AGENTS);
            if (j_strcmp(xmlnode_get_data(cur2),"jabber:iq:gateway") == 0)
                xmlnode_insert_cdata(xmlnode_insert_tag_ns(a, "transport", NULL, NS_AGENTS),"Enter ID", -1);
        }
    }

    jpacket_reset(m->packet);
    if(m->s != NULL) {
	/* XXX null session hack! */
        xmlnode_put_attrib_ns(m->packet->x, "from", NULL, NULL, m->packet->from->server);
        js_session_to(m->s,m->packet);
    } else {
        js_deliver(m->si, m->packet, NULL);
    }

    xmlnode_free(agents);

    return M_HANDLED;
}

/**
 * Handle an iq get stanza with a query in the jabber:iq:agent namespace.
 *
 * Generate a result stanza with information about the session manager (the server).
 * The information is collected from the <vCard/>, <agents/> and <register/> elements
 * in the session manager configuration.
 *
 * @param m the mapi structure (contains the request packet)
 * @return M_HANDLED if the request could be answered, M_PASS if no information could be found in the configuration file.
 */
static mreturn mod_agents_agent(mapi m) {
    xmlnode ret, retq, info, agents, reg;

    /* get data from the config file */
    info = js_config(m->si,"vcard:vCard", xmlnode_get_lang(m->packet->x));
    agents = js_config(m->si,"jsm:agents", xmlnode_get_lang(m->packet->x));
    reg = js_config(m->si,"register:register", NULL);

    /* if we don't have anything to say, bounce */
    if(info == NULL && agents == NULL && reg == NULL)
        return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling agent query");

    /* build the result IQ */
    ret = jutil_iqresult(m->packet->x);
    retq = xmlnode_insert_tag_ns(ret, "query", NULL, NS_AGENT);

    /* copy in the vCard info */
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(retq, "name", NULL, NS_AGENT), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(info, "vcard:FN", m->si->std_namespace_prefixes), 0)),-1);
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(retq, "url", NULL, NS_AGENT), xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(info, "vcard:URL", m->si->std_namespace_prefixes), 0)),-1);
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(retq, "service", NULL, NS_AGENT), "jabber", 6);

    /* set the flags */
    if (agents != NULL)
        xmlnode_insert_tag_ns(retq,"agents", NULL, NS_AGENTS);
    if (reg != NULL)
        xmlnode_insert_tag_ns(retq,"register", NULL, NS_AGENTS);

    jpacket_reset(m->packet);
    if (m->s != NULL) {
	/* XXX null session hack! */
        xmlnode_put_attrib_ns(m->packet->x, "from", NULL, NULL, m->packet->from->server);
        js_session_to(m->s,m->packet);
    } else {
        js_deliver(m->si, m->packet, NULL);
    }

    xmlnode_free(info);
    xmlnode_free(agents);
    xmlnode_free(reg);
    return M_HANDLED;
}

/**
 * Check if we have to process an iq stanza and call the right handler for the stanza
 *
 * Handled are iq stanzas of type 'get' with a query in the namespace jabber:iq:agent or jabber:iq:agents.
 *
 * @param m the mapi structure (contains the stanza)
 * @param arg not used/ignored
 * @return M_IGNORE if the packet is no iq stanza, M_PASS if the packet has not been handled, M_HANDLED if the packet is processed
 */
static mreturn mod_agents_handler(mapi m, void *arg) {
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE; /* only handle IQ stanzas */

    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS; /* only care for IQ stanzas of type 'get' */
    if (m->s != NULL && (m->packet->to != NULL && j_strcmp(jid_full(m->packet->to),m->packet->from->server) != 0))
	return M_PASS; /* for session calls, only answer to=NULL or to=server */

    if (NSCHECK(m->packet->iq, NS_AGENT))
	return mod_agents_agent(m);
    if (NSCHECK(m->packet->iq,NS_AGENTS))
	return mod_agents_agents(m);

    return M_PASS;
}

/**
 * This function registers the mod_agents_handler callback for any outgoing stanza,
 * this is needed so that we can handle <iq/> stanzas without a to attribute.
 *
 * This function gets called once for every stablished session on the session manager.
 *
 * The original comment on this function was, that this is a stupid workaround ;-)
 *
 * Note that the mod_agents_handler callback registered here will effectivly process
 * the jabber:iq:agents iq stanzas including the to attribute as well, but we have to
 * register mod_agents_handler for e_SERVER in mod_agents as well to be able to
 * process queries from users of other session managers or other servers.
 *
 * @param m the mapi structure
 * @param arg not used/ignored
 * @return always M_PASS
 */
static mreturn mod_agents_shack(mapi m, void *arg) {
    js_mapi_session(es_OUT,m->s,mod_agents_handler,NULL);
    return M_PASS;
}

/**
 * initialize the mod_agents module
 *
 * register callbacks for outgoing packets from the session manager (to process iq
 * stanzas without a to attribute) and to process packets that arrive at the
 * session manager address.
 *
 * @param si the session manager instance
 */
extern "C" void mod_agents(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "init");
    js_mapi_register(si,e_SERVER, mod_agents_handler, NULL);
    js_mapi_register(si,e_SESSION, mod_agents_shack, NULL);
    js_mapi_register(si,e_DESERIALIZE, mod_agents_shack, NULL);
}
