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

mreturn mod_register_new(mapi m, void *arg)
{
    xmlnode q, reg;

    if((reg = js_config(m->si, "register")) == NULL) return M_PASS;

    log_debug("mod_register","checking");

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        /* create reply to the get */
        jutil_iqresult(m->packet->x);

        /* create a new query */
        q = xmlnode_insert_tag(m->packet->x, "query");
        xmlnode_put_attrib(q,"xmlns",NS_REGISTER);

        /* copy in the registration fields from the config file */
        xmlnode_insert_node(q,xmlnode_get_firstchild(reg));

        /* insert the key, we don't need to check it, but we'll send it :) */
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"key"),jutil_regkey(NULL,"foobar"),-1);
        break;

    case JPACKET__SET:

        log_debug(ZONE,"processing valid registration for %s",jid_full(m->packet->to));

        /* try to save the auth data */
        if(xdb_set(m->si->xc, m->packet->to->server, m->packet->to, NS_AUTH, xmlnode_get_tag(m->packet->iq,"password")))
        {
            jutil_error(m->packet->x, TERROR_FORBIDDEN); /* or 503? */
            break;
        }

        /* save the registration data */
        xmlnode_hide(xmlnode_get_tag(m->packet->iq,"password")); /* hide the username/password from the reg db */
        xmlnode_hide(xmlnode_get_tag(m->packet->iq,"username"));
        jutil_delay(m->packet->iq,"registered");
        xdb_set(m->si->xc, m->packet->to->server, m->packet->to, NS_REGISTER, m->packet->iq);

        /* clean up and respond */
        jutil_iqresult(m->packet->x);
        break;

    default:
        return M_PASS;
    }

    return M_HANDLED;
}

mreturn mod_register_server(mapi m, void *arg)
{
    xmlnode q, reg, cur, check;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;
    if(m->user == NULL) return M_PASS;
    if(js_config(m->si,"register") == NULL) return M_PASS;

    log_debug("mod_register","updating server: %s, user %s",m->user->id->server,jid_full(m->user->id));

    /* check for their registration */
    reg =  xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_REGISTER);

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        /* create reply to the get */
        jutil_iqresult(m->packet->x);

        /* create a new query */
        q = xmlnode_insert_tag(m->packet->x, "query");
        xmlnode_put_attrib(q,"xmlns",NS_REGISTER);
        xmlnode_insert_tag(q,"password");

        /* copy in the registration fields from the config file */
        xmlnode_insert_node(q,xmlnode_get_firstchild(js_config(m->si,"register")));

        /* insert the key, we don't need to check it, but we'll send it :) */
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"key"),jutil_regkey(NULL,"foobar"),-1);

        /* replace fields with already-registered ones */
        for(cur = xmlnode_get_firstchild(q); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            if(xmlnode_get_type(cur) != NTYPE_TAG) continue;

            check = xmlnode_get_tag(reg,xmlnode_get_name(cur));
            if(check == NULL) continue;

            xmlnode_insert_node(cur,xmlnode_get_firstchild(check));
        }

        /* add the registered flag and hide the username flag */
        xmlnode_insert_tag(q,"registered");

        break;

    case JPACKET__SET:
        if(xmlnode_get_tag(m->packet->iq,"remove") != NULL)
        {
            log_notice(m->user->id->server,"User Unregistered: %s",m->user->user);

            /* XXX BRUTE FORCE: remove the registration and auth and any misc data */
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_REGISTER, NULL);
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_AUTH, NULL);
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_PRIVATE, NULL);
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_ROSTER, NULL);
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_VCARD, NULL);
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_OFFLINE, NULL);
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_FILTER, NULL);
        }else{
            log_debug(ZONE,"updating registration for %s",jid_full(m->user->id));

            /* update the registration data */
            xmlnode_hide(xmlnode_get_tag(m->packet->iq,"username")); /* hide the username/password from the reg db */
            xmlnode_hide(xmlnode_get_tag(m->packet->iq,"password"));
            jutil_delay(m->packet->iq,"updated");
            xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_REGISTER, m->packet->iq);

        }
        /* clean up and respond */
        jutil_iqresult(m->packet->x);
        break;

    default:
        xmlnode_free(reg);
        return M_PASS;
    }

    xmlnode_free(reg);
    js_deliver(m->si, jpacket_reset(m->packet));
    return M_HANDLED;
}

void mod_register(jsmi si)
{
    log_debug("mod_register","init");
    js_mapi_register(si, e_REGISTER, mod_register_new, NULL);
    js_mapi_register(si, e_SERVER, mod_register_server, NULL);
}
