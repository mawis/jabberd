/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

#include "jsm.h"

mreturn mod_register_new(mapi m, void *arg)
{
    xmlnode q, reg;
    udata u;

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

        /* make sure we ask for the username and password, otherwise what's the point? */
        xmlnode_insert_tag(q,"username");
        xmlnode_insert_tag(q,"password");

        /* insert the key, we don't need to check it, but we'll send it :) */
        xmlnode_insert_cdata(xmlnode_insert_tag(q,"key"),jutil_regkey(NULL,"foobar"),-1);
        break;

    case JPACKET__SET:

        /* make sure the username they want isn't in use */
        u = js_user(m->si, m->packet->to, NULL);
        if(u != NULL)
        {
            jutil_error(m->packet->x, (terror){409,"Username Not Available"});
            break;
        }

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
    udata u;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;
    if(m->packet->from->user == NULL || !ghash_get(m->si->hosts, m->packet->from->server)) return M_PASS;
    if(js_config(m->si,"register") == NULL) return M_PASS;

    log_debug("mod_register","updating");

    /* get the sender */
    u = js_user(m->si,m->packet->from,NULL);
    if(u == NULL)
    {
        js_bounce(m->si, m->packet->x,TERROR_FORBIDDEN);
        return M_HANDLED;
    }

    /* check for their registration */
    reg =  xdb_get(m->si->xc, m->packet->to->server, m->packet->to, NS_REGISTER);
    if(reg == NULL)
    {
        js_bounce(m->si, m->packet->x,TERROR_REGISTER);
        return M_HANDLED;
    }

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        /* create reply to the get */
        jutil_iqresult(m->packet->x);

        /* create a new query */
        q = xmlnode_insert_tag(m->packet->x, "query");
        xmlnode_put_attrib(q,"xmlns",NS_REGISTER);

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
        xmlnode_hide(xmlnode_get_tag(q,"username"));

        break;

    case JPACKET__SET:
        if(xmlnode_get_tag(m->packet->iq,"remove") != NULL)
        {
            log_debug(ZONE,"REMOVING registration for %s",u->user);

            /* remove the registration and auth and any misc data */
            xdb_set(m->si->xc, m->packet->from->server, m->packet->from, NS_REGISTER, NULL);
            xdb_set(m->si->xc, m->packet->from->server, m->packet->from, NS_AUTH, NULL);
            xdb_set(m->si->xc, m->packet->from->server, m->packet->from, NS_PRIVATE, NULL);
            xdb_set(m->si->xc, m->packet->from->server, m->packet->from, NS_ROSTER, NULL);
            xdb_set(m->si->xc, m->packet->from->server, m->packet->from, NS_VCARD, NULL);
        }else{
            log_debug(ZONE,"updating registration for %s",u->user);

            /* try to reset the password */
            if(xdb_set(m->si->xc, m->packet->from->server, m->packet->from, NS_AUTH, xmlnode_get_tag(m->packet->iq,"password")))
            {
                js_bounce(m->si, m->packet->x,TERROR_FORBIDDEN); /* or 503? */
                return M_HANDLED;
            }

            /* update the registration data */
            xmlnode_hide(xmlnode_get_tag(m->packet->iq,"username")); /* hide the username/password from the reg db */
            xmlnode_hide(xmlnode_get_tag(m->packet->iq,"password"));
            xdb_set(m->si->xc, m->packet->from->server, m->packet->from, NS_REGISTER, m->packet->iq);

        }
        /* clean up and respond */
        jutil_iqresult(m->packet->x);
        break;

    default:
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
