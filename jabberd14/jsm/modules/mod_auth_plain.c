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

mreturn mod_auth_plain_jane(mapi m, void *arg)
{
    char *passA, *passB;
    xmlnode xdb;

    log_debug("mod_auth_plain","checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do plain-text auth */
        xmlnode_insert_tag(m->packet->iq,"password");
        return M_PASS;
    }

    if((passA = xmlnode_get_tag_data(m->packet->iq, "password")) == NULL)
        return M_PASS;

    /* make sure we can get the auth packet and that it contains a password */
    xdb = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_AUTH);
    if(xdb == NULL || (passB = xmlnode_get_data(xdb)) == NULL)
    {
        xmlnode_free(xdb);
        return M_PASS;
    }

    log_debug("mod_auth_plain","comparing %s %s",passA,passB);

    if(strcmp(passA, passB) != 0)
        jutil_error(m->packet->x, TERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    xmlnode_free(xdb); /* free xdb results */

    return M_HANDLED;
}

int mod_auth_plain_reset(mapi m, xmlnode pass)
{
    log_debug("mod_auth_plain","resetting password");
    if(xmlnode_get_data(pass) == NULL) return 1;

    return xdb_set(m->si->xc, m->packet->to->server, m->packet->to, NS_AUTH, pass);
}

/* handle saving the password for registration */
mreturn mod_auth_plain_reg(mapi m, void *arg)
{
    if(jpacket_subtype(m->packet) != JPACKET__SET) return M_PASS;

    if(mod_auth_plain_reset(m,xmlnode_get_tag(m->packet->iq,"password")))
    {
        jutil_error(m->packet->x,(terror){500,"Password Storage Failed"});
        return M_HANDLED;
    }

    return M_PASS;
}

/* handle password change requests from a session */
mreturn mod_auth_plain_server(mapi m, void *arg)
{
    xmlnode pass;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(jpacket_subtype(m->packet) != JPACKET__SET || !NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;
    if(!js_islocal(m->si, m->packet->from)) return M_PASS;
    if((pass = xmlnode_get_tag(m->packet->iq,"password")) == NULL) return M_PASS;

    if(mod_auth_plain_reset(m,pass))
    {
        js_bounce(m->si,m->packet->x,(terror){500,"Password Storage Failed"});
        return M_HANDLED;
    }
    return M_PASS;
}

void mod_auth_plain(jsmi si)
{
    log_debug("mod_auth_plain","init");
    js_mapi_register(si, e_REGISTER, mod_auth_plain_reg, NULL);
    js_mapi_register(si, e_AUTH, mod_auth_plain_jane, NULL);
    js_mapi_register(si, e_SERVER, mod_auth_plain_server, NULL);
}
