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

mreturn mod_auth_plain_jane(mapi m, void *arg)
{
    char *pass;

    log_debug("mod_auth_plain","checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do plain-text auth */
        xmlnode_insert_tag(m->packet->iq,"password");
        return M_PASS;
    }

    if((pass = xmlnode_get_tag_data(m->packet->iq, "password")) == NULL)
        return M_PASS;

    /* if no password stored, try a check */
    if(m->user->pass == NULL)
    {
        log_debug("mod_auth_plain","using xdb act check");
        if(xdb_act(m->si->xc, m->user->id, NS_AUTH, "check", NULL, xmlnode_get_tag(m->packet->iq,"password")))
            jutil_error(m->packet->x, TERROR_AUTH);
    }else if(strcmp(pass, m->user->pass) != 0) {
        jutil_error(m->packet->x, TERROR_AUTH);
    }else{
        jutil_iqresult(m->packet->x);
    }
    return M_HANDLED;
}

int mod_auth_plain_reset(mapi m, jid id, xmlnode pass)
{
    log_debug("mod_auth_plain","resetting password");

    xmlnode_put_attrib(pass,"xmlns",NS_AUTH);
    return xdb_set(m->si->xc, id, NS_AUTH, pass);
}

/* handle saving the password for registration */
mreturn mod_auth_plain_reg(mapi m, void *arg)
{
    jid id;
    xmlnode pass;

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do plain-text regs */
        xmlnode_insert_tag(m->packet->iq,"password");
        return M_PASS;
    }

    if(jpacket_subtype(m->packet) != JPACKET__SET || (pass = xmlnode_get_tag(m->packet->iq,"password")) == NULL) return M_PASS;

    /* get the jid of the user, depending on how we were called */
    if(m->user == NULL)
        id = jid_user(m->packet->to);
    else
        id = m->user->id;

    /* tuck away for a rainy day */
    if(mod_auth_plain_reset(m,id,pass))
    {
        jutil_error(m->packet->x,(terror){500,"Password Storage Failed"});
        return M_HANDLED;
    }

    return M_PASS;
}

/* handle password change requests from a session */
mreturn mod_auth_plain_server(mapi m, void *arg)
{
    mreturn ret;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->user == NULL) return M_PASS;
    if(!NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;

    /* just do normal reg process, but deliver afterwards */
    ret = mod_auth_plain_reg(m,arg);
    if(ret == M_HANDLED)
        js_deliver(m->si, jpacket_reset(m->packet));

    return ret;
}

void mod_auth_plain(jsmi si)
{
    log_debug("mod_auth_plain","init");

    js_mapi_register(si, e_AUTH, mod_auth_plain_jane, NULL);
    js_mapi_register(si, e_SERVER, mod_auth_plain_server, NULL);
    if (js_config(si,"register") != NULL) js_mapi_register(si, e_REGISTER, mod_auth_plain_reg, NULL);
}
