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
#include <sys/utsname.h>

mreturn mod_version_reply(mapi m, void *arg)
{
    struct utsname un;
    xmlnode os;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_VERSION) || m->packet->to->resource != NULL) return M_PASS;

    /* first, is this a valid request? */
    if(jpacket_subtype(m->packet) != JPACKET__GET)
    {
        js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_version","handling query from",jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_put_attrib(xmlnode_insert_tag(m->packet->x,"query"),"xmlns",NS_VERSION);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"name"),"jsm",3);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"version"),VERSION,-1);

    uname(&un);
    os = xmlnode_insert_tag(m->packet->iq,"os");
    xmlnode_insert_cdata(os,un.sysname,-1);
    xmlnode_insert_cdata(os," ",1);
    xmlnode_insert_cdata(os,un.release,-1);

    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

void mod_version(jsmi si)
{
    char *from;
    xmlnode x;

    js_mapi_register(si,e_SERVER,mod_version_reply,NULL);

    /* check for updates */
    from = xmlnode_get_data(js_config(si,"update"));
    if(from == NULL) return;

    x = xmlnode_new_tag("presence");
    xmlnode_put_attrib(x,"from",from);
    xmlnode_put_attrib(x,"to","jsm@update.jabber.org/" VERSION);
    deliver(dpacket_new(x), si->i);
}

