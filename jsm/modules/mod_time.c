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

mreturn mod_time_reply(mapi m, void *arg)
{
    time_t t;
    char *tstr;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(!NSCHECK(m->packet->iq,NS_TIME)) return M_PASS;

    /* first, is this a valid request? */
    if(jpacket_subtype(m->packet) != JPACKET__GET)
    {
        js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_time","handling time query from %s",jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_put_attrib(xmlnode_insert_tag(m->packet->x,"query"),"xmlns",NS_TIME);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"utc"),jutil_timestamp(),-1);
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"tz"),tzname[0],-1);

    /* create nice display time */
    t = time(NULL);
    tstr = ctime(&t);
    tstr[strlen(tstr) - 1] = '\0'; /* cut off newline */
    xmlnode_insert_cdata(xmlnode_insert_tag(m->packet->iq,"display"),tstr,-1);

    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

void mod_time(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_time_reply,NULL);
}


