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

mreturn mod_echo_reply(mapi m, void *arg)
{
    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;

    /* first, is this a valid request? */
    if(m->packet->to->resource == NULL || strncasecmp(m->packet->to->resource,"echo",4) != 0) return M_PASS;

    log_debug("mod_echo","handling echo request from %s",jid_full(m->packet->from));

    xmlnode_put_attrib(m->packet->x,"from",jid_full(m->packet->to));
    xmlnode_put_attrib(m->packet->x,"to",jid_full(m->packet->from));
    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

void mod_echo(jsmi si)
{
    js_mapi_register(si,e_SERVER,mod_echo_reply,NULL);
}


