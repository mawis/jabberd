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

mreturn mod_archive_redirect(mapi m, void* arg)
{
    char* redirecthost = (char*)arg;
    xmlnode redirectpkt= NULL;
    
    /* Ensure that we only archive messages */
    if (m->packet->type != JPACKET_MESSAGE) 
        return M_IGNORE;

    redirectpkt = xmlnode_wrap(m->packet->x, "route");
    xmlnode_put_attrib(redirectpkt, "to", redirecthost);

    /* Transmit the message as route message to redirect host */
    log_debug(ZONE, "redirecting to %s: %s", redirecthost, xmlnode2str(redirectpkt));

    deliver(dpacket_new(redirectpkt), NULL);
 
    log_debug(ZONE, "done");
    return M_PASS;
}

mreturn mod_archive_session(mapi m, void *arg)
{
    /* Setup a callback for outgoing _and_ incoming packets */
    js_mapi_session(es_OUT,m->s,mod_archive_redirect,arg);
    js_mapi_session(es_IN, m->s,mod_archive_redirect,arg);
    return M_PASS;
}

void mod_archive(jsmi si)
{
    /* Load configuration info */
    xmlnode cfg = js_config(si, "archiveid");
    if ((cfg != NULL) && (xmlnode_get_data(cfg) != NULL))
    {
        js_mapi_register(si, e_SESSION, mod_archive_session, xmlnode_get_data(cfg));
    }
}


