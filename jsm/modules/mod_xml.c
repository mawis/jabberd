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

mreturn mod_private_set(mapi m, void *arg)
{
    xmlnode inx, storedx;
    char *ns;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->packet->to != NULL || !NSCHECK(m->packet->iq,NS_PRIVATE)) return M_PASS;

    /* get the namespace of the chunk within the iq:private query */
    inx = xmlnode_get_tag(m->packet->iq,"?xmlns");
    ns = xmlnode_get_attrib(inx,"xmlns");
    if(ns == NULL || strncmp(ns,"jabber:",7) == 0)
    {
        jutil_error(m->packet->x,TERROR_NOTACCEPTABLE);
        js_session_to(m->s,m->packet);
        return M_HANDLED;
    }

    storedx = xdb_get(m->si->xc, m->user->id, ns);

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        log_debug("mod_private","handling get request for %s",ns);
        xmlnode_put_attrib(m->packet->x,"type","result");

        /* insert the chunk into the result */
        if(storedx != NULL)
        {
            xmlnode_insert_tag_node(m->packet->iq, storedx);
            xmlnode_hide(inx);
        }

        /* send to the user */
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);

        break;
    case JPACKET__SET:
        log_debug("mod_private","handling set request for %s",ns);

        /* save the changes */
        log_debug(ZONE,"PRIVATE: %s",xmlnode2str(m->packet->iq));
        if(xdb_set(m->si->xc, m->user->id, ns,xmlnode_dup(inx)))
        {
            /* failed */
            jutil_error(m->packet->x,TERROR_UNAVAIL);
        }else{
            jutil_iqresult(m->packet->x);
        }

        /* send to the user */
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);

        break;
    default:
        xmlnode_free(m->packet->x);
        break;
    }
    xmlnode_free(storedx);

    return M_HANDLED;
}

mreturn mod_private_session(mapi m, void *arg)
{
    js_mapi_session(es_OUT,m->s,mod_private_set,NULL);
    return M_PASS;
}

void mod_private(jsmi si)
{
    js_mapi_register(si,e_SESSION,mod_private_session,NULL);
}


