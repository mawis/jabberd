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

/* logs session characteristics */
mreturn mod_log_session_end(mapi m, void *arg)
{
    time_t t = time(NULL);

    log_debug(ZONE,"creating session log entry");

    log_record(jid_full(m->user->id), "session", "end", "%d %d %d %s", (int)(t - m->s->started), m->s->c_in, m->s->c_out, m->s->res);

    return M_PASS;
}

mreturn mod_log_archiver(mapi m, void* arg)
{
    jid svcs = (jid)arg;
    xmlnode x;
    
    if(m->packet->type != JPACKET_MESSAGE) return M_IGNORE;

    log_debug(ZONE,"archiving message");

    /* get a copy wrapped w/ a route and stamp it w/ a type='archive' (why not?) */
    x = xmlnode_wrap(xmlnode_dup(m->packet->x), "route");
    xmlnode_put_attrib(x,"type","archive");

    /* if there's more than one service, copy to the others */
    for(;svcs->next != NULL; svcs = svcs->next)
    {
        xmlnode_put_attrib(x, "to", jid_full(svcs));
        deliver(dpacket_new(xmlnode_dup(x)), NULL);
    }

    /* send off to the last (or only) one */
    xmlnode_put_attrib(x, "to", jid_full(svcs));
    deliver(dpacket_new(x), NULL);

    return M_PASS;
}

/* log session */
mreturn mod_log_session(mapi m, void *arg)
{
    jid svcs = (jid)arg;

    if(svcs != NULL)
    {
        js_mapi_session(es_IN, m->s, mod_log_archiver, svcs);
        js_mapi_session(es_OUT, m->s, mod_log_archiver, svcs);
    }

    /* we always generate log records, if you don't like it, don't use mod_log :) */
    js_mapi_session(es_END, m->s, mod_log_session_end, NULL);

    return M_PASS;
}

/* we should be last in the list of modules */
void mod_log(jsmi si)
{
    xmlnode cfg = js_config(si,"archive");
    jid svcs = NULL;

    log_debug(ZONE,"mod_log init");

    /* look for archiving service too */
    for(cfg = xmlnode_get_firstchild(cfg); cfg != NULL; cfg = xmlnode_get_nextsibling(cfg))
    {
        if(xmlnode_get_type(cfg) != NTYPE_TAG || j_strcmp(xmlnode_get_name(cfg),"service") != 0) continue;
        if(svcs == NULL)
            svcs = jid_new(si->p,xmlnode_get_data(cfg));
        else
            jid_append(svcs,jid_new(si->p,xmlnode_get_data(cfg)));
    }

    js_mapi_register(si,e_SESSION, mod_log_session, (void*)svcs);
}

