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

mreturn mod_vcard_jud(mapi m)
{
    xmlnode vcard, reg, regq;
    char *key;

    vcard = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_VCARD);
    key = xmlnode_get_tag_data(m->packet->iq,"key");

    if(vcard != NULL && key != NULL)
    {
        log_debug("mod_vcard_jud","sending registration for %s",jid_full(m->packet->to));
        reg = jutil_iqnew(JPACKET__SET,NS_REGISTER);
        xmlnode_put_attrib(reg,"to",jid_full(m->packet->from));
        xmlnode_put_attrib(reg,"from",jid_full(m->packet->to));
        regq = xmlnode_get_tag(reg,"query");
        xmlnode_insert_cdata(xmlnode_insert_tag(regq,"key"),key,-1);

        xmlnode_insert_cdata(xmlnode_insert_tag(regq,"name"),xmlnode_get_tag_data(vcard,"FN"),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag(regq,"first"),xmlnode_get_tag_data(vcard,"N/GIVEN"),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag(regq,"last"),xmlnode_get_tag_data(vcard,"N/FAMILY"),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag(regq,"nick"),xmlnode_get_tag_data(vcard,"NICKNAME"),-1);
        xmlnode_insert_cdata(xmlnode_insert_tag(regq,"email"),xmlnode_get_tag_data(vcard,"EMAIL"),-1);
        js_deliver(m->si,jpacket_new(reg));
    }

    xmlnode_free(m->packet->x);
    xmlnode_free(vcard);
    return M_HANDLED;
}

mreturn mod_vcard_set(mapi m, void *arg)
{
    xmlnode vcard, cur, judreg;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->packet->to != NULL || !NSCHECK(m->packet->iq,NS_VCARD)) return M_PASS;

    vcard = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_VCARD);

    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__GET:
        log_debug("mod_vcard","handling get request");
        xmlnode_put_attrib(m->packet->x,"type","result");

        /* insert the vcard into the result */
        xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(vcard));
        jpacket_reset(m->packet);

        /* send to the user */
        js_session_to(m->s,m->packet);

        break;
    case JPACKET__SET:
        log_debug("mod_vcard","handling set request %s",xmlnode2str(m->packet->iq));

        /* save and send response to the user */
        if(xdb_set(m->si->xc, m->user->id->server, m->user->id, NS_VCARD, xmlnode_dup(m->packet->iq)))
        {
            /* failed */
            jutil_error(m->packet->x,TERROR_UNAVAIL);
        }else{
            jutil_iqresult(m->packet->x);
        }

        /* don't need to send the whole thing back */
        xmlnode_hide(xmlnode_get_tag(m->packet->x,"vcard"));
        jpacket_reset(m->packet);
        js_session_to(m->s,m->packet);

        /* send a get request to the jud services */
        for(cur = xmlnode_get_firstchild(js_config(m->si,"agents")); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            if(j_strcmp(xmlnode_get_tag_data(cur,"service"),"jud") != 0) continue;

            judreg = jutil_iqnew(JPACKET__GET,NS_REGISTER);
            xmlnode_put_attrib(judreg,"to",xmlnode_get_attrib(cur,"jid"));
            xmlnode_put_attrib(judreg,"id","mod_vcard_jud");
            js_session_from(m->s,jpacket_new(judreg));
        }
        break;
    default:
        xmlnode_free(m->packet->x);
        break;
    }
    xmlnode_free(vcard);
    return M_HANDLED;
}

mreturn mod_vcard_reply(mapi m, void *arg)
{
    xmlnode vcard;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(j_strcmp(xmlnode_get_attrib(m->packet->x,"id"),"mod_vcard_jud") == 0) return mod_vcard_jud(m);
    if(!NSCHECK(m->packet->iq,NS_VCARD)) return M_PASS;

    /* first, is this a valid request? */
    switch(jpacket_subtype(m->packet))
    {
    case JPACKET__RESULT:
    case JPACKET__ERROR:
        return M_PASS;
    case JPACKET__SET:
        js_bounce(m->si,m->packet->x,TERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug("mod_vcard","handling query for user %s",m->user->user);

    /* get this guys vcard info */
    vcard = xdb_get(m->si->xc, m->user->id->server, m->user->id, NS_VCARD);

    /* check permissions, XXX hack for now till vcard draft
    if(xmlnode_get_tag(vcard,"public") == NULL)
{ 
        item = js_xdb_get(m->user, NS_ROSTER);
        item = jid_nodescan(m->packet->from,item);
        sub = xmlnode_get_attrib(item,"subscription");
        if(sub == NULL || j_strcmp(sub,"none") == 0 || j_strcmp(sub,"to") == 0)
        {
            js_bounce(m->si,m->packet->x,TERROR_FORBIDDEN);
            return;
        }
}*/

    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    xmlnode_insert_tag_node(m->packet->x,vcard);
    js_deliver(m->si,m->packet);

    xmlnode_free(vcard);
    return M_HANDLED;
}

mreturn mod_vcard_session(mapi m, void *arg)
{
    js_mapi_session(es_OUT,m->s,mod_vcard_set,NULL);
    js_mapi_session(es_IN,m->s,mod_vcard_reply,NULL);
    return M_PASS;
}

void mod_vcard(jsmi si)
{
    js_mapi_register(si,e_SESSION,mod_vcard_session,NULL);
    js_mapi_register(si,e_OFFLINE,mod_vcard_reply,NULL);
}


