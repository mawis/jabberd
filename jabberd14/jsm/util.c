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
 * util.c -- utility functions for jsm
 * 
 * --------------------------------------------------------------------------*/

#include "jsm.h"

/*
 *  js_bounce -- short_desc
 *  
 *  Long_description
 *
 *  parameters
 *  	x -- the node to bounce
 *      terr - the error code describing the reason for the bounce
 *
 */
void js_bounce(jsmi si, xmlnode x, terror terr)
{
    /* if the node is a subscription */
    if(j_strcmp(xmlnode_get_name(x),"presence") == 0 && j_strcmp(xmlnode_get_attrib(x,"type"),"subscribe") == 0)
    {
        /* turn the node into a result tag. it's a hack, but it get's the job done */
        jutil_iqresult(x);
        xmlnode_put_attrib(x,"type","unsubscribed");
        xmlnode_insert_cdata(xmlnode_insert_tag(x,"status"),terr.msg,-1);

        /* deliver it back to the client */
        js_deliver(si, jpacket_new(x));
        return;

    }

    /* if it's a presence packet, just drop it */
    if(j_strcmp(xmlnode_get_name(x),"presence") == 0 || j_strcmp(xmlnode_get_attrib(x,"type"),"error") == 0)
    {
        log_debug(ZONE,"dropping %d packet %s",terr.code,xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* if it's neither of these, make an error message an deliver it */
    jutil_error(x, terr);
    js_deliver(si, jpacket_new(x));

}


/*
 *  js_config -- get a configuration node
 *
 *  parameters
 *      si -- session instance
 *      query -- the path through the tag hierarchy of the desired tag
 *               eg. for the conf file <foo><bar>bar value</bar><baz/><foo>
 *               use "foo/bar" to retreive the bar node
 *
 *  returns
 *      a pointer to the xmlnode specified in query
 *      or the root config node if query is null
 */
xmlnode js_config(jsmi si, char *query)
{

    log_debug(ZONE,"config query %s",query);

    if(query == NULL)
        return si->config;
    else
        return xmlnode_get_tag(si->config, query);
}

/* macro to make sure the jid is a local user */
int js_islocal(jsmi si, jid id)
{
    if(id == NULL || id->user == NULL) return 0;
    if(ghash_get(si->hosts, id->server) == NULL) return 0;
    return 1;
}

/* macro to validate a user as an admin */
int js_admin(udata u, int flag)
{
    if(u == NULL || u->admin == ADMIN_NONE) return 0;

    if(u->admin == ADMIN_UNKNOWN)
    {
        if(js_config(u->si, spools(u->p,"admin/write=",jid_full(u->id),u->p)) != NULL)
        {
            u->admin = ADMIN_READ | ADMIN_WRITE;
        }else if(js_config(u->si, spools(u->p,"admin/read=",jid_full(u->id),u->p)) != NULL){
            u->admin = ADMIN_READ;
        }else{
            u->admin = ADMIN_NONE;
        }
    }

    if(u->admin & flag)
        return 1;

    return 0;
}

/* returns true if id has a s10n to u */
int js_s10n(jsmi si, udata u, jid id)
{
    xmlnode x, i;
    char *s10n;

    x =  xdb_get(si->xc, u->id, NS_ROSTER);
    i = xmlnode_get_tag(x,spools(id->p,"?jid=",jid_full(jid_user(id)),id->p));
    if((s10n = xmlnode_get_attrib(i,"subscription")) == NULL)
        return 0;
    if(j_strcmp(s10n,"both") == 0)
        return 1;
    if(j_strcmp(s10n,"from") == 0)
        return 1;
    return 0;
}
