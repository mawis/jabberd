/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 *
 * util.c -- utility functions for jsm
 * 
 * --------------------------------------------------------------------------*/

#include "jsm.h"

/**
 * @file util.c
 * @brief utility functions for jsm
 */

/**
 * generate an error packet, that bounces a packet back to the server
 *
 * @param si the session manger instance
 * @param x the xmlnode for which the bounce packet should be generated
 * @param xterr the reason for the bounce
 */
void js_bounce_xmpp(jsmi si, xmlnode x, xterror xterr) {
    /* if the node is a subscription */
    if(j_strcmp(xmlnode_get_name(x),"presence") == 0 && j_strcmp(xmlnode_get_attrib(x,"type"),"subscribe") == 0)
    {
        /* turn the node into a result tag. it's a hack, but it get's the job done */
        jutil_iqresult(x);
        xmlnode_put_attrib(x,"type","unsubscribed");
        xmlnode_insert_cdata(xmlnode_insert_tag(x,"status"),xterr.msg,-1);

        /* deliver it back to the client */
        js_deliver(si, jpacket_new(x));
        return;

    }

    /* if it's a presence packet, just drop it */
    if(j_strcmp(xmlnode_get_name(x),"presence") == 0 || j_strcmp(xmlnode_get_attrib(x,"type"),"error") == 0)
    {
        log_debug2(ZONE, LOGT_DELIVER, "dropping %d packet %s",xterr.code,xmlnode2str(x));
        xmlnode_free(x);
        return;
    }

    /* if it's neither of these, make an error message an deliver it */
    jutil_error_xmpp(x, xterr);
    js_deliver(si, jpacket_new(x));

}

#ifdef INCLUDE_LEGACY
/**
 * generate an error packet, that bounces a packet back to the server - using a legacy/pre-xmpp reason
 *
 * This function mapps the legacy/pre-xmpp reason to a xmpp-style reasond and calls js_bounce_xmpp() with that.
 *
 * @param si the session manager instance
 * @param x the xmlnode that generated the bounce
 * @param terr the error code describing the reason for the bounce
 */
void js_bounce(jsmi si, xmlnode x, terror terr)
{
    xterror xterr;

    jutil_error_map(terr, &xterr);
    js_bounce_xmpp(si, x, xterr);
}
#endif


/**
 * get a configuration node inside the session manager configuration
 *
 * @param si the session manager instance data
 * @param query the path through the tag hierarchy of the desired tag, eg. for the conf file
 * 	<foo><bar>bar value</bar><baz/></foo> use "foo/bar" to retrieve the bar node, may be
 * 	NULL to get the root node of the jsm config
 * @return a pointer to the xmlnode, or NULL if no such node could be found
 */
xmlnode js_config(jsmi si, char *query) {

    log_debug2(ZONE, LOGT_CONFIG, "config query %s",query);

    if(query == NULL)
        return si->config;
    else
        return xmlnode_get_tag(si->config, query);
}

/**
 * macro to make sure the jid is a local user
 *
 * @param si the session manager instance data
 * @param id the user to test
 * @return 0 if the user is not local, 1 if the user is local
 */
int js_islocal(jsmi si, jid id)
{
    if(id == NULL || id->user == NULL) return 0;
    if(xhash_get(si->hosts, id->server) == NULL) return 0;
    return 1;
}

/**
 * macro to validate a user as an admin
 *
 * @param u the udata structure of the user
 * @param flag for which right we want to check ADMIN_READ or ADMIN_WRITE
 * @return 1 if the user has the queried admin right, 0 if not
 */
int js_admin(udata u, int flag) {
    if(u == NULL || u->admin == ADMIN_NONE) return 0;

    if(u->admin == ADMIN_UNKNOWN) {
        if(js_config(u->si, spools(u->p,"admin/write=",jid_full(u->id),u->p)) != NULL) {
            u->admin = ADMIN_READ | ADMIN_WRITE;
        } else if (js_config(u->si, spools(u->p,"admin/write-only=",jid_full(u->id),u->p)) != NULL) {
            u->admin = ADMIN_WRITE;
        } else if (js_config(u->si, spools(u->p,"admin/read=",jid_full(u->id),u->p)) != NULL) {
            u->admin = ADMIN_READ;
        } else {
            u->admin = ADMIN_NONE;
        }
    }

    if(u->admin & flag)
        return 1;

    return 0;
}

/**
 * get the list of jids, that are subscribed to a given user
 *
 * @param u for which user to get the list
 * @return pointer to the first list entry
 */
jid js_trustees(udata u) {
    xmlnode roster, cur;

    if(u == NULL) return NULL;

    if(u->utrust != NULL) return u->utrust;

    log_debug2(ZONE, LOGT_SESSION, "generating trustees list for user %s",jid_full(u->id));

    /* initialize with at least self */
    u->utrust = jid_user(u->id);

    /* fill in rest from roster */
    roster = xdb_get(u->si->xc, u->id, NS_ROSTER);
    for(cur = xmlnode_get_firstchild(roster); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
        if(j_strcmp(xmlnode_get_attrib(cur,"subscription"),"from") == 0 || j_strcmp(xmlnode_get_attrib(cur,"subscription"),"both") == 0)
            jid_append(u->utrust,jid_new(u->p,xmlnode_get_attrib(cur,"jid")));
    }
    xmlnode_free(roster);

    return u->utrust;
}


/**
 * this tries to be a smarter jid matcher, where a "host" matches any "user@host" and "user@host" matches "user@host/resource"
 *
 * @param id the jid that should be checked
 * @param match the jid that should be matched
 * @return 0 if it did not match, 1 if it did match
 */
int _js_jidscanner(jid id, jid match)
{
    for(;id != NULL; id = id->next)
    {
        if(j_strcmp(id->server,match->server) != 0) continue;
        if(id->user == NULL) return 1;
        if(j_strcasecmp(id->user,match->user) != 0) continue;
        if(id->resource == NULL) return 1;
        if(j_strcmp(id->resource,match->resource) != 0) continue;
        return 1;
    }
    return 0;
}

/**
 * check if a id is trusted (allowed to see the presence of a user)
 *
 * @param u the user for which the check should be made
 * @param id the jid which should be checked if it is trusted
 * @return 0 if it is not trusted, 1 if it is trusted
 */
int js_trust(udata u, jid id)
{
    if(u == NULL || id == NULL) return 0;

    /* first, check global trusted ids */
    if(_js_jidscanner(u->si->gtrust,id)) return 1;

    /* then check user trusted ids */
    if(_js_jidscanner(js_trustees(u),id)) return 1;

    return 0;
}

/**
 * check if a mapi call is for the "online" event
 *
 * sucks, should just rewrite the whole mapi to make things like this better
 *
 * @param m the mapi call
 * @return 1 if the mapi call is for the "online" event, 0 else
 */
int js_online(mapi m) {
    if(m == NULL || m->packet == NULL || m->packet->to != NULL || m->s == NULL || m->s->priority >= -128) return 0;

    if(jpacket_subtype(m->packet) == JPACKET__AVAILABLE || jpacket_subtype(m->packet) == JPACKET__INVISIBLE) return 1;

    return 0;
}
