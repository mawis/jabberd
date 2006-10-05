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
 :q



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
 * --------------------------------------------------------------------------*/
#include "jsm.h"

/**
 * @file mod_time.c
 * @brief implement the Entity Time protocol (XEP-0090)
 *
 * The protocol implemented by this module can be used the query the current time on the server.
 */

/**
 * callback that handles iq stanzas containing a query in the jabber:x:time namespace
 *
 * ignores stanzas of other types, does not process iq stanzas containing other namespaces or addressed to a reseouce of the server
 *
 * sends back replies to jabber:x:time queries.
 *
 * @param m the mapi structure
 * @return M_IGNORED if not a iq stanza, M_PASS if other namespace or sent to a resource of the server, M_HANDLED else
 */
static mreturn _mod_time_reply(mapi m) {
    time_t t;
    char *tstr;
    struct tm *tmd;

    if (m->packet->to->resource != NULL)
	return M_PASS;

    /* first, is this a valid request? */
    if (jpacket_subtype(m->packet) != JPACKET__GET) {
        js_bounce_xmpp(m->si,m->packet->x,XTERROR_NOTALLOWED);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling time query from %s", jid_full(m->packet->from));

    jutil_iqresult(m->packet->x);
    xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_TIME);
    jpacket_reset(m->packet);
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "utc", NULL, NS_TIME),jutil_timestamp(),-1);

    /* create nice display time */
    t = time(NULL);
    tstr = ctime(&t);
    tstr[strlen(tstr) - 1] = '\0'; /* cut off newline */
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "display", NULL, NS_TIME),tstr,-1);
    tzset();
    tmd = localtime(&t);

#ifdef TMZONE
    /* some platforms don't have tzname I guess */
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "tz", NULL, NS_TIME), tmd->tm_zone, -1);
#else
    xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "tz", NULL, NS_TIME), tzname[0], -1);
#endif

    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn _mod_time_disco_info(mapi m) {
    xmlnode feature = NULL;

    /* only no node, only get */
    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS;
    if (xmlnode_get_attrib_ns(m->packet->iq, "node", NULL) != NULL)
	return M_PASS;

    /* build the result IQ */
    js_mapi_create_additional_iq_result(m, "query", NULL, NS_DISCO_INFO);
    if (m->additional_result == NULL || m->additional_result->iq == NULL)
	return M_PASS;

    /* add features */
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_TIME);

    return M_PASS;
}

/**
 * handle iq packets to the server address
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if no iq request, M_HANDLED or M_PASS else
 */
static mreturn mod_time_iq_server(mapi m, void *arg) {
    /* sanity check */
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    /* only handle iq packets */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    /* version request? */
    if (NSCHECK(m->packet->iq, NS_TIME))
	return _mod_time_reply(m);

    /* disco#info query? */
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return _mod_time_disco_info(m);

    return M_PASS;
}

/**
 * init this module
 *
 * register mod_time_reply() as a callback for stanzas sent to the server's address
 *
 * @param si the session manager instance
 */
void mod_time(jsmi si) {
    js_mapi_register(si,e_SERVER, mod_time_iq_server,NULL);
}
