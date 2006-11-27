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
 * --------------------------------------------------------------------------*/
#include "jsm.h"

/**
 * @file mod_xml.c
 * @brief handling jabber:iq:private (XEP-0049) requests
 *
 * This module implements the storage of private data by a client on the server using the
 * jabber:iq:private namespace documented in XEP-0049.
 *
 * The module also used to implement the storage of data, that had been accessible by any entity on
 * the Jabber network and the handling of requests by other users to this data. But this has been
 * dropped with jabberd14 1.6.0.
 */

/**
 * callback that handles iq stanzas of the user itself (either set and get requests!)
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_IGNORE if it is not an iq stanza, M_PASS if the stanza has not been processed, M_HANDLED if the stanza has been handled
 */
mreturn mod_xml_set(mapi m, void *arg) {
    xmlnode storedx, inx = m->packet->iq;
    const char *ns = xmlnode_get_namespace(m->packet->iq);
    int private = 0;
    int got_result = 0;
    jpacket jp;
    xmlnode_list_item result_item = NULL;

    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    /* to someone else? */
    if (m->packet->to != NULL)
	return M_PASS;

    /* we only handle requests in the jabber:iq:private namespace */
    if (!NSCHECK(m->packet->iq, NS_PRIVATE))
	return M_PASS;

    private = 1;
    inx = xmlnode_get_firstchild(m->packet->iq);
    while (inx != NULL && (xmlnode_get_type(inx) != NTYPE_TAG || j_strcmp(xmlnode_get_namespace(inx), NS_PRIVATE) == 0 ))
	inx = xmlnode_get_nextsibling(inx);
    if (inx == NULL) {
	jutil_error_xmpp(m->packet->x, (xterror){406, N_("The query element in the jabber:iq:private namespace needs a child element in another namespace."), "modify", "not-acceptable"});
	js_session_to(m->s, m->packet);
	return M_HANDLED;
    }
    ns = xmlnode_get_namespace(inx);

    switch (jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    log_debug2(ZONE, LOGT_DELIVER|LOGT_STORAGE, "handling get request for %s", ns);

	    /* get the stored data */
	    storedx = xdb_get(m->si->xc, m->user->id, NS_PRIVATE);

	    /* get the relevant items */
	    for (result_item = xmlnode_get_tags(storedx, spools(m->packet->p, "private:query[@jabberd:ns='", ns, "']", m->packet->p), m->si->std_namespace_prefixes); result_item != NULL; result_item = result_item->next) {
		if (!got_result) {
		    got_result = 1;
		    /* prepare result */
		    jutil_iqresult(m->packet->x);
		}
		log_debug2(ZONE, LOGT_STORAGE, "found node: %s", xmlnode_serialize_string(result_item->node, NULL, NULL, 0));
		xmlnode_hide_attrib_ns(result_item->node, "ns", NS_JABBERD_WRAPPER);
		xmlnode_insert_tag_node(m->packet->x, result_item->node);
	    }

	    /* found something? */
	    if (!got_result) {
		/* no => return error */
		js_bounce_xmpp(m->si, m->packet->x, XTERROR_NOTFOUND);
	    } else {
		/* yes => return result */
		jpacket_reset(m->packet);
		js_session_to(m->s,m->packet);
	    }

	    /* free the result */
	    xmlnode_free(storedx);

	    break;

	case JPACKET__SET:
	    log_debug2(ZONE, LOGT_DELIVER|LOGT_STORAGE, "handling set request for %s with data %s", ns, xmlnode_serialize_string(inx, NULL, NULL, 0));

	    /* save the changes */
	    xmlnode_put_attrib_ns(m->packet->iq, "ns", "jabberd", NS_JABBERD_WRAPPER, ns);
	    if (xdb_act_path(m->si->xc, m->user->id, NS_PRIVATE, "insert", spools(m->packet->p, "private:query[@jabberd:ns='", ns, "']", m->packet->p), m->si->std_namespace_prefixes, m->packet->iq))
		jutil_error_xmpp(m->packet->x, XTERROR_UNAVAIL);

	    /* build result and send back */
	    jutil_iqresult(m->packet->x);
	    jpacket_reset(m->packet);
	    js_session_to(m->s,m->packet);

	    break;

	default:
	    return M_PASS;
    }

    return M_HANDLED;
}

/**
 * callback that gets notified on new sessions of a user
 *
 * will register mod_xml_set as callback for stanzas sent by the user itself
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_xml_session(mapi m, void *arg) {
    js_mapi_session(es_OUT, m->s, mod_xml_set, NULL);
    return M_PASS;
}

/**
 * if a user is deleted, delete his stored data
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_xml_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_PRIVATE, NULL);
    return M_PASS;
}

/**
 * init the mod_xml module by registering callbacks
 *
 * mod_xml_session will register the mod_xml_set callback to process
 * requests from the user itself when the user starts a new session
 *
 * @param si the session manager instance
 */
void mod_xml(jsmi si) {
    js_mapi_register(si, e_SESSION, mod_xml_session, NULL);
    js_mapi_register(si, e_DESERIALIZE, mod_xml_session, NULL);
    js_mapi_register(si, e_DELETE, mod_xml_delete, NULL);
}
