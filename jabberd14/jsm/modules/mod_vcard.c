/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

#include "jsm.h"

/**
 * @file mod_vcard.c
 * @brief Implement handling of namespace 'vcard-temp' (JEP-0054)
 *
 * This module allows publishing of vcard data, replies queries for the vcard data
 * of a user, responds to queries for the server vcard, and my forward published
 * vcards to a configured Jabber users directory.
 */

/**
 * publish vcard data to a Jabber users directory: handle the result to a get
 * request we sent to the users directory to get a key.
 *
 * @param m the mapi_struct containing the result
 * @return always M_HANDLED
 */
mreturn mod_vcard_jud(mapi m) {
    xmlnode vcard, reg, regq;
    char *key;

    vcard = xdb_get(m->si->xc, m->user->id, NS_VCARD);
    key = xmlnode_get_tag_data(m->packet->iq,"key");

    if(vcard != NULL) {
        log_debug2(ZONE, LOGT_DELIVER, "sending registration for %s",jid_full(m->packet->to));
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

/**
 * handle requests by the user to update his vcard
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if not an iq stanza, M_HANDLED if the packet has been handled, M_PASS else
 */
mreturn mod_vcard_set(mapi m, void *arg) {
    xmlnode vcard = NULL;
    xmlnode cur, judreg;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->packet->to != NULL || !NSCHECK(m->packet->iq,NS_VCARD)) return M_PASS;

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    log_debug2(ZONE, LOGT_DELIVER, "handling get request");

	    /* request the vcard from storage */
	    vcard = xdb_get(m->si->xc, m->user->id, NS_VCARD);
	   
	    /* generate result */
	    xmlnode_put_attrib(m->packet->x,"type","result");

	    /* insert the vcard into the result */
	    xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(vcard));
	    jpacket_reset(m->packet);

	    /* send to the user */
	    js_session_to(m->s,m->packet);

	    /* free the vcard again */
	    xmlnode_free(vcard);

	    break;
	case JPACKET__SET:
	    log_debug2(ZONE, LOGT_DELIVER, "handling set request %s",xmlnode2str(m->packet->iq));

	    /* save and send response to the user */
	    if(xdb_set(m->si->xc, m->user->id, NS_VCARD, m->packet->iq)) {
		/* failed */
		jutil_error_xmpp(m->packet->x,XTERROR_UNAVAIL);
	    } else {
		jutil_iqresult(m->packet->x);
	    }

	    /* don't need to send the whole thing back */
	    xmlnode_hide(xmlnode_get_tag(m->packet->x,"vcard"));
	    jpacket_reset(m->packet);
	    js_session_to(m->s,m->packet);

	    if(js_config(m->si,"vcard2jud") == NULL)
		break;

	    /* handle putting the vcard to the configured jud: send a get request to the jud services */
	    for(cur = xmlnode_get_firstchild(js_config(m->si,"browse")); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		if(j_strcmp(xmlnode_get_attrib(cur,"type"),"jud") != 0) continue;

		judreg = jutil_iqnew(JPACKET__GET,NS_REGISTER);
		xmlnode_put_attrib(judreg,"to",xmlnode_get_attrib(cur,"jid"));
		xmlnode_put_attrib(judreg,"id","mod_vcard_jud");
		js_session_from(m->s,jpacket_new(judreg));

		/* added this in so it only does the first one */
		break;
	    }
	    break;
	default:
	    xmlnode_free(m->packet->x);
	    break;
    }
    return M_HANDLED;
}

/**
 * handle packets sent to an offline user
 *
 * Check if the packet is a query for the user's vcard, if yes reply to it.
 *
 * @param m the mapi_struct containing the query packet
 * @param arg unused/ignored
 * @return M_IGNORE if not an iq stanza, M_HANDLED if the packet is handled, M_PASS else
 */
mreturn mod_vcard_reply(mapi m, void *arg) {
    xmlnode vcard;

    /* we only handle iq stanzas */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;

    /* XXX: this seems to be hacky: we send M_HANDLED for everything with an ID of mod_vcard_jud! */
    if(j_strcmp(xmlnode_get_attrib(m->packet->x,"id"),"mod_vcard_jud") == 0) return mod_vcard_jud(m);

    /* we only care about iq stanzas in the vcard-temp namespace */
    if(!NSCHECK(m->packet->iq,NS_VCARD)) return M_PASS;

    /* first, is this a valid request? */
    switch(jpacket_subtype(m->packet)) {
	case JPACKET__RESULT:
	case JPACKET__ERROR:
	    return M_PASS;
	case JPACKET__SET:
	    js_bounce_xmpp(m->si,m->packet->x,XTERROR_NOTALLOWED);
	    return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_DELIVER, "handling query for user %s",m->user->user);

    /* get this guys vcard info */
    vcard = xdb_get(m->si->xc, m->user->id, NS_VCARD);

    /* send back */
    jutil_iqresult(m->packet->x);
    jpacket_reset(m->packet);
    xmlnode_insert_tag_node(m->packet->x,vcard);
    js_deliver(m->si,m->packet);

    xmlnode_free(vcard);
    return M_HANDLED;
}

/**
 * Register callbacks for a session, called at session establishment
 *
 * Register the mod_vcard_set callback for packets the client sents,
 * register the mod_vcard_reply callback for packets the client receives.
 *
 * @param m the mapi_struct containing the pointer to the new session
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_vcard_session(mapi m, void *arg) {
    js_mapi_session(es_OUT,m->s,mod_vcard_set,NULL);
    js_mapi_session(es_IN,m->s,mod_vcard_reply,NULL);
    return M_PASS;
}

/**
 * handle packets addressed to the server
 *
 * Reply IQ get packets in the vcard-temp namespace addressed to the server
 * by sending the servers vCard back to the sender.
 *
 * @param m the mapi_struct containing the packet
 * @param arg unused/ignored
 * @return M_IGNORE if not a iq stanza, M_HANDLED if the packet has been handled, M_PASS else
 */
mreturn mod_vcard_server(mapi m, void *arg) {   
    xmlnode vcard, query;

    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(jpacket_subtype(m->packet) != JPACKET__GET || !NSCHECK(m->packet->iq,NS_VCARD) || m->packet->to->resource != NULL) return M_PASS;

    /* get data from the config file */
    if((vcard = js_config(m->si,"vCard")) == NULL)
        return M_PASS;

    log_debug2(ZONE, LOGT_DELIVER, "handling server vcard query");

    /* build the result IQ */
    jutil_iqresult(m->packet->x);
    query = xmlnode_insert_tag_node(m->packet->x,vcard);
    xmlnode_put_attrib(query,"xmlns",NS_VCARD);
    jpacket_reset(m->packet);
    js_deliver(m->si,m->packet);

    return M_HANDLED;
}

/**
 * Init the module, register callbacks in the session manager
 *
 * Register mod_vcard_session to be called for new established sessions,
 * register mod_vcard_session to be called for stanzas while user is offline,
 * register mod_vcard_server to be called for packets sent to the server address.
 *
 * @param si the session manager instance internal data
 */
void mod_vcard(jsmi si) {
    js_mapi_register(si,e_SESSION,mod_vcard_session,NULL);
    js_mapi_register(si,e_OFFLINE,mod_vcard_reply,NULL);
    js_mapi_register(si,e_SERVER,mod_vcard_server,NULL);
}
