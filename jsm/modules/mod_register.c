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
 * @file mod_register.c
 * @brief handles in-band registrations (XEP-0077)
 *
 * This module implements the functionality used to register and unregister accounts on the Jabber
 * server and to change passwords.
 *
 * It can be configured to send a welcome message to the user on successful registration.
 *
 * @todo allow the admin to change passwords of other users and delete their accounts (XEP-0133?)
 */

/**
 * handle new user registration requests
 *
 * Handles new user registration requests and sends a welcome message to the new user,
 * if configured to do so.
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_PASS if registration is not allowed, or iq not of type set or get, M_HANDLED else
 */
static mreturn mod_register_new(mapi m, void *arg) {
    xmlnode reg, x;
    xmlnode welcome = NULL;

    if ((reg = js_config(m->si, "register:register")) == NULL)
	return M_PASS;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__GET:

	    /* copy in the registration fields from the config file */
	    xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(reg));

	    break;

	case JPACKET__SET:

	    log_debug2(ZONE, LOGT_AUTH, "processing valid registration for %s",jid_full(m->packet->to));

	    /* save the registration data */
	    jutil_delay(m->packet->iq,"registered");
	    /* don't store password in clear text in the NS_REGISTER namespace */
	    xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes), 0));
	    xdb_set(m->si->xc, jid_user(m->packet->to), NS_REGISTER, m->packet->iq);

	    /* if configured to, send admins a notice */
	    if (xmlnode_get_attrib_ns(reg, "notify", NULL) != NULL) {
		char *email = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:email", m->si->std_namespace_prefixes), 0));
		spool msg_body = spool_new(m->packet->p);

		spool_add(msg_body, "A new user has just been created!\n");
		spool_add(msg_body, "User: ");
		spool_add(msg_body, jid_full(m->packet->to));
		spool_add(msg_body, "\n");
		spool_add(msg_body, "E-Mail: ");
		spool_add(msg_body, email ? email : "no address provided");

		x = jutil_msgnew("chat", m->packet->to->server, "Registration Notice", spool_print(msg_body));
		xmlnode_put_attrib_ns(x, "from", NULL, NULL, m->packet->to->server);
		js_deliver(m->si,jpacket_new(x));
	    }

	    /* if also configured, send the new user a welcome message */
	    if ((welcome = js_config(m->si, "welcome")) != NULL) {
		const char *lang = NULL;

		lang = xmlnode_get_lang(welcome);

		x = xmlnode_new_tag_ns("message", NULL, NS_SERVER);
		xmlnode_put_attrib_ns(x, "from", NULL, NULL, m->packet->to->server);
		xmlnode_put_attrib_ns(x, "to", NULL, NULL, jid_full(m->packet->to));
		if (lang != NULL) {
		    xmlnode_put_attrib_ns(x, "lang", "xml", NS_XML, lang);
		}
		xmlnode_insert_node(x, xmlnode_get_firstchild(welcome));
		js_deliver(m->si,jpacket_new(x));
	    }
	    xmlnode_free(welcome);
	    welcome = NULL;

	    /* clean up and respond */
	    jutil_iqresult(m->packet->x);
	    break;

	default:
	    xmlnode_free(reg);
	    return M_PASS;
    }

    xmlnode_free(reg);
    return M_HANDLED;
}

/**
 * handle jabber:iq:register queries from existing users (removing accounts and changing passwords)
 *
 * This function ignores all stanzas but iq stanzas.
 *
 * This module only handles queries in the jabber:iq:register namespace for existing users. Requests are not
 * handled if the <register/> element does not exist in the session manager configuration.
 *
 * This handles querying for the existing registration by the user, changing the password and removing
 * the account.
 *
 * @param m the mapi structure
 * @return M_IGNORE if stanza is not of type iq, M_PASS if stanza has not been handled, M_HANDLED if stanza has been handled
 */
static mreturn _mod_register_server_register(mapi m) {
    xmlnode reg, cur, check;
    xmlnode register_config = NULL;

    /* pre-requisites */
    if (m->user == NULL)
	return M_PASS;

    log_debug2(ZONE, LOGT_AUTH, "updating server: %s, user %s", m->user->id->server, jid_full(m->user->id));

    /* check for their registration */
    reg =  xdb_get(m->si->xc, m->user->id, NS_REGISTER);

    switch (jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    /* create reply to the get */
	    xmlnode_put_attrib_ns(m->packet->x, "type", NULL, NULL, "result");
	    jutil_tofrom(m->packet->x);

	    /* copy in the registration fields from the config file */
	    register_config = js_config(m->si, "register:register");
	    xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(register_config));
	    xmlnode_free(register_config);
	    register_config = NULL;

	    /* replace fields with already-registered ones */
	    for (cur = xmlnode_get_firstchild(m->packet->iq); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
		if (xmlnode_get_type(cur) != NTYPE_TAG)
		    continue;
		if (j_strcmp(xmlnode_get_namespace(cur), NS_REGISTER) != 0)
		    continue;

		check = xmlnode_get_list_item(xmlnode_get_tags(reg, spools(m->packet->p, "register:", xmlnode_get_localname(cur), m->packet->p), m->si->std_namespace_prefixes), 0);
		if (check == NULL)
		    continue;

		/* copy the text() child */
		xmlnode_insert_node(cur,xmlnode_get_firstchild(check));
	    }

	    /* add the registered flag */
	    xmlnode_insert_tag_ns(m->packet->iq, "registered", NULL, NS_REGISTER);

	    break;

	case JPACKET__SET:
	    if (xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:remove", m->si->std_namespace_prefixes), 0) != NULL) {
		xmlnode roster, cur;
	    
		log_notice(m->user->id->server,"User Unregistered: %s",m->user->id->user);

		/* let the modules remove their data for this user */
		js_user_delete(m->si, m->user->id);
	    } else {
		log_debug2(ZONE, LOGT_ROSTER, "updating registration for %s",jid_full(m->user->id));

		/* update the registration data */
		xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:username", m->si->std_namespace_prefixes), 0)); /* hide the username/password from the reg db */
		xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:password", m->si->std_namespace_prefixes), 0));
		jutil_delay(m->packet->iq,"updated");
		xdb_set(m->si->xc, m->user->id, NS_REGISTER, m->packet->iq);
	    }
	    /* clean up and respond */
	    jutil_iqresult(m->packet->x);
	    break;

	default:
	    xmlnode_free(reg);
	    return M_PASS;
    }

    xmlnode_free(reg);
    js_deliver(m->si, jpacket_reset(m->packet));
    return M_HANDLED;
}

/**
 * delete data in the jabber:iq:register namespace if a user is deleted
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_register_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_REGISTER, NULL);
    return M_PASS;
}

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn _mod_register_disco_info(mapi m) {
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
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_REGISTER);

    return M_PASS;
}

/**
 * handle iq packets to the server address
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if no iq request, M_HANDLED or M_PASS else
 */
static mreturn _mod_register_iq_server(mapi m, void *arg) {
    /* sanity check */
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    /* only handle iq packets */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    /* version request? */
    if (NSCHECK(m->packet->iq, NS_REGISTER))
	return _mod_register_server_register(m);

    /* disco#info query? */
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return _mod_register_disco_info(m);

    return M_PASS;
}

static mreturn mod_register_check(mapi m, void *arg) {
    return M_PASS;
}

/**
 * init the module, register callbacks
 *
 * registers mod_register_new() as the callback for new user's registration requests,
 * registers mod_register_server() as the callback for existing user's registration requests (unregister and change password)
 *
 * @param si the session manager instance
 */
void mod_register(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "init");
    js_mapi_register(si, e_REGISTER, mod_register_new, NULL);
    js_mapi_register(si, e_SERVER, _mod_register_iq_server, NULL);
    js_mapi_register(si, e_DELETE, mod_register_delete, NULL);
    js_mapi_register(si, e_PRE_REGISTER, mod_register_check, NULL);
}
