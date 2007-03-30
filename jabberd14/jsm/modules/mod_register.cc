/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include "jsm.h"

/**
 * @file mod_register.cc
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
 * this function calls the modules, that registered the e_PASSWORDCHANGE event
 * (i.e. the modules that do authentication and therefore have to store the password
 * as their credentials).
 *
 * @param m the mapi structure holding the original client request
 * @return M_PASS if the modules accepted the new password, M_HANDLED if a module rejected the new password and already returned an error
 */
static mreturn mod_register_passwordchange(mapi m) {
    xmlnode passwordchange = NULL;
    xmlnode_list_item iter = NULL;
    jpacket p;
    int password_present = 0;

    /* create a fictive request */

    /* make a copy of the original request */
    passwordchange = xmlnode_dup(m->packet->x);
    p = jpacket_new(passwordchange);
    xmlnode_change_namespace(p->iq, NS_AUTH);

    /* remove all but the new password, and the username */
    for (iter = xmlnode_get_tags(p->iq, "*", m->si->std_namespace_prefixes); iter != NULL; iter = iter->next) {
	if (iter->node->type != NTYPE_TAG) {
	    xmlnode_hide(iter->node);
	    continue;
	}

	if (!NSCHECK(iter->node, NS_REGISTER)) {
	    xmlnode_hide(iter->node);
	    continue;
	}

	if (j_strcmp(xmlnode_get_localname(iter->node), "username") == 0) {
	    jid_set(p->to, xmlnode_get_data(iter->node), JID_USER);
	    xmlnode_put_attrib_ns(p->x, "to", NULL, NS_SERVER, jid_full(p->to));
	    xmlnode_hide(iter->node);
	    continue;
	}

	if (j_strcmp(xmlnode_get_localname(iter->node), "password") != 0) {
	    xmlnode_hide(iter->node);
	    continue;
	}

	xmlnode_change_namespace(iter->node, NS_AUTH);
	password_present++;
    }

    /* check that there is only one password */
    if (password_present > 1) {
	xmlnode_free(passwordchange);
	jutil_error_xmpp(m->packet->x, XTERROR_NOTACCEPTABLE);
	log_notice(m->user->id->server, "Denied password change, password field has been provied %i times (user %s)", password_present, jid_full(m->packet->to));
	return M_HANDLED;
    }

    /* if there is a password, call the modules */
    if (password_present) {
	if (js_mapi_call(m->si, e_PASSWORDCHANGE, p, NULL, NULL)) {
	    /* it was replied by one of the modules */
	    log_debug2(ZONE, LOGT_REGISTER, "one of the e_PASSWORDCHANGE modules did not like the password change");
	    return M_HANDLED;
	}
    }


    xmlnode_free(passwordchange);
    return M_PASS;
}

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
    xmlnode prefered_nodes = NULL;
    xmlnode_list_item all_nodes = NULL;

    if ((reg = js_config(m->si, "register:register", NULL)) == NULL)
	return M_PASS;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    switch(jpacket_subtype(m->packet)) {
	case JPACKET__GET:

	    /* copy in the registration fields from the config file */
	    xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(reg));

	    /* remove duplicate <instructions/> elements */
	    all_nodes = xmlnode_get_tags(m->packet->iq, "register:instructions", m->si->std_namespace_prefixes);
	    prefered_nodes = xmlnode_select_by_lang(all_nodes, xmlnode_get_lang(m->packet->x));
	    for (; all_nodes != NULL; all_nodes = all_nodes->next) {
		if (all_nodes->node != prefered_nodes) {
		    xmlnode_hide(all_nodes->node);
		}
	    }

	    /* remove duplicate <x xmlns='jabber:x:oob'/> elements */
	    all_nodes = xmlnode_get_tags(m->packet->iq, "xoob:x", m->si->std_namespace_prefixes);
	    prefered_nodes = xmlnode_select_by_lang(all_nodes, xmlnode_get_lang(m->packet->x));
	    for (; all_nodes != NULL; all_nodes = all_nodes->next) {
		if (all_nodes->node != prefered_nodes) {
		    xmlnode_hide(all_nodes->node);
		}
	    }

	    break;

	case JPACKET__SET:

	    log_debug2(ZONE, LOGT_AUTH, "processing valid registration for %s",jid_full(m->packet->to));

	    /* let the auth modules store the credentials */
	    if (mod_register_passwordchange(m) == M_HANDLED) {
		log_notice(m->user->id->server, "Could not store password when processing registration request: %s", jid_full(m->user->id));
		xmlnode_free(reg);
		return M_HANDLED;
	    }

	    log_notice(m->packet->to->server, "User %s registered", jid_full(m->packet->to));

	    /* stamp the registration data */
	    jutil_delay(m->packet->iq,"registered");

	    log_debug2(ZONE, LOGT_REGISTER, "handled packet is: %s", xmlnode_serialize_string(m->packet->iq, xmppd::ns_decl_list(), 0));

	    /* don't store password in the NS_REGISTER namespace */
	    xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:password", m->si->std_namespace_prefixes), 0));
	    xdb_set(m->si->xc, jid_user(m->packet->to), NS_REGISTER, m->packet->iq);

	    /* if configured to, send admins a notice */
	    if (xmlnode_get_attrib_ns(reg, "notify", NULL) != NULL) {
		char *email = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:email", m->si->std_namespace_prefixes), 0));
		spool msg_body = spool_new(m->packet->p);

		spool_add(msg_body, "A new user has just been created!\n");
		spool_add(msg_body, "User: ");
		spool_add(msg_body, jid_full(m->packet->to));
		spool_add(msg_body, "\n");
		spool_add(msg_body, "E-Mail: ");
		spool_add(msg_body, email ? email : "no address provided");

		x = jutil_msgnew("chat", m->packet->to->server, "Registration Notice", spool_print(msg_body));
		xmlnode_put_attrib_ns(x, "from", NULL, NULL, m->packet->to->server);
		js_deliver(m->si, jpacket_new(x), m->s);
	    }

	    /* if also configured, send the new user a welcome message */
	    if ((welcome = js_config(m->si, "welcome", xmlnode_get_lang(m->packet->x))) != NULL) {
		const char *lang = NULL;

		lang = xmlnode_get_lang(welcome);

		x = xmlnode_new_tag_ns("message", NULL, NS_SERVER);
		xmlnode_put_attrib_ns(x, "from", NULL, NULL, m->packet->to->server);
		xmlnode_put_attrib_ns(x, "to", NULL, NULL, jid_full(m->packet->to));
		if (lang != NULL) {
		    xmlnode_put_attrib_ns(x, "lang", "xml", NS_XML, lang);
		}
		xmlnode_insert_node(x, xmlnode_get_firstchild(welcome));
		js_deliver(m->si, jpacket_new(x), m->s);
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
 * check if a registration set request contains all necessary fields
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if no iq request, M_HANDLED if the request in invalid and a bounce has been sent, M_PASS else
 */
static mreturn mod_register_check(mapi m, void *arg) {
    xmlnode register_config = NULL;
    xmlnode_list_item item = NULL;
    xmlnode_list_item request_item = NULL;
    int returned_elements = 0;
    xht register_namespace = NULL;

    /* sanity check */
    if (m == NULL || m->packet == NULL) {
	return M_PASS;
    }

    /* only handle iq packets */
    if (m->packet->type != JPACKET_IQ) {
	return M_IGNORE;
    }

    /* we only verify set queries */
    if (jpacket_subtype(m->packet) != JPACKET__SET) {
	return M_PASS;
    }

    /* get the fields that we requested */
    register_config = js_config(m->si, "register:register", NULL);
    if (register_config == NULL) {
	/* there is nothing we have to verify */
	return M_PASS;
    }

    /* we never require the client to send <instructions/> back */
    register_namespace = xhash_new(1);
    xhash_put(register_namespace, "", const_cast<char*>(NS_REGISTER));
    for (item = xmlnode_get_tags(register_config, "instructions", register_namespace); item != NULL; item = item->next) {
	xmlnode_hide(item->node);
    }

    /* check which elements have been sent back */
    for (request_item = xmlnode_get_tags(m->packet->iq, "register:*", m->si->std_namespace_prefixes); request_item != NULL; request_item = request_item->next) {
	log_debug2(ZONE, LOGT_REGISTER, "we got a reply for: %s", xmlnode_get_localname(request_item->node));

	for (item = xmlnode_get_tags(register_config, xmlnode_get_localname(request_item->node), register_namespace); item != NULL; item = item->next) {
	    returned_elements++;
	    xmlnode_hide(item->node);
	}
    }
    xhash_free(register_namespace);
    register_namespace = NULL;

    /* check if all elements have been returned */
    item = xmlnode_get_tags(register_config, "register:*", m->si->std_namespace_prefixes);
    if (item != NULL) {
	xmlnode_list_item xoob_url = xmlnode_get_tags(register_config, "xoob:x/xoob:url", m->si->std_namespace_prefixes);
	xterror err = {400, "", "modify", "bad-request"};
	if (xoob_url == NULL) {
	    snprintf(err.msg, sizeof(err.msg), "%s: %s", messages_get(xmlnode_get_lang(m->packet->x), N_("Missing data field")), xmlnode_get_localname(item->node));
	} else {
	    snprintf(err.msg, sizeof(err.msg), "%s: %s - %s %s", messages_get(xmlnode_get_lang(m->packet->x), N_("Missing data field")), xmlnode_get_localname(item->node), messages_get(xmlnode_get_lang(m->packet->x), N_("you may also register at")), xmlnode_get_data(xoob_url->node));
	}
	log_debug2(ZONE, LOGT_REGISTER, "returned err msg: %s", err.msg);
	jutil_error_xmpp(m->packet->x, err);
	log_debug2(ZONE, LOGT_REGISTER, "missing fields: %s", xmlnode_serialize_string(register_config, xmppd::ns_decl_list(), 0));
	xmlnode_free(register_config);
	return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_REGISTER, "%i elements have been replied", returned_elements);

    /* have there been any element, that has been replied and that was requested?
     * if no fields where requested, we don't allow account registration
     */
    if (returned_elements <= 0) {
	item = xmlnode_get_tags(register_config, "xoob:x/xoob:url", m->si->std_namespace_prefixes);
	xterror err = {400, "", "modify", "bad-request"};
	if (item == NULL) {
	    snprintf(err.msg, sizeof(err.msg), messages_get(xmlnode_get_lang(m->packet->x), N_("Registration not allowed.")));
	} else {
	    snprintf(err.msg, sizeof(err.msg), "%s %s", messages_get(xmlnode_get_lang(m->packet->x), N_("Registration not allowed. See")), xmlnode_get_data(item->node));
	}
	log_debug2(ZONE, LOGT_REGISTER, "returned err msg: %s", err.msg);
	jutil_error_xmpp(m->packet->x, err);
	xmlnode_free(register_config);
	return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_REGISTER, "registration set request passed all checks");

    xmlnode_free(register_config);
    return M_PASS;
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
    xht register_namespace = NULL;
    xmlnode register_config = NULL;
    xmlnode_list_item iter = NULL;

    /* pre-requisites */
    if (m->user == NULL)
	return M_PASS;

    log_debug2(ZONE, LOGT_AUTH, "updating server: %s, user %s", m->user->id->server, jid_full(m->user->id));

    /* check for their registration */
    reg =  xdb_get(m->si->xc, m->user->id, NS_REGISTER);

    log_debug2(ZONE, LOGT_AUTH, "current registration data: %s", xmlnode_serialize_string(reg, xmppd::ns_decl_list(), 0));

    switch (jpacket_subtype(m->packet)) {
	case JPACKET__GET:
	    /* create reply to the get */
	    xmlnode_put_attrib_ns(m->packet->x, "type", NULL, NULL, "result");
	    jutil_tofrom(m->packet->x);

	    /* copy in the currently known data */
	    xmlnode_insert_node(m->packet->iq, xmlnode_get_firstchild(reg));

	    /* add the registered flag */
	    xmlnode_insert_tag_ns(m->packet->iq, "registered", NULL, NS_REGISTER);

	    /* copy additional required fields from configuration */
	    register_config = js_config(m->si, "register:register", NULL);
	    register_namespace = xhash_new(1);
	    xhash_put(register_namespace, "", const_cast<char*>(NS_REGISTER));
	    for (iter = xmlnode_get_tags(register_config, "register:*", m->si->std_namespace_prefixes); iter != NULL; iter = iter->next) {
		if (j_strcmp(xmlnode_get_localname(iter->node), "instructions") == 0)
		    continue;

		/* check if the field is already present */
		if (xmlnode_get_tags(m->packet->iq, xmlnode_get_localname(iter->node), register_namespace) != NULL)
		    continue;

		/* insert the field */
		xmlnode_insert_tag_ns(m->packet->iq, xmlnode_get_localname(iter->node), NULL, NS_REGISTER);
	    }

	    /* free temp data */
	    xhash_free(register_namespace);
	    register_namespace = NULL;
	    xmlnode_free(register_config);
	    register_config = NULL;

	    break;

	case JPACKET__SET:
	    if (xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:remove", m->si->std_namespace_prefixes), 0) != NULL) {
		xmlnode roster, cur;
		xmlnode nounregister = NULL;

		/* is deleting accounts forbidden by the configuration? */
		nounregister = js_config(m->si, "jsm:nounregister", xmlnode_get_lang(m->packet->x));
		if (nounregister != NULL) {
		    xterror err = {405, N_("Not Allowed"), "cancel", "not-allowed"};
		    char* nounregister_data = xmlnode_get_data(nounregister);
		    if (nounregister_data != NULL) {
			snprintf(err.msg, sizeof(err.msg), "%s", nounregister_data);
		    }
		    js_bounce_xmpp(m->si, m->s, m->packet->x, err);
		    xmlnode_free(nounregister);
		    xmlnode_free(reg);
		    log_notice(m->user->id->server, "Denied unregistration to user %s", jid_full(m->user->id));
		    return M_HANDLED;
		}
	    
		log_notice(m->user->id->server,"User Unregistered: %s",m->user->id->user);

		/* let the modules remove their data for this user */
		js_user_delete(m->si, m->user->id);
	    } else {
		int only_passwordchange = 1;
		int is_passwordchange = 0;
		int has_username = 0;
		xmlnode_list_item iter = NULL;
		xmlnode noregistrationchange = NULL;

		/* is it a password change, or an update for the registration data? */
		for (iter = xmlnode_get_tags(m->packet->iq, "register:*", m->si->std_namespace_prefixes); iter != NULL; iter = iter->next) {
		    const char* localname = xmlnode_get_localname(iter->node);

		    /* the username cannot be changed, if it is present, it has to stay the same */
		    if (j_strcmp(localname, "username") == 0) {
			has_username++;
			jid username_jid = jid_new(m->packet->p, jid_full(m->user->id));
			jid_set(username_jid, xmlnode_get_data(iter->node), JID_USER);
			if (jid_cmp(m->user->id, username_jid) == 0) {
			    xmlnode_hide(iter->node); /* we'll regenerate using preped version */
			    continue; /* it's still the same username, everything is perfect */
			}

			/* user tries to change his username */
			js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTACCEPTABLE);
			xmlnode_free(reg);
			log_notice(m->user->id->server, "Denied update of username for %s to %s", jid_full(m->user->id), xmlnode_get_data(iter->node));
			return M_HANDLED;
		    }

		    /* does the request contain a new password? */
		    if (j_strcmp(localname, "password") == 0) {
			is_passwordchange = 1;
			continue;
		    }

		    /* anything else is a change in the registration data */
		    only_passwordchange = 0;
		}

		/* ensure, that there is exactly one username */
		if (has_username > 1) {
		    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
		    xmlnode_free(reg);
		    log_notice(m->user->id->server, "User %s sent registration data set request containing multiple usernames", jid_full(m->user->id));
		    return M_HANDLED;
		}
		xmlnode_insert_cdata(xmlnode_insert_tag_ns(m->packet->iq, "username", NULL, NS_REGISTER), m->user->id->user, -1);

		/* did we find anything useful? */
		if (!is_passwordchange && only_passwordchange) {
		    js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
		    xmlnode_free(reg);
		    log_notice(m->user->id->server, "User %s sent incomplete registration data set request", jid_full(m->user->id));
		    return M_HANDLED;
		}

		/* if it is a real regstration update (not only password-change), check that all required fields have been provided */
		if (!only_passwordchange) {
		    log_debug2(ZONE, LOGT_ROSTER, "updating registration for %s",jid_full(m->user->id));

		    if (mod_register_check(m, NULL) == M_HANDLED) {
			js_deliver(m->si, jpacket_reset(m->packet), m->s);
			xmlnode_free(reg);
			return M_HANDLED;
		    }

		    /* is updating registration data forbidden by the configuration? */
		    noregistrationchange = js_config(m->si, "jsm:noregistrationchange", xmlnode_get_lang(m->packet->x));
		    if (noregistrationchange != NULL) {
			xterror err = {405, N_("Not Allowed"), "cancel", "not-allowed"};
			char* noregistrationchange_data = xmlnode_get_data(noregistrationchange);
			if (noregistrationchange_data != NULL) {
			    snprintf(err.msg, sizeof(err.msg), "%s", noregistrationchange_data);
			}
			js_bounce_xmpp(m->si, m->s, m->packet->x, err);
			xmlnode_free(noregistrationchange);
			xmlnode_free(reg);
			log_notice(m->user->id->server, "Denied registration data change to user %s", jid_full(m->user->id));
			return M_HANDLED;
		    }
		}

		/* let the authentication modules update the stored password */
		if (is_passwordchange) {
		    xmlnode nopasswordchange = js_config(m->si, "jsm:nopasswordchange", xmlnode_get_lang(m->packet->x));
		    if (nopasswordchange != NULL) {
			xterror err = {405, N_("Not Allowed"), "cancel", "not-allowed"};
			char* nopasswordchange_data = xmlnode_get_data(nopasswordchange);
			if (nopasswordchange_data != NULL) {
			    snprintf(err.msg, sizeof(err.msg), "%s", nopasswordchange_data);
			}
			js_bounce_xmpp(m->si, m->s, m->packet->x, err);
			xmlnode_free(nopasswordchange);
			xmlnode_free(reg);
			log_notice(m->user->id->server, "Denied password change to user %s", jid_full(m->user->id));
			return M_HANDLED;
		    }
		    xmlnode_free(nopasswordchange);

		    if (mod_register_passwordchange(m) == M_HANDLED) {
			xmlnode_free(reg);
			return M_HANDLED;
		    }
		    log_notice(m->user->id->server, "User %s changed password", jid_full(m->user->id));
		}

		if (!only_passwordchange) {
		    /* update the registration data */
		    xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:username", m->si->std_namespace_prefixes), 0)); /* hide the username/password from the reg db */
		    xmlnode_hide(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:password", m->si->std_namespace_prefixes), 0));
		    jutil_delay(m->packet->iq,"updated");
		    xdb_set(m->si->xc, m->user->id, NS_REGISTER, m->packet->iq);
		}
	    }
	    /* clean up and respond */
	    jutil_iqresult(m->packet->x);
	    break;

	default:
	    xmlnode_free(reg);
	    return M_PASS;
    }

    xmlnode_free(reg);
    js_deliver(m->si, jpacket_reset(m->packet), m->s);
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

    /* register request? */
    if (NSCHECK(m->packet->iq, NS_REGISTER))
	return _mod_register_server_register(m);

    /* disco#info query? */
    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return _mod_register_disco_info(m);

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
extern "C" void mod_register(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "init");
    js_mapi_register(si, e_REGISTER, mod_register_new, NULL);
    js_mapi_register(si, e_SERVER, _mod_register_iq_server, NULL);
    js_mapi_register(si, e_DELETE, mod_register_delete, NULL);
    js_mapi_register(si, e_PRE_REGISTER, mod_register_check, NULL);
}
