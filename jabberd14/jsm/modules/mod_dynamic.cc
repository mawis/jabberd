/*
 * Copyrights
 * 
 * Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file mod_dynamic.cc
 * @brief implements dynamic adding and removing of hosts from the JSM instance
 *
 * With this module an administrator can dynamically add or remove hosts from
 * the session manager without the need to restart the instance.
 * But the chances made by this module are not presistant. To get them persistant,
 * you have to add them as well to the configuration file, so the new hosts get
 * (not) configured after a restart. (At least for now.)
 */

static mreturn mod_dynamic_server_disco_items(mapi m) {
    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS;
    char const* node = xmlnode_get_attrib_ns(m->packet->iq, "node", NULL);
    if (j_strcmp(node, NS_COMMAND) != 0 && j_strcmp(node, "host") != 0 && j_strcmp(node, "unhost") != 0) {
	return M_PASS;
    }

    jutil_iqresult(m->packet->x);
    m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_DISCO_ITEMS);
    xmlnode_put_attrib_ns(m->packet->iq, "node", NULL, NULL, NS_COMMAND);

    if (acl_check_access(m->si->xc, ADMIN_DYNAMIC, m->packet->from) && j_strcmp(node, NS_COMMAND) == 0) {
	xmlnode item = xmlnode_insert_tag_ns(m->packet->iq, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(m->packet->to));
	xmlnode_put_attrib_ns(item, "node", NULL, NULL, "host");
	xmlnode_put_attrib_ns(item, "name", NULL, NULL,  messages_get(xmlnode_get_lang(m->packet->x), N_("Add host")));

	item = xmlnode_insert_tag_ns(m->packet->iq, "item", NULL, NS_DISCO_ITEMS);
	xmlnode_put_attrib_ns(item, "jid", NULL, NULL, jid_full(m->packet->to));
	xmlnode_put_attrib_ns(item, "node", NULL, NULL, "unhost");
	xmlnode_put_attrib_ns(item, "name", NULL, NULL,  messages_get(xmlnode_get_lang(m->packet->x), N_("Remove host")));
    }

    jpacket_reset(m->packet);
    js_deliver(m->si, m->packet, NULL);
    return M_HANDLED;
}

/**
 * handle disco info query to the server address, add our feature
 */
static mreturn mod_dynamic_server_disco_info(mapi m) {
    xmlnode feature = NULL;

    /* only no node, only get */
    if (jpacket_subtype(m->packet) != JPACKET__GET)
	return M_PASS;
    char const* disco_node = xmlnode_get_attrib_ns(m->packet->iq, "node", NULL);
    if (j_strcmp(disco_node, NS_COMMAND) == 0) {
	jutil_iqresult(m->packet->x);
	m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_DISCO_INFO);

	xmlnode identity = xmlnode_insert_tag_ns(m->packet->iq, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(identity, "name", NULL, NULL,  messages_get(xmlnode_get_lang(m->packet->x), N_("Commands")));
	xmlnode_put_attrib_ns(identity, "category", NULL, NULL, "automation");
	xmlnode_put_attrib_ns(identity, "type", NULL, NULL, "command-list");

	jpacket_reset(m->packet);
	js_deliver(m->si, m->packet, NULL);
	return M_HANDLED;
    }
    if (j_strcmp(disco_node, "host") == 0) {
	jutil_iqresult(m->packet->x);
	m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_DISCO_INFO);
	xmlnode identity = xmlnode_insert_tag_ns(m->packet->iq, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(identity, "name", NULL, NULL,  messages_get(xmlnode_get_lang(m->packet->x), N_("Add host")));
	xmlnode_put_attrib_ns(identity, "category", NULL, NULL, "automation");
	xmlnode_put_attrib_ns(identity, "type", NULL, NULL, "command-node");
	xmlnode feature = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_COMMAND);
	feature = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_DATA);

	// send back
	jpacket_reset(m->packet);
	js_deliver(m->si, m->packet, NULL);
	return M_HANDLED;
    }
    if (j_strcmp(disco_node, "unhost") == 0) {
	jutil_iqresult(m->packet->x);
	m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "query", NULL, NS_DISCO_INFO);
	xmlnode identity = xmlnode_insert_tag_ns(m->packet->iq, "identity", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(identity, "name", NULL, NULL,  messages_get(xmlnode_get_lang(m->packet->x), N_("Remove host")));
	xmlnode_put_attrib_ns(identity, "category", NULL, NULL, "automation");
	xmlnode_put_attrib_ns(identity, "type", NULL, NULL, "command-node");
	xmlnode feature = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_COMMAND);
	feature = xmlnode_insert_tag_ns(m->packet->iq, "feature", NULL, NS_DISCO_INFO);
	xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_DATA);

	// send back
	jpacket_reset(m->packet);
	js_deliver(m->si, m->packet, NULL);
	return M_HANDLED;
    }
    if (disco_node != NULL) {
	return M_PASS;
    }

    /* build the result IQ */
    js_mapi_create_additional_iq_result(m, "query", NULL, NS_DISCO_INFO);
    if (m->additional_result == NULL || m->additional_result->iq == NULL)
	return M_PASS;

    /* add feature NS_COMMAND */
    feature = xmlnode_insert_tag_ns(m->additional_result->iq, "feature", NULL, NS_DISCO_INFO);
    xmlnode_put_attrib_ns(feature, "var", NULL, NULL, NS_COMMAND); // XXX check that feature has not already been added by other module

    return M_PASS;
}
/**
 * handle our server commands
 *
 * @param m the ::mapi_struct that contains the request
 * @return signalling if this method processed the request
 */
static mreturn mod_dynamic_server_command(mapi m) {
    // we only handle set requests
    if (jpacket_subtype(m->packet) != JPACKET__SET)
	return M_PASS;

    // get the command node
    char const* node = xmlnode_get_attrib_ns(m->packet->iq, "node", NULL);

    // check if it is one of the nodes we implement
    enum our_nodes {
	host,
	unhost
    } given_command;
    if (j_strcmp(node, "host") == 0) {
	given_command = host;
    } else if (j_strcmp(node, "unhost") == 0) {
	given_command = unhost;
    } else {
	// not a command node we implement
	return M_PASS;
    }

    // check access to the features
    if (!acl_check_access(m->si->xc, ADMIN_DYNAMIC, m->packet->from)) {
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_NOTALLOWED);
	return M_HANDLED;
    }

    // get the action type of the command
    char const* action = xmlnode_get_attrib_ns(m->packet->iq, "action", NULL);
    if (!action)
	action = "execute";

    // get the (submitted) form
    xmlnode_vector form = xmlnode_get_tags(m->packet->iq, "data:x", m->si->std_namespace_prefixes);

    // no submitted form? then form is requested
    if (form.empty()) {
	// create basic form
	jutil_iqresult(m->packet->x);
	m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "command", NULL, NS_COMMAND);
	xmlnode_put_attrib_ns(m->packet->iq, "status", NULL, NULL, "executing");
	xmlnode_put_attrib_ns(m->packet->iq, "node", NULL, NULL, node);

	xmlnode form = xmlnode_insert_tag_ns(m->packet->iq, "x", NULL, NS_DATA);
	xmlnode_put_attrib_ns(form, "type", NULL, NULL, "form");

	xmlnode form_title = NULL;
	xmlnode form_instructions = NULL;
	xmlnode form_field = NULL;
	switch (given_command) {
	    case host:
		form_title = xmlnode_insert_tag_ns(form, "title", NULL, NS_DATA);
		xmlnode_insert_cdata(form_title, messages_get(xmlnode_get_lang(m->packet->x), N_("Adding host")), -1);
		form_instructions = xmlnode_insert_tag_ns(form, "instructions", NULL, NS_DATA);
		xmlnode_insert_cdata(form_instructions, messages_get(xmlnode_get_lang(m->packet->x), N_("Please insert the hostname, that should get added.")), -1);
		form_field = xmlnode_insert_tag_ns(form, "field", NULL, NS_DATA);
		xmlnode_put_attrib_ns(form_field, "type", NULL, NULL, "text-single");
		xmlnode_put_attrib_ns(form_field, "label", NULL, NULL, messages_get(xmlnode_get_lang(m->packet->x), N_("Hostname")));
		xmlnode_put_attrib_ns(form_field, "var", NULL, NULL, "host");
		break;
	    case unhost:
		form_title = xmlnode_insert_tag_ns(form, "title", NULL, NS_DATA);
		xmlnode_insert_cdata(form_title, messages_get(xmlnode_get_lang(m->packet->x), N_("Adding host")), -1);
		form_instructions = xmlnode_insert_tag_ns(form, "instructions", NULL, NS_DATA);
		xmlnode_insert_cdata(form_instructions, messages_get(xmlnode_get_lang(m->packet->x), N_("Please insert the hostname, that should get added.")), -1);
		form_field = xmlnode_insert_tag_ns(form, "field", NULL, NS_DATA);
		xmlnode_put_attrib_ns(form_field, "type", NULL, NULL, "text-single");
		xmlnode_put_attrib_ns(form_field, "label", NULL, NULL, messages_get(xmlnode_get_lang(m->packet->x), N_("Hostname")));
		xmlnode_put_attrib_ns(form_field, "var", NULL, NULL, "host");
		break;
	}

	// send the form back
	jpacket_reset(m->packet);
	js_deliver(m->si, m->packet, NULL);
	return M_HANDLED;
    }

    // okay, form has been submitted - get type of form
    char const* type = xmlnode_get_attrib_ns(form[0], "type", NULL);

    // is user submitting the form?
    if (j_strcmp(type, "submit") == 0) {
	// get the hostname to add/remove
	xmlnode_vector hostname_node = xmlnode_get_tags(form[0], "data:field[@var='host']/data:value/text()", m->si->std_namespace_prefixes);
	if (!hostname_node.empty()) {
	    char const* hostname = xmlnode_get_data(hostname_node[0]);

	    if (hostname) {
		// stringprep the hostname
		jid preped_hostname = jid_new(m->packet->p, hostname);

		// okay, we can execute the command
		jutil_iqresult(m->packet->x);
		m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "command", NULL, NS_COMMAND);
		xmlnode_put_attrib_ns(m->packet->iq, "status", NULL, NULL, "completed");
		xmlnode_put_attrib_ns(m->packet->iq, "node", NULL, NULL, node);

		xmlnode note = xmlnode_insert_tag_ns(m->packet->iq, "note", NULL, NS_COMMAND);

		if (!preped_hostname || !preped_hostname->server) {
		    xmlnode_put_attrib_ns(note, "type", NULL, NULL, "error");
		    xmlnode_insert_cdata(note, messages_get(xmlnode_get_lang(m->packet->x), N_("The entered hostname is invalid.")), -1);
		} else if (j_strcmp(preped_hostname->server, m->si->i->id) == 0) {
		    xmlnode_put_attrib_ns(note, "type", NULL, NULL, "error");
		    xmlnode_insert_cdata(note, messages_get(xmlnode_get_lang(m->packet->x), N_("The main hostname of a session manager cannot be modified.")), -1);
		} else {
		    xmlnode_put_attrib_ns(note, "type", NULL, NULL, "info");

		    // execute
		    switch (given_command) {
			case host:
			    xmlnode_insert_cdata(note, messages_get(xmlnode_get_lang(m->packet->x), N_("Hostname has been added.")), -1);
			    log_debug2(ZONE, LOGT_DYNAMIC, "registering hostname %s on server %s", preped_hostname->server, m->si->i->id);
			    register_instance(m->si->i, preped_hostname->server);
			    break;
			case unhost:
			    // XXX kick existing sessions and remove local data about this domain
			    xmlnode_insert_cdata(note, messages_get(xmlnode_get_lang(m->packet->x), N_("Hostname has been removed.")), -1);
			    log_debug2(ZONE, LOGT_DYNAMIC, "unregistering hostname %s on server %s", preped_hostname->server, m->si->i->id);
			    unregister_instance(m->si->i, preped_hostname->server);
			    break;
		    }
		}

		// send back the result
		jpacket_reset(m->packet);
		js_deliver(m->si, m->packet, NULL);
		return M_HANDLED;
	    }
	}

	// submitted form data is invalid
	js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_BAD);
	return M_HANDLED;
    } else if (j_strcmp(type, "cancel") == 0) {
	// confirm cancel
	jutil_iqresult(m->packet->x);
	m->packet->iq = xmlnode_insert_tag_ns(m->packet->x, "command", NULL, NS_COMMAND);
	xmlnode_put_attrib_ns(m->packet->iq, "status", NULL, NULL, "canceled");
	xmlnode_put_attrib_ns(m->packet->iq, "node", NULL, NULL, node);
	jpacket_reset(m->packet);
	js_deliver(m->si, m->packet, NULL);
	return M_HANDLED;
    }

    return M_PASS;
}

/**
 * handle requests to add or remove hosts from the server
 *
 * @param m the ::mapi_struct that contains the request to handle
 * @param arg unused/ignored
 * @return signalling if this method processed the request
 */
static mreturn mod_dynamic_server(mapi m, void *arg) {
    /* sanity check */
    if (m == NULL || m->packet == NULL)
	return M_PASS;

    /* only handle iqs */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;

    if (NSCHECK(m->packet->iq, NS_DISCO_INFO))
	return mod_dynamic_server_disco_info(m);

    if (NSCHECK(m->packet->iq, NS_DISCO_ITEMS))
	return mod_dynamic_server_disco_items(m);

    if (NSCHECK(m->packet->iq, NS_COMMAND))
	return mod_dynamic_server_command(m);

    return M_PASS;
}

/**
 * init the module, register callbacks
 *
 * @param si the session manager instance
 */
extern "C" void mod_dynamic(jsmi si) {
    js_mapi_register(si, e_SERVER, mod_dynamic_server, NULL);
}
