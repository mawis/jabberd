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
 * @file mod_useridpolicy.c
 * @brief checks new user registrations against a policy for allowed/forbidden usernames
 *
 * This module allows the administrator to block some user-names from being registered
 * by users.
 */

/**
 * handle new user registration requests
 *
 * Check if the username is allowed to be registered. Generate an error reply if not.
 *
 * @param m the mapi structure
 * @param arg unused/ignored
 * @return M_PASS if registration is not allowed, M_IGNORE if the module is not configured, M_HANDLED else
 */
mreturn mod_useridpolicy_new(mapi m, void *arg) {
    xmlnode config = NULL;	/* xmlnode holding the module configuration */
    xmlnode x=NULL;		/* for iterating */
    char *username = NULL;	/* the username that should be registered */
    jid user_jid = NULL;	/* JID containing the username (to get stringpreped) */
    size_t username_len = 0;	/* length of the username in characters (!) */
    char *ptr = NULL;		/* for iterating */

    log_debug2(ZONE, LOGT_AUTH, "checking registration policy");

    /* in get requests there is no username, so we cannot check it there */
    if (jpacket_subtype(m->packet) != JPACKET__SET)
	return M_PASS;

    /* get the desired username */
    username = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "register:username", m->si->std_namespace_prefixes), 0));

    /* if there is no username, we don't care, mod_register will probably reject it */
    if (username == NULL)
	return M_PASS;

    /* stringprep the username */
    user_jid = jid_new(m->packet->p, "invalid"); /* for 'invalid' as domain see RFC 2606, we just need any domain */
    jid_set(user_jid, username, JID_USER);
    username = user_jid->user;

    /* get configuration, disable the module if not configured */
    if ((config = js_config(m->si, "jsm:mod_useridpolicy", NULL)) == NULL)
	return M_IGNORE;
    
    /* check for forbidden usernames */
    for (x=xmlnode_get_firstchild(config); x!=NULL; x=xmlnode_get_nextsibling(x)) {
	/* ignore direct CDATA childs */
	if (xmlnode_get_type(x) != NTYPE_TAG)
	    continue;

	if (!NSCHECK(x, NS_JABBERD_CONFIG_JSM))
	    continue;

	/* we only care for "forbidden" elements at this point */
	if (j_strcmp(xmlnode_get_localname(x), "forbidden") != 0)
	    continue;

	/* check for a match and possibly reject */
	if (j_strcmp(xmlnode_get_data(x), username) == 0) {
	    log_notice(m->packet->to->server, "blocked account '%s' from being registered: forbidden username", username);
	    jutil_error_xmpp(m->packet->x, XTERROR_NOTACCEPTABLE);
	    xmlnode_free(config);
	    return M_HANDLED;
	}
    }

    /* check the length of the username in characters */
    /* XXX normalize username using nodeprep before */
    for (ptr = username; ptr != NULL && *ptr != '\0'; ptr++) {
	/* no new unicode character, continued UTF-8 character */
	if ((*ptr & 0xC0) == 0x80) {
	    continue;
	}

	/* new character in the UTF-8 string started */
	username_len++;
    }
    log_debug2(ZONE, LOGT_REGISTER, "length of username is %i", username_len);

    /* check for minimum length */
    if (j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:minlen", m->si->std_namespace_prefixes), 0)), 1) > username_len) {
	log_notice(m->packet->to->server, "blocked account '%s' from being registered: username to short", username);
	jutil_error_xmpp(m->packet->x, XTERROR_NOTACCEPTABLE);
	xmlnode_free(config);
	return M_HANDLED;
    }
    
    /* check for maximum length */
    if (j_atoi(xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(config, "jsm:maxlen", m->si->std_namespace_prefixes), 0)), 1023) < username_len) {
	log_notice(m->packet->to->server, "blocked account '%s' from being registered: username to long", username);
	jutil_error_xmpp(m->packet->x, XTERROR_NOTACCEPTABLE);
	xmlnode_free(config);
	return M_HANDLED;
    }

    /* it passed the policy ... let the other modules do their job */
    xmlnode_free(config);
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
void mod_useridpolicy(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "mod_useridpolicy starting up");
    js_mapi_register(si, e_PRE_REGISTER, mod_useridpolicy_new, NULL);
}
