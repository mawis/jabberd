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
 * @file mod_auth_plain.cc
 * @brief handles authentication using plaintext password with plaintext passwords in xdb
 *
 * This module is responsible for handling authentication if the client uses
 * legacy plaintext authentication. It stores and uses plaintext password in xdb.
 * mod_auth_crypt.c is available as a replacement for mod_auth_plain.c, if only hash
 * values of the password should be stored in xdb. But this means that many more advanced
 * authentication methods won't work if you only store hashes.
 *
 * Using plaintext password in xdb also will make it much more easy to convert your
 * server to use SASL in the future.
 */

/**
 * handle authentication requests
 *
 * get requests are used to check which authentication methods are available
 * set requests are the actual authentication requests
 *
 * @param m the mapi structure, containing the authentication request
 * @param arg unused / ignored
 * @return M_PASS if the next module should be called to handle the request, M_HANDLED if the request has been completely handled
 */
static mreturn mod_auth_plain_jane(mapi m, void *arg) {
    char *pass = NULL;
    xmlnode xmlpass = NULL;
    const char *stored_pass = NULL;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    if (jpacket_subtype(m->packet) == JPACKET__GET) {
	/* type=get means we flag that the server can do plain-text auth */
        xmlnode_insert_tag_ns(m->packet->iq, "password", NULL, NS_AUTH);
        return M_PASS;
    }

    if ((pass = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes), 0))) == NULL)
        return M_PASS;

    xmlpass = xdb_get(m->si->xc, m->user->id, NS_AUTH);
    stored_pass = xmlnode_get_data(xmlpass);

    /* if there is a password avail, always handle */
    if (stored_pass != NULL) {
        if (strcmp(pass, stored_pass) != 0)
            jutil_error_xmpp(m->packet->x, XTERROR_AUTH);
        else
            jutil_iqresult(m->packet->x);
	xmlnode_free(xmlpass);
        return M_HANDLED;
    }
    xmlnode_free(xmlpass);

    log_debug2(ZONE, LOGT_AUTH, "trying xdb act check");
    /* if the act "check" fails, PASS so that 0k could use the password to try and auth w/ it's data */
    /* XXX see the comment in xdb_file/xdb_file.c for the check action */
    if (xdb_act_path(m->si->xc, m->user->id, NS_AUTH, "check", NULL, NULL, xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes), 0)))
        return M_PASS;

    jutil_iqresult(m->packet->x);
    return M_HANDLED;
}

/**
 * save the new password of a user in xdb
 *
 * @param m the mapi instance
 * @param id for which user to set the password
 * @param pass the new password (wrapped in a password element of the right namespace)
 * @return 0 if setting the password succeded, it failed otherwise
 */
static int mod_auth_plain_reset(mapi m, jid id, xmlnode pass) {
    int result = 0;
    xmlnode auth_pass = NULL;

    log_debug2(ZONE, LOGT_AUTH, "resetting password");
    return xdb_set(m->si->xc, id, NS_AUTH, pass);
}

/**
 * handle request for required registration data
 *
 * used if the user just registers his account
 *
 * requests are used to check if authentication type is supported
 *
 * @param m the mapi instance containing the query
 * @param arg type of action (password change or register request) for logging
 * @return always M_PASS
 */
static mreturn mod_auth_plain_reg(mapi m, void *arg) {
    if (jpacket_subtype(m->packet) == JPACKET__GET) {
	/* type=get means we tell what we need */
	if (xmlnode_get_tags(m->packet->iq, "register:password", m->si->std_namespace_prefixes) == NULL)
	    xmlnode_insert_tag_ns(m->packet->iq, "password", NULL, NS_REGISTER);
    }
    return M_PASS;
}

/**
 * handle saving the password
 *
 * used if the user just registers his account or if the user changed
 * his password
 *
 * @param m the mapi instance containing the query
 * @param arg unused/ignored
 * @return M_HANDLED if we rejected the request, H_PASS else
 */
static mreturn mod_auth_plain_pwchange(mapi m, void *arg) {
    jid id;
    xmlnode pass;

    /* get the jid of the user */
    id = jid_user(m->packet->to);

    /* get the new password */
    pass = xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes), 0);

    /* tuck away for a rainy day */
    if (mod_auth_plain_reset(m, id, pass)) {
        js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_STORAGE_FAILED);
        return M_HANDLED;
    }

    return M_PASS;
}

/**
 * if a user is deleted, delete his authentication data
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
static mreturn mod_auth_plain_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_AUTH, NULL);
    xdb_set(m->si->xc, m->user->id, NS_AUTH_CRYPT, NULL); /* to be sure */
    return M_PASS;
}

/**
 * register this module in the session manager
 *
 * will register the following callbacks in the session manager:
 * - mod_auth_plain_jane as authentication handler
 * - mod_auth_plain_server to process packets sent to the server address
 * - mod_auth_plain_reg to process request for required files in a registration
 *   request (only if there is a &lt;register/&gt; element in the session manager
 *   configuration)
 * - mod_auth_plain_pwchange to process changed passwords
 *
 * @param si the session manager instance
 */
extern "C" void mod_auth_plain(jsmi si) {
    xmlnode register_config = js_config(si, "register:register", NULL);

    log_debug2(ZONE, LOGT_INIT, "mod_auth_plain is initializing");

    js_mapi_register(si, e_AUTH, mod_auth_plain_jane, NULL);
    js_mapi_register(si, e_PASSWORDCHANGE, mod_auth_plain_pwchange, NULL);
    if (register_config != NULL) {
	js_mapi_register(si, e_REGISTER, mod_auth_plain_reg, NULL);
    }
    js_mapi_register(si, e_DELETE, mod_auth_plain_delete, NULL);
    xmlnode_free(register_config);
}
