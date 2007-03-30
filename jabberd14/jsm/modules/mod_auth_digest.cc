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

#include <jsm.h>

/**
 * @file mod_auth_digest.cc
 * @brief Handle authentication using hashed passwords on the wire (requires plain passwords in storage) and registration. See XEP-0077 and XEP-0078 for the protocol.
 */

/**
 * handle authentication requests
 *
 * For get request we just flag support for digest authentication.
 * For set requests we handle it if it is a digest auth request.
 *
 * @param m the mapi_struct containing the authentication request
 * @param arg unused/ignored
 * @return M_HANDLED if the request was handled using digest authentication, M_PASS else
 */
static mreturn mod_auth_digest_yum(mapi m, void *arg) {
    spool s;
    char *sid;
    char *digest;
    char *mydigest;
    const char *pass = NULL;
    xmlnode xmlpass = NULL;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    if (jpacket_subtype(m->packet) == JPACKET__GET) {
	xmlpass = xdb_get(m->si->xc, m->user->id, NS_AUTH);

	/* type=get means we flag that the server can do digest auth */
	if (xmlnode_get_data(xmlpass) != NULL)
            xmlnode_insert_tag_ns(m->packet->iq, "digest", NULL, NS_AUTH);

	xmlnode_free(xmlpass);
        return M_PASS;
    }

    if ((digest = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:digest", m->si->std_namespace_prefixes), 0))) == NULL)
        return M_PASS;

    sid = xmlnode_get_attrib_ns(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:digest", m->si->std_namespace_prefixes), 0), "sid", NULL);

    xmlpass = xdb_get(m->si->xc, m->user->id, NS_AUTH);
    pass = xmlnode_get_data(xmlpass);

    /* Concat the stream id and password */
    /* SHA it up */
    log_debug2(ZONE, LOGT_AUTH, "Got SID: %s", sid);
    s = spool_new(m->packet->p);
    spooler(s,sid,pass,s);

    mydigest = shahash(spool_print(s));

    log_debug2(ZONE, LOGT_AUTH, "comparing %s %s",digest,mydigest);

    if (pass == NULL || sid == NULL || mydigest == NULL)
        jutil_error_xmpp(m->packet->x, XTERROR_NOTIMPL);
    else if (j_strcasecmp(digest, mydigest) != 0)
        jutil_error_xmpp(m->packet->x, XTERROR_AUTH);
    else
        jutil_iqresult(m->packet->x);

    xmlnode_free(xmlpass);
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
static int mod_auth_digest_reset(mapi m, jid id, xmlnode pass) {
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
static mreturn mod_auth_digest_reg(mapi m, void *arg) {
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
static mreturn mod_auth_digest_pwchange(mapi m, void *arg) {
    jid id;
    xmlnode pass;

    /* get the jid of the user */
    id = jid_user(m->packet->to);

    /* get the new password */
    pass = xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes), 0);

    /* tuck away for a rainy day */
    if (mod_auth_digest_reset(m, id, pass)) {
        js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_STORAGE_FAILED);
        return M_HANDLED;
    }

    return M_PASS;
}

/**
 * init the module, register callbacks
 *
 * registers the mod_auth_digest_yum callback to handle authentication,
 * registers the mod_auth_digest_server callback to handle password changes,
 * if we should support inband registration, we also register mod_auth_digest_reg.
 *
 * @param si the jsmi_struct containing instance internal data for the Jabber session manager
 */
extern "C" void mod_auth_digest(jsmi si) {
    xmlnode register_config = js_config(si, "register:register", NULL);

    log_debug2(ZONE, LOGT_INIT, "init");
    js_mapi_register(si,e_AUTH, mod_auth_digest_yum, NULL);
    js_mapi_register(si,e_PASSWORDCHANGE, mod_auth_digest_pwchange, NULL);
    if (register_config != NULL)
	js_mapi_register(si, e_REGISTER, mod_auth_digest_reg, NULL);
    xmlnode_free(register_config);
}
