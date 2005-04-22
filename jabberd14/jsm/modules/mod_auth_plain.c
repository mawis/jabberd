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
 * @file mod_auth_plain.c
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
mreturn mod_auth_plain_jane(mapi m, void *arg)
{
    char *pass;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do plain-text auth */
        xmlnode_insert_tag(m->packet->iq,"password");
        return M_PASS;
    }

    if((pass = xmlnode_get_tag_data(m->packet->iq, "password")) == NULL)
        return M_PASS;

    /* if there is a password avail, always handle */
    if(m->user->pass != NULL)
    {
        if(strcmp(pass, m->user->pass) != 0)
            jutil_error_xmpp(m->packet->x, XTERROR_AUTH);
        else
            jutil_iqresult(m->packet->x);
        return M_HANDLED;
    }

    log_debug2(ZONE, LOGT_AUTH, "trying xdb act check");
    /* if the act "check" fails, PASS so that 0k could use the password to try and auth w/ it's data */
    /* XXX see the comment in xdb_file/xdb_file.c for the check action */
    if(xdb_act(m->si->xc, m->user->id, NS_AUTH, "check", NULL, xmlnode_get_tag(m->packet->iq,"password")))
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
int mod_auth_plain_reset(mapi m, jid id, xmlnode pass)
{
    log_debug2(ZONE, LOGT_AUTH, "resetting password");

    xmlnode_put_attrib(pass,"xmlns",NS_AUTH);
    return xdb_set(m->si->xc, id, NS_AUTH, pass);
}

/**
 * handle saving the password
 *
 * used if the user just registers his account or if the user changed
 * his password
 *
 * get requests are used to check if authentication type is supported
 * set requests are used to set the password
 *
 * @param m the mapi instance containing the query
 * @param arg type of action (password change or register request) for logging
 * @return M_HANDLED if we handled the request (or rejected it), H_PASS else
 */
mreturn mod_auth_plain_reg(mapi m, void *arg)
{
    jid id;
    xmlnode pass;

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do plain-text regs */
        xmlnode_insert_tag(m->packet->iq,"password");
        return M_PASS;
    }

    /* only handle set requests (get requests already have been handled) */
    if(jpacket_subtype(m->packet) != JPACKET__SET) return M_PASS;

    /* do not handle/reject unregister requests */
    if (xmlnode_get_tag(m->packet->iq, "remove") != NULL) {
	return M_PASS;
    }

    /* take care, that there is a new password) */
    if((pass = xmlnode_get_tag(m->packet->iq,"password")) == NULL
	    || xmlnode_get_data(pass) == NULL) {
	jutil_error_xmpp(m->packet->x, (xterror){400, "New password required", "modify", "bad-request"});
	return M_HANDLED;
    }

    /* and take care that the <username/> element contains the right user
     * if it is the request of an existing user */
    if (m->user != NULL) {
	id = jid_new(m->packet->p, jid_full(m->user->id));
	jid_set(id, xmlnode_get_tag_data(m->packet->iq, "username"), JID_USER);
	if (jid_cmpx(m->user->id, id, JID_USER) != 0) {
	    jutil_error_xmpp(m->packet->x, (xterror){400, "Wrong or missing username", "modify", "bad-request"});
	    return M_HANDLED;
	}
    }

    /* get the jid of the user, depending on how we were called */
    if(m->user == NULL)
        id = jid_user(m->packet->to);
    else
        id = m->user->id;

    /* tuck away for a rainy day */
    if(mod_auth_plain_reset(m,id,pass)) {
        jutil_error_xmpp(m->packet->x,(xterror){500,"Password Storage Failed","wait","internal-server-error"});
        return M_HANDLED;
    }
    log_notice(m->si->i->id, "user %s %s", jid_full(id), arg);

    return M_PASS;
}

/**
 * handle password change requests from a session
 *
 * This function handles stanzas sent to the server address, this are
 * password change requests after the user already authenticated - it
 * does not handle normal user registration.
 *
 * @param m the mapi instance, containing the user's request
 * @param arg unused / ignored
 * @return M_IGNORE if it is no iq stanza, M_HANDLED if we handled the password change, M_PASS else
 */
mreturn mod_auth_plain_server(mapi m, void *arg) {
    mreturn ret;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->user == NULL) return M_PASS;
    if(!NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;

    /* just do normal reg process, but deliver afterwards */
    ret = mod_auth_plain_reg(m, "changed password");
    if(ret == M_HANDLED)
        js_deliver(m->si, jpacket_reset(m->packet));

    return ret;
}


/**
 * register this module in the session manager
 *
 * will register the following callbacks in the session manager:
 * - mod_auth_plain_jane as authentication handler
 * - mod_auth_plain_server to process packets sent to the server address
 * - mod_auth_plain_reg to process data of registering users (only if there is
 *   a <register/> element in the session manager configuration)
 *
 * @param si the session manager instance
 */
void mod_auth_plain(jsmi si)
{
    log_debug2(ZONE, LOGT_INIT, "mod_auth_plain is initializing");

    js_mapi_register(si, e_AUTH, mod_auth_plain_jane, NULL);
    js_mapi_register(si, e_SERVER, mod_auth_plain_server, NULL);
    if (js_config(si,"register") != NULL) js_mapi_register(si, e_REGISTER, mod_auth_plain_reg, "registered account");
}
