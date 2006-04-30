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
#include <jsm.h>

/**
 * @file mod_auth_digest.c
 * @brief Handle authentication using hashed passwords on the wire (requires plain passwords in storage) and registration. See JEP-0077 and JEP-0078 for the protocol.
 */

/**
 * get the password of a user from xdb
 *
 * @param m the mapi_struct containing the request that is handled
 * @param id which user's password should be retrieved
 * @return NULL on failure, password else
 */
const char *mod_auth_digest_get_pass(mapi m, jid id) {
    if (m == NULL || id == NULL)
	return NULL;
    
    return xmlnode_get_data(xdb_get(m->si->xc, id, NS_AUTH));
}

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
mreturn mod_auth_digest_yum(mapi m, void *arg) {
    spool s;
    char *sid;
    char *digest;
    char *mydigest;
    const char *pass = NULL;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    if (jpacket_subtype(m->packet) == JPACKET__GET) {
	/* type=get means we flag that the server can do digest auth */
        if (mod_auth_digest_get_pass(m, m->user->id) != NULL)
            xmlnode_insert_tag_ns(m->packet->iq, "digest", NULL, NS_AUTH);
        return M_PASS;
    }

    if ((digest = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:digest", m->si->std_namespace_prefixes), 0))) == NULL)
        return M_PASS;

    sid = xmlnode_get_attrib_ns(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:digest", m->si->std_namespace_prefixes), 0), "sid", NULL);

    pass = mod_auth_digest_get_pass(m, m->user->id);

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

    return M_HANDLED;
}

/**
 * store a new password in xdb
 *
 * @param m the mapi_struct containing the request used to update the password
 * @param id which user's password should be updated
 * @param pass the new password
 * @return 0 on success, other value indicates failure
 */
int mod_auth_digest_reset(mapi m, jid id, xmlnode pass) {
    log_debug2(ZONE, LOGT_AUTH, "resetting password");

    return xdb_set(m->si->xc, id, NS_AUTH, pass);
}

/**
 * handle saving the password for registration
 *
 * used as callback function as well as from inside mod_auth_digest_server()
 *
 * @param m the mapi_struct containing the request
 * @param arg ununsed/ignored
 * @return M_HANDLED if password storrage failed, M_PASS in all other cases (other modules might want to update their password as well)
 */
mreturn mod_auth_digest_reg(mapi m, void *arg) {
    jid id;
    xmlnode pass;

    if(jpacket_subtype(m->packet) == JPACKET__GET) {
	/* type=get means we flag that the server can do plain-text regs */
        xmlnode_insert_tag_ns(m->packet->iq, "password", NULL, NS_AUTH);
        return M_PASS;
    }

    /* ignore all but set requests (gets have already been handled) and
     * take care, that there is a new password */
    if (jpacket_subtype(m->packet) != JPACKET__SET
	    || (pass = xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes) ,0)) == NULL
	    || xmlnode_get_data(pass) == NULL)
	return M_PASS;

    /* get the jid of the user, depending on how we were called */
    if (m->user == NULL)
        id = jid_user(m->packet->to);
    else
        id = m->user->id;

    /* tuck away for a rainy day */
    if (mod_auth_digest_reset(m,id,pass)) {
        jutil_error_xmpp(m->packet->x, XTERROR_STORAGE_FAILED);
        return M_HANDLED;
    }

    return M_PASS;
}

/**
 * handle password change requests from a user, that is online
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_IGNORE if not an iq stanza, M_HANDLED if password storage failed, M_PASS else (other modules might want to update their passwords as well)
 */
mreturn mod_auth_digest_server(mapi m, void *arg) {
    mreturn ret;

    /* pre-requisites */
    if (m->packet->type != JPACKET_IQ)
	return M_IGNORE;
    if (m->user == NULL)
	return M_PASS;
    if (!NSCHECK(m->packet->iq, NS_REGISTER))
	return M_PASS;

    /* just do normal reg process, but deliver afterwards */
    ret = mod_auth_digest_reg(m,arg);
    if (ret == M_HANDLED)
        js_deliver(m->si, jpacket_reset(m->packet));

    return ret;
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
void mod_auth_digest(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "init");
    js_mapi_register(si,e_AUTH, mod_auth_digest_yum, NULL);
    js_mapi_register(si,e_SERVER, mod_auth_digest_server, NULL);
    if (js_config(si,"register:register") != NULL)
	js_mapi_register(si, e_REGISTER, mod_auth_digest_reg, NULL);
}
