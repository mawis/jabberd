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

#include <jsm.h>

/**
 * @file mod_auth_digest.c
 * @brief Handle authentication using hashed passwords on the wire (requires plain passwords in storage) and registration. See JEP-0077 and JEP-0078 for the protocol.
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
mreturn mod_auth_digest_yum(mapi m, void *arg) {
    spool s;
    char *sid;
    char *digest;
    char *mydigest;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET) {
	/* type=get means we flag that the server can do digest auth */
        if(m->user->pass != NULL)
            xmlnode_insert_tag(m->packet->iq,"digest");
        return M_PASS;
    }

    if((digest = xmlnode_get_tag_data(m->packet->iq,"digest")) == NULL)
        return M_PASS;

    sid = xmlnode_get_attrib(xmlnode_get_tag(m->packet->iq,"digest"), "sid");

    /* Concat the stream id and password */
    /* SHA it up */
    log_debug2(ZONE, LOGT_AUTH, "Got SID: %s", sid);
    s = spool_new(m->packet->p);
    spooler(s,sid,m->user->pass,s);

    mydigest = shahash(spool_print(s));

    log_debug2(ZONE, LOGT_AUTH, "comparing %s %s",digest,mydigest);

    if(m->user->pass == NULL || sid == NULL || mydigest == NULL)
        jutil_error_xmpp(m->packet->x, XTERROR_NOTIMPL);
    else if(j_strcasecmp(digest, mydigest) != 0)
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
int mod_auth_digest_reset(mapi m, jid id, xmlnode pass)
{
    log_debug2(ZONE, LOGT_AUTH, "resetting password");

    xmlnode_put_attrib(pass,"xmlns",NS_AUTH);
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
mreturn mod_auth_digest_reg(mapi m, void *arg)
{
    jid id;
    xmlnode pass;

    if(jpacket_subtype(m->packet) == JPACKET__GET)
    { /* type=get means we flag that the server can do plain-text regs */
        xmlnode_insert_tag(m->packet->iq,"password");
        return M_PASS;
    }

    /* ignore all but set requests (gets have already been handled) and
     * take care, that there is a new password */
    if(jpacket_subtype(m->packet) != JPACKET__SET
	    || (pass = xmlnode_get_tag(m->packet->iq,"password")) == NULL
	    || xmlnode_get_data(pass) == NULL)
	return M_PASS;

    /* get the jid of the user, depending on how we were called */
    if(m->user == NULL)
        id = jid_user(m->packet->to);
    else
        id = m->user->id;

    /* tuck away for a rainy day */
    if(mod_auth_digest_reset(m,id,pass))
    {
        jutil_error_xmpp(m->packet->x,(xterror){500,"Password Storage Failed","wait","internal-server-error"});
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
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(m->user == NULL) return M_PASS;
    if(!NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;

    /* just do normal reg process, but deliver afterwards */
    ret = mod_auth_digest_reg(m,arg);
    if(ret == M_HANDLED)
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
    if (js_config(si,"register") != NULL) js_mapi_register(si, e_REGISTER, mod_auth_digest_reg, NULL);
}
