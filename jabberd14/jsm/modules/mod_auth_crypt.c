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
 * @file mod_auth_crypt.c
 * @brief handle (non-SASL) authentication using plain text passwords on the wire but hashes in storage
 *
 * This is an alternative implementation for plain text password on the wire (the other is mod_auth_plain.c).
 * The advantage of this module is that there are no plaintext passwords in the xdb storage, the advantage
 * of mod_auth_plain.c and using plain text passwords in the storage is, that other authentication
 * schemes using hashes on the wire can be used.
 *
 * In general using mod_auth_plain.c should be prefered. You will get into problems upgrading to harder
 * authentication mechanisms if you use mod_auth_crypt.c.
 */

#define _XOPEN_SOURCE
#include <unistd.h>

#ifdef INCLUDE_CRYPT_H
#  include <crypt.h>
#endif

#define HASH_CRYPT 1
#define HASH_SHA1  2

/**
 * this function hashes the given password with the SHA1 and formats the
 * result to be usable for password storage
 *
 * @param password the password
 * @param buf buffer where the result can be stored
 * @param buflen length of the buffer (must be at least 35 bytes)
 * @return 1 on success, 0 otherwise
 */
int mod_auth_crypt_sha1(char *password, char *buf, size_t buflen) {
    unsigned char hash[20];

    /* our result is 34 characters long and we need a terminating '\0' */
    if (buflen < 35)
	return 0;

    /* the pointers have to be valid */
    if (password == NULL || buf == NULL)
	return 0;

    /* calculate the hash */
    shaBlock(password, j_strlen(password), hash);

    /* write the result */
    strcpy(buf, "{SHA}");
    return base64_encode(hash, sizeof(hash), buf+5, buflen-5);
}

/**
 * handle authentication requests
 *
 * get requests are used to check which authentication methods are available,
 * set requests are the actual authentication requests
 *
 * @param m the mapi_struct containing the request
 * @param arg unused/ignored
 * @return M_HANDLED if the request has been completely handled, M_PASS else (other modules get the chance to handle it)
 */
mreturn mod_auth_crypt_jane(mapi m, void *arg) {
    char *passA, *passB;
    char salt[3];
    char shahash[35];
    xmlnode xdb;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET) {
	/* type=get means we flag that the server can do plain-text auth */
        xmlnode_insert_tag(m->packet->iq,"password");
        return M_PASS;
    }

    if((passA = xmlnode_get_tag_data(m->packet->iq, "password")) == NULL)
        return M_PASS;

    /* make sure we can get the auth packet and that it contains a password */
    xdb = xdb_get(m->si->xc, m->user->id, NS_AUTH_CRYPT);
    if(xdb == NULL || (passB = xmlnode_get_data(xdb)) == NULL) {
        xmlnode_free(xdb);
        return M_PASS;
    }

    /* check which hashing algoithm has been used */
    if (j_strncmp(passB, "{SHA}", 5) == 0) {
	/* it is SHA-1 */
	mod_auth_crypt_sha1(passA, shahash, sizeof(shahash));
	passA = shahash;
	log_debug2(ZONE, LOGT_AUTH, "comparing %s %s",shahash,passB);
    } else {
	/* it is traditional crypt() */
	strncpy(salt, passB, 2);
	salt[2] = '\0';
	passA = crypt(passA, salt);
	log_debug2(ZONE, LOGT_AUTH, "comparing %s %s",passA,passB);
    }

    if(strcmp(passA, passB) != 0)
	jutil_error_xmpp(m->packet->x, XTERROR_AUTH);
    else
	jutil_iqresult(m->packet->x);

    xmlnode_free(xdb); /* free xdb results */

    return M_HANDLED;
}

/**
 * get a random salt
 *
 * @note this is not thread safe. Calls overwrite the result of previous calls.
 *
 * @return pointer to a two character string containing the new salt
 */
static char* mod_auth_crypt_get_salt() {
    static char result[3] = { '\0', '\0', '\0'};
    int i;
    if (!result[0]) srand(time(NULL));
    i = 0;
    for (i = 0; i < 2; i++)
    {
        result[i] = (char)(rand() % 64) + '.';
        if (result[i] <= '9') continue;
        result[i] += 'A' - '9' - 1;
        if (result[i] <= 'Z') continue;
        result[i] += 'a' - 'Z' - 1;
    }
    return result;
}

/**
 * store a new password (hash of it) in the xdb storage
 *
 * @param m the mapi_struct containing the request, that is related to the password update
 * @param id for which user the password should be updated
 * @param pass the new password for the user
 * @return 0 on success, 1 if updated failed
 */
int mod_auth_crypt_reset(mapi m, jid id, xmlnode pass) {
    char shahash[35];
    char* password;
    xmlnode newpass;
    char* hashalgo;
    int usedhashalgo;

    log_debug2(ZONE, LOGT_AUTH, "resetting password");

    hashalgo = xmlnode_get_tag_data(js_config(m->si, "mod_auth_crypt"), "hash");
    if (j_strcasecmp(hashalgo, "SHA1") == 0) {
	usedhashalgo = HASH_SHA1;
    } else {
	usedhashalgo = HASH_CRYPT;
    }

    password = xmlnode_get_data(pass);
    if(password == NULL) return 1;
    newpass = xmlnode_new_tag("crypt");

    switch (usedhashalgo) {
	case HASH_SHA1:
	    mod_auth_crypt_sha1(password, shahash, sizeof(shahash));
	    log_debug2(ZONE, LOGT_AUTH, "SHA1 hash is %s", shahash);
	    if (xmlnode_insert_cdata(newpass, shahash, -1) == NULL)
		return -1;
	    break;
	default:
	    if (xmlnode_insert_cdata(newpass, crypt(password, mod_auth_crypt_get_salt()), -1) == NULL)
		return -1;
    }
    
    xmlnode_put_attrib(newpass,"xmlns",NS_AUTH_CRYPT);
    return xdb_set(m->si->xc, jid_user(id), NS_AUTH_CRYPT, newpass);
}

/**
 * handle saving the password for registration
 *
 * used if the user just registered his account or is changing his password
 *
 * @param m the mapi_struct containing the related request
 * @param arg unused/ignored
 * @return M_HANDLED if update failed, M_PASS else
 */
mreturn mod_auth_crypt_reg(mapi m, void *arg) {
    if(jpacket_subtype(m->packet) != JPACKET__SET) return M_PASS;

    if(mod_auth_crypt_reset(m,m->packet->to,xmlnode_get_tag(m->packet->iq,"password"))) {
        jutil_error_xmpp(m->packet->x,(xterror){500,"Password Storage Failed","wait","internal-server-error"});
        return M_HANDLED;
    }

    return M_PASS;
}

/**
 * handle password change requests from a session
 *
 * This function handles stanzas sent to the server address, this are password updated for existing accounts
 *
 * @param m the mapi_struct containing the ralted request
 * @param arg unused/ignored
 * @return M_HANDLED if update failed, M_PASS else
 */
mreturn mod_auth_crypt_server(mapi m, void *arg) {
    xmlnode pass;

    /* pre-requisites */
    if(m->packet->type != JPACKET_IQ) return M_IGNORE;
    if(jpacket_subtype(m->packet) != JPACKET__SET || !NSCHECK(m->packet->iq,NS_REGISTER)) return M_PASS;
    if(m->user == NULL) return M_PASS;
    if((pass = xmlnode_get_tag(m->packet->iq,"password")) == NULL) return M_PASS;

    if(mod_auth_crypt_reset(m,m->user->id,pass)) {
        js_bounce_xmpp(m->si,m->packet->x,(xterror){500,"Password Storage Failed","wait","internal-server-error"});
        return M_HANDLED;
    }
    return M_PASS;
}

/**
 * init the mod_auth_crypt module, register the callbacks with the Jabber session manager
 *
 * @param si the jsmi_struct containing session manager instance-internal data
 */
void mod_auth_crypt(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "init");

    js_mapi_register(si, e_AUTH, mod_auth_crypt_jane, NULL);
    js_mapi_register(si, e_SERVER, mod_auth_crypt_server, NULL);
    if (js_config(si,"register") != NULL) js_mapi_register(si, e_REGISTER, mod_auth_crypt_reg, NULL);
}
