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
 * delete the password if a user is deleted
 *
 * @param m the mapi_struct
 * @param arg unused/ignored
 * @return always M_PASS
 */
mreturn mod_auth_crypt_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_AUTH, NULL); /* to be sure */
    xdb_set(m->si->xc, m->user->id, NS_AUTH_CRYPT, NULL);
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
    js_mapi_register(si, e_DELETE, mod_auth_crypt_delete, NULL);
}
