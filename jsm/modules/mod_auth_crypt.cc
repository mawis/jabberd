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
 * @file mod_auth_crypt.cc
 * @brief handle (non-SASL) authentication using plain text passwords on the wire but hashes in storage
 *
 * This is an alternative implementation for plain text password on the wire (the other is mod_auth_crypt.c).
 * The advantage of this module is that there are no plaintext passwords in the xdb storage, the advantage
 * of mod_auth_crypt.c and using plain text passwords in the storage is, that other authentication
 * schemes using hashes on the wire can be used.
 *
 * In general using mod_auth_crypt.c should be prefered. You will get into problems upgrading to harder
 * authentication mechanisms if you use mod_auth_crypt.c.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif

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
static int mod_auth_crypt_sha1(char *password, char *buf, size_t buflen) {
    unsigned char hash[20];

    /* our result is 34 characters long and we need a terminating '\0' */
    if (buflen < 35)
	return 0;

    /* the pointers have to be valid */
    if (password == NULL || buf == NULL)
	return 0;

    /* calculate the hash */
    shaBlock((unsigned char *)password, j_strlen(password), hash);

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
static mreturn mod_auth_crypt_jane(mapi m, void *arg) {
    char *passA, *passB;
    char salt[3];
    char shahash[35];
    xmlnode xdb;

    log_debug2(ZONE, LOGT_AUTH, "checking");

    if(jpacket_subtype(m->packet) == JPACKET__GET) {
	/* type=get means we flag that the server can do plain-text auth */
        xmlnode_insert_tag_ns(m->packet->iq, "password", NULL, NS_AUTH);
        return M_PASS;
    }

    if((passA = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes), 0))) == NULL)
        return M_PASS;

    /* make sure we can get the auth packet and that it contains a password */
    xdb = xdb_get(m->si->xc, m->user->id, NS_AUTH_CRYPT);
    if (xdb == NULL || (passB = xmlnode_get_data(xdb)) == NULL) {
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
    int i = 0;
    
    if (!result[0])
	srand(time(NULL));
    
    for (i = 0; i < 2; i++) {
        result[i] = (char)(rand() % 64) + '.';
        if (result[i] <= '9')
	    continue;
        result[i] += 'A' - '9' - 1;
        if (result[i] <= 'Z')
	    continue;
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
static int mod_auth_crypt_reset(mapi m, jid id, xmlnode pass) {
    char shahash[35];
    char* password;
    xmlnode newpass;
    char* hashalgo;
    int usedhashalgo;
    xmlnode mod_auth_crypt_config = js_config(m->si, "jsm:mod_auth_crypt", NULL);

    log_debug2(ZONE, LOGT_AUTH, "resetting password");

    hashalgo = xmlnode_get_data(xmlnode_get_list_item(xmlnode_get_tags(mod_auth_crypt_config, "jsm:hash", m->si->std_namespace_prefixes), 0));
    if (j_strcasecmp(hashalgo, "SHA1") == 0) {
	usedhashalgo = HASH_SHA1;
    } else {
	usedhashalgo = HASH_CRYPT;
    }
    xmlnode_free(mod_auth_crypt_config);
    mod_auth_crypt_config = NULL;
    hashalgo = NULL;

    password = xmlnode_get_data(pass);
    if (password == NULL)
	return 1;
    newpass = xmlnode_new_tag_ns("crypt", NULL, NS_AUTH_CRYPT);

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
    
    return xdb_set(m->si->xc, jid_user(id), NS_AUTH_CRYPT, newpass);
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
static mreturn mod_auth_crypt_reg(mapi m, void *arg) {
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
static mreturn mod_auth_crypt_pwchange(mapi m, void *arg) {
    jid id;
    xmlnode pass;

    /* get the jid of the user */
    id = jid_user(m->packet->to);

    /* get the new password */
    pass = xmlnode_get_list_item(xmlnode_get_tags(m->packet->iq, "auth:password", m->si->std_namespace_prefixes), 0);

    /* tuck away for a rainy day */
    if (mod_auth_crypt_reset(m, id, pass)) {
        js_bounce_xmpp(m->si, m->s, m->packet->x, XTERROR_STORAGE_FAILED);
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
static mreturn mod_auth_crypt_delete(mapi m, void *arg) {
    xdb_set(m->si->xc, m->user->id, NS_AUTH, NULL); /* to be sure */
    xdb_set(m->si->xc, m->user->id, NS_AUTH_CRYPT, NULL);
    return M_PASS;
}

/**
 * init the mod_auth_crypt module, register the callbacks with the Jabber session manager
 *
 * @param si the jsmi_struct containing session manager instance-internal data
 */
extern "C" void mod_auth_crypt(jsmi si) {
    log_debug2(ZONE, LOGT_INIT, "init");
    log_warn(NULL, "You configured your server to use the mod_auth_crypt module. This module might cause problems if you want to upgrade to SASL authentication.");
    xmlnode register_config = js_config(si, "register:register", NULL);

    js_mapi_register(si, e_AUTH, mod_auth_crypt_jane, NULL);
    js_mapi_register(si, e_PASSWORDCHANGE, mod_auth_crypt_pwchange, NULL);
    if (register_config != NULL)
	js_mapi_register(si, e_REGISTER, mod_auth_crypt_reg, NULL);
    js_mapi_register(si, e_DELETE, mod_auth_crypt_delete, NULL);
    xmlnode_free(register_config);
}
