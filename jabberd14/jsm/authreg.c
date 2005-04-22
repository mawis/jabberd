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
 * @file authreg.c
 * @brief handle authentication or new-user registration requests
 */

/**
 * Handle authentication requests (delegation from inside js_authreg())
 *
 * This function does only prepare the packet p to be sent back, but
 * js_authreg() is responsible for sending the packet back after calling
 * this function.
 *
 * @param p the packet that contains the authentication request
 */
void _js_authreg_auth(jpacket p) {
    jsmi si = (jsmi)(p->aux1);
    udata user;

    log_debug2(ZONE, LOGT_AUTH, "auth request");

    /* attempt to fetch user data based on the username */
    user = js_user(si, p->to, NULL);
    if (user == NULL) {
	jutil_error_xmpp(p->x, XTERROR_AUTH);
    } else {
	/* lock the udata structure, so it does not get freed in the mapi call */
	user->ref++;

	if(!js_mapi_call(si, e_AUTH, p, user, NULL)) {
	    if(jpacket_subtype(p) == JPACKET__GET) {
		/* if it's a type="get" for auth, everybody mods it and we result and return it */
		xmlnode_insert_tag(p->iq,"resource"); /* of course, resource is required :) */
		xmlnode_put_attrib(p->x,"type","result");
		jutil_tofrom(p->x);
	    } else {
		/* type="set" that didn't get handled used to be a problem, but now auth_plain passes on failed checks so it might be normal */
		jutil_error_xmpp(p->x, XTERROR_AUTH);
	    }
	}

	/* release the lock */
	user->ref--;
    }
}

/**
 * Handle registration requests (delegation from inside js_authreg())
 *
 * This function does only prepare the packet p to be sent back, but
 * js_authreg() is responsible for sending the packet back after calling
 * this function.
 *
 * @param p the packet that contains the registration request
 */
void _js_authreg_register(jpacket p) {
    jsmi si = (jsmi)(p->aux1);

    if (jpacket_subtype(p) == JPACKET__GET) {
	/* request for information on requested data */
	
	log_debug2(ZONE, LOGT_AUTH, "registration get request");
	/* let modules try to handle it */
	if(!js_mapi_call(si, e_REGISTER, p, NULL, NULL))
	{
	    jutil_error_xmpp(p->x, XTERROR_NOTIMPL);
	}else{ /* make a reply and the username requirement is built-in :) */
	    xmlnode_put_attrib(p->x,"type","result");
	    jutil_tofrom(p->x);
	    xmlnode_insert_tag(p->iq,"username");
	}
    } else {
	/* actual registration request */

	log_debug2(ZONE, LOGT_AUTH, "registration set request");
	if(p->to->user == NULL || xmlnode_get_tag_data(p->iq,"password") == NULL)
	{
	    jutil_error_xmpp(p->x, XTERROR_NOTACCEPTABLE);
	}else if(js_user(si,p->to,NULL) != NULL){
	    jutil_error_xmpp(p->x, (xterror){409,"Username Not Available","cancel","conflict"});
	}else if(!js_mapi_call(si, e_REGISTER, p, NULL, NULL)){
	    jutil_error_xmpp(p->x, XTERROR_NOTIMPL);
	}
    }
}

/**
 * Handle authentication or new-user registration requests
 *
 * If jsm is not configured to let an external component handle authentication and
 * registration of new users, it will let this function handle these both jobs
 *
 * @param arg the packet containing the authentication or registration request
 */
void js_authreg(void *arg)
{
    jpacket p = (jpacket)arg;
    udata user;
    char *ul;
    jsmi si = (jsmi)(p->aux1);
    xmlnode x;

    /* enforce the username to lowercase */
    if(p->to->user != NULL)
        for(ul = p->to->user;*ul != '\0'; ul++)
            *ul = tolower(*ul);

    if(p->to->user != NULL && (jpacket_subtype(p) == JPACKET__GET || p->to->resource != NULL) && NSCHECK(p->iq,NS_AUTH)) {
	/* is this a valid auth request? */
	_js_authreg_auth(p);
    } else if (NSCHECK(p->iq,NS_REGISTER)) {
	/* is this a registration request? */
	_js_authreg_register(p);
    } else {
	/* unknown namespace or other problem */
        jutil_error_xmpp(p->x, XTERROR_NOTACCEPTABLE);
    }

    /* restore the route packet */
    x = xmlnode_wrap(p->x,"route");
    xmlnode_put_attrib(x,"from",xmlnode_get_attrib(p->x,"from"));
    xmlnode_put_attrib(x,"to",xmlnode_get_attrib(p->x,"to"));
    xmlnode_put_attrib(x,"type",xmlnode_get_attrib(p->x,"route"));
    /* hide our uglies */
    xmlnode_hide_attrib(p->x,"from");
    xmlnode_hide_attrib(p->x,"to");
    xmlnode_hide_attrib(p->x,"route");
    /* reply */
    deliver(dpacket_new(x), si->i);
}

