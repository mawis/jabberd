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
 * service.c - Service API
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

