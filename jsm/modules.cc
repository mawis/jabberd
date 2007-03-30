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
 * @file modules.cc
 * @brief jsm module API
 */

/**
 * let a module register a new callback for a specified phase
 *
 * Takes a function pointer and argument and stores them in the
 * callback list for the event e
 *
 * @param si the session manager instance data
 * @param e the event type for which to register the callback
 * @param c pointer to the function, that gets registered
 * @param arg an argument to pass to c when it is called
 */
void js_mapi_register(jsmi si, event e, mcall c, void *arg) {
    mlist newl, curl;

    if(c == NULL || si == NULL || e >= e_LAST) return;

    /* create a new mlist record for the call back */
    newl = static_cast<mlist>(pmalloco(si->p, sizeof(_mlist)));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* append */
    if (si->events[e] == NULL) {
        si->events[e] = newl;
    } else {
	/* spin to end of list */
        for (curl = si->events[e]; curl->next != NULL; curl = curl->next)
	    /* do nothing special */;
        curl->next = newl;
    }
    log_debug2(ZONE, LOGT_INIT, "mapi_register %d %X",e,newl);
}

/**
 * let a module register a new callback for a specified phase on a session
 *
 * This is like js_mapi_register except that the call only applies to the specified session.
 *
 * @param e the event type for which to register the callback
 * @param s the session for which the callback should be registered
 * @param c pointer to the function, that gets registered
 * @param arg an argument to pass to c when it is called
 */
void js_mapi_session(event e, session s, mcall c, void *arg) {
    mlist newl, curl;

    if (c == NULL || s == NULL || e >= es_LAST)
	return;

    /* create item for the call list */
    newl = static_cast<mlist>(pmalloco(s->p, sizeof(_mlist)));
    newl->c = c;
    newl->arg = arg;
    newl->mask = 0x00;
    newl->next = NULL;

    /* append */
    if (s->events[e] == NULL) {
        s->events[e] = newl;
    } else {
        for (curl = s->events[e]; curl->next != NULL; curl = curl->next)
	    ; /* spin to end of list */
        curl->next = newl;
    }

    log_debug2(ZONE, LOGT_INIT, "mapi_register_session %d %X",e,newl);
}

/**
 * create an additiona_result element in the mapi structure
 *
 * checks if there is already an additional result in the mapi structure, if not, it generates an iq result for the current query in the
 * packet inside the mapi strucutre (needs to by an iq query of type get or set).
 *
 * If name, prefix, and ns_iri is not NULL, an element in inserted in the iq result having this data.
 *
 * @param m the mapi structure
 * @param name the local name of the element contained in the iq result
 * @param prefix the prefix of the element contained in the iq result
 * @param ns_iri the namespace iri of the element contained in the iq result
 */
void js_mapi_create_additional_iq_result(mapi m, const char* name, const char *prefix, const char *ns_iri) {
    /* do nothing, if the result already exists */
    if (m->additional_result != NULL)
	return;

    /* only generate for iq requests */
    if (m->packet->type != JPACKET_IQ || jpacket_subtype(m->packet) != JPACKET__GET && jpacket_subtype(m->packet) != JPACKET__SET)
	return;

    /* create the new packet */
    m->additional_result = jpacket_new(jutil_iqresult(xmlnode_dup(m->packet->x)));

    /* insert element in the result? */
    if (name != NULL) {
	m->additional_result->iq = xmlnode_insert_tag_ns(m->additional_result->x, name, prefix, ns_iri);
    }
}

/**
 * check if the modules generated an additional result
 *
 * To let several modules generate a common result, mapi has been enhanced with the additional_result
 * element. Modules can create a result there, which jsm will return after having called all modules.
 * This function checks if such a result has been created by the modules, and sends the result.
 *
 * @note Other than modules, that have to free the packet, that they processed, if the return, that
 * they handle the packet (usually this is just done by sending the packet back as a result). This
 * function will never free the packet inside the mapi structure!
 *
 * @param m the mapi structure, that has been used for the module calles
 * @return 1 if a result has been sent, 0 else
 */
static int _js_mapi_process_additional_result(mapi m) {
    /* is there an additional result to send back? */
    if (m->additional_result == NULL)
	return 0;

    /* yes: create packet and send */
    jpacket_reset(m->additional_result);
    js_deliver(m->si, m->additional_result, m->s);
    return 1;
}

/**
 * call all the module callbacks for a phase
 *
 * Addes callbacks to the ignore mask for a given packet type if they return M_IGNORE.
 *
 * @param si the session manager instance data (MUST be NULL for a es_* event)
 * @param e call the modules for which event type
 * @param packet the packet being processed, may be NULL
 * @param user the user data for the current session (or the sender for e_SERVER if it is local), may be NULL
 * @param s the session for which to call the event, may be NULL
 * @return 1 if the call was handled by a module, 0 if it wasn't handled
 */
int js_mapi_call(jsmi si, event e, jpacket packet, udata user, session s) {
    return js_mapi_call2(si, e, packet, user, s, NULL);
}

/**
 * call all the module callbacks for a phase
 *
 * Only needed for the events es_SERIALIZE and es_DESERIALIZE. Other events can use the shorter interface of js_mapi_call()
 *
 * Addes callbacks to the ignore mask for a given packet type if they return M_IGNORE.
 *
 * @param si the session manager instance data (MUST be NULL for a es_* event)
 * @param e call the modules for which event type
 * @param packet the packet being processed, may be NULL
 * @param user the user data for the current session (or the sender for e_SERVER if it is local), may be NULL
 * @param s the session for which to call the event, may be NULL
 * @param serialization_node the xmlnode to pass for es_SERIALIZE, and es_DESERIALIZE event
 * @return 1 if the call was handled by a module, 0 if it wasn't handled
 */
int js_mapi_call2(jsmi si, event e, jpacket packet, udata user, session s, xmlnode serialization_node) {
    mlist l;
    _mapi m;		/* mapi structure to be passed to the call back */

    log_debug2(ZONE, LOGT_EXECFLOW, "mapi_call %d",e);

    /* this is a session event */
    if(si == NULL && s != NULL) {
        si = s->si;
        l = s->events[e];
    } else {
        l = si->events[e];
    }

    /* fill in the mapi structure */
    m.si = si;
    m.e = e;
    m.packet = packet;
    m.user = user;
    m.s = s;
    m.serialization_node = serialization_node;
    m.additional_result = NULL;

    /* traverse the list of call backs */
    for (;l != NULL; l = l->next) {
        /* skip call-back if the packet type mask matches */
        if(packet != NULL && (packet->type & l->mask) == packet->type)
	    continue;
	log_debug2(ZONE, LOGT_EXECFLOW, "MAPI %X",l);
	
        /* call the function and handle the result */
        switch((*(l->c))(&m, l->arg)) {
	    /* this module is ignoring this packet->type */
	    case M_IGNORE:
		/* add the packet type to the mask */
		l->mask |= packet->type;
		break;
	    /* this module handled the packet */
	    case M_HANDLED:
		_js_mapi_process_additional_result(&m);
		return 1;
	    default:
		;
        }
    }

    log_debug2(ZONE, LOGT_EXECFLOW, "mapi_call returning unhandled");

    /* did the modules generate a co-generated result? */
    if (_js_mapi_process_additional_result(&m)) {
	xmlnode_free(m.packet->x);
	return 1;
    }

    /* if we got here, no module handled the packet */
    return 0;
}
