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
#include "jsm.h"

/**
 * structure holding statistics data
 */
typedef struct mod_stat_data_st {
    jsmi si;

    int messages_delivered;
    int presences_delivered;
    int iqs_delivered;
    int subscriptions_delivered;
} *mod_stat_data_t;

/**
 * write statistical information to the log
 *
 */
result mod_stat_write(void *arg) {
    mod_stat_data_t stat = (mod_stat_data_t)arg;

    if (stat == NULL)
	return r_UNREG;

    log_generic("stat", stat->si->i->id, "delivered", "messages", "%i", stat->messages_delivered);
    log_generic("stat", stat->si->i->id, "delivered", "presences", "%i", stat->presences_delivered);
    log_generic("stat", stat->si->i->id, "delivered", "iqs", "%i", stat->iqs_delivered);
    log_generic("stat", stat->si->i->id, "delivered", "subscriptions", "%i", stat->subscriptions_delivered);

    return r_DONE;
}

/**
 * event for packets that will be delivered
 *
 * @param m pointer to the module api releated data
 * @param arg pointer to the statistics data instance
 * @return if a packet has been handled, ignored, ...
 */
mreturn mod_stat_deliver(mapi m, void *arg) {
    mod_stat_data_t stat = (mod_stat_data_t)arg;

    if (stat == NULL)
	return M_PASS;

    switch (m->packet->type) {
	case JPACKET_MESSAGE:
	    stat->messages_delivered++;
	    break;
	case JPACKET_PRESENCE:
	    stat->presences_delivered++;
	    break;
	case JPACKET_IQ:
	    stat->iqs_delivered++;
	    break;
	case JPACKET_S10N:
	    stat->subscriptions_delivered++;
	    break;
    }

    return M_PASS;
}

/**
 * the main startup/initialization function of mod_stat
 * registering the callbacks in the session manager
 *
 * @param si the session manager instance
 */
void mod_stat(jsmi si) {
    mod_stat_data_t stat_data = (mod_stat_data_t)malloc(sizeof(struct mod_stat_data_st));
    stat_data->si = si;

    register_beat(300, mod_stat_write, (void*)stat_data);

    if (stat_data != NULL) {
	js_mapi_register(si, e_DELIVER, mod_stat_deliver, (void*)stat_data);
    }
}
