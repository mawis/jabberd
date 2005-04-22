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
 * @file mod_stat.c
 * @brief collect statistical information and write it the the log
 *
 * this module collects statistical information and writes them every 5 minutes to
 * the log
 *
 * @todo make the statistical information accessible to the administrator requesting
 * it by a Jabber query.
 */

/**
 * @brief structure holding statistics data
 *
 * One instance of this structure is used to keep statistical data for a session manager instance.
 */
typedef struct mod_stat_data_st {
    jsmi si;

    int messages_delivered;	/**< how many messages have been delivered */
    int presences_delivered;	/**< how many presences have been delivered */
    int iqs_delivered;		/**< how many iqs have been delivered */
    int subscriptions_delivered;/**< how many subscriptions have been delivered */
} *mod_stat_data_t;

/**
 * write statistical information to the log
 *
 * @param arg pointer to this instance's mod_stat_data_st structure
 * @return r_UNREG if no mod_stat_data_st has been given, r_DONE else
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
    mod_stat_data_t stat_data = (mod_stat_data_t)pmalloco(si->p, sizeof(struct mod_stat_data_st));
    stat_data->si = si;

    register_beat(300, mod_stat_write, (void*)stat_data);

    if (stat_data != NULL) {
	js_mapi_register(si, e_DELIVER, mod_stat_deliver, (void*)stat_data);
    }
}
