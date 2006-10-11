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

#include "jadc2s.h"

/***
* walk over the rate table and clear out the old entries
* @param c2s the c2s context
*/
void connection_rate_cleanup(xmppd::pointer<c2s_st> c2s) {
    static time_t last = 0;
    time_t now;

    /* no entries? nothing to do! */
    if (c2s->connection_rates.empty())
	return;

    /* time to do a connection rate check again? */
    if ((time(&now) - last) > c2s->connection_rate_seconds) {

	/* iterate all entries in the map */
	std::map<std::string, connection_rate_t>::iterator p;
	for (p=c2s->connection_rates.begin(); p != c2s->connection_rates.end(); ++p) {

	    /* about to expire this entry? */
	    if (now - p->second->first_time > c2s->connection_rate_seconds) {
		DBG("free and zap");
		delete p->second;
		c2s->connection_rates.erase(p->first);
	    }
	}

	/* remember when we did this check last */
        time(&last);
    }
}

/***
* See if a connection is within the rate limit
*
* @param c2s the c2s context
* @param ip the ip to check
* @return 0 on valid 1 on invalid
*/
int connection_rate_check(xmppd::pointer<c2s_st> c2s, const std::string& ip) {
    connection_rate_t cr;
    time_t now;
    
    /* See if this is disabled */
    if (c2s->connection_rate_times == 0 || c2s->connection_rate_seconds == 0)
        return 0;

    cr = (c2s->connection_rates)[ip];

    /* If it is NULL they are the first of a possible series */
    if (cr == NULL)
    {
        cr = static_cast<connection_rate_t>(malloc(sizeof(struct connection_rate_st)));
        cr->ip = ip;
        cr->count = 1;
        time(&cr->first_time);
	(c2s->connection_rates)[ip] = cr;
        return 0;
    }

    /* If they are outside the time limit just reset them */
    if ((time(&now) - cr->first_time) > c2s->connection_rate_seconds)
    {
        cr->first_time = now;
        cr->count = 1;
        return 0;
    }

    /* see if they have too many conns */
    cr->count++;
    if (cr->count > c2s->connection_rate_times)
        return 1;
    
    return 0;
}
