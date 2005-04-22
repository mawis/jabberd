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

#include "jabberd.h"

#ifdef HAVE_SYSLOG

#include <syslog.h>

result base_syslog_deliver(instance id, dpacket p, void* arg)
{
    int facility = (int)arg;
    char* message = NULL;
    char* type_s = NULL;
    int type;

    message = xmlnode_get_data(p->x);
    if (message == NULL) {
       log_debug2(ZONE, LOGT_STRANGE, "base_syslog_deliver error: no message available to log.");
       return r_ERR;
    }

    type_s = xmlnode_get_attrib(p->x, "type");
    if (type_s == NULL) {
	log_debug2(ZONE, LOGT_STRANGE, "base_syslog_deliver error: no type attribute.");
	return r_ERR;
    }

    type = log_get_level(type_s);
    if (type == -1)
	type = LOG_INFO;

    syslog(facility|type, "%s", message);
    
    /* Release the packet */
    pool_free(p->p);
    return r_DONE;    
}

result base_syslog_config(instance id, xmlnode x, void *arg)
{
    int facility = 0;
    char *facility_str = NULL;

    if(id == NULL)
    {
        log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_syslog_config validating configuration");

        if (xmlnode_get_data(x) == NULL)
        {
            log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_syslog_config error: no facility provided");
            xmlnode_put_attrib(x,"error","'syslog' tag must contain a facility (use daemon, local0, ... local7)");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_CONFIG|LOGT_INIT, "base_syslog configuring instance %s",id->id);

    if(id->type != p_LOG)
    {
        log_alert(NULL,"ERROR in instance %s: <syslog>..</syslog> element only allowed in log sections", id->id);
        return r_ERR;
    }

    /* check which facility to use */
    facility_str = xmlnode_get_data(x);
    facility = log_get_facility(facility_str);

    if (facility == -1) {
	log_alert(NULL, "base_syslog_config error: unknown syslog facility: %s", facility_str);
	return r_ERR;
    }

    /* Register a handler for this instance... */
    register_phandler(id, o_DELIVER, base_syslog_deliver, (void*)facility); 

    return r_DONE;
}
#else
result base_syslog_config(instance id, xmlnode x, void *arg) {
    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_syslog_config error: jabberd compiled without syslog support.");
    xmlnode_put_attrib(x, "error", PACKAGE " compiled without syslog support");
    return r_ERR;
}
#endif

void base_syslog(void)
{
    log_debug2(ZONE, LOGT_INIT, "base_syslog loading...");
    register_config("syslog",base_syslog_config,NULL);
}
