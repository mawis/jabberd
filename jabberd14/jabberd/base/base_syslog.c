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

#include "jabberd.h"

#ifdef HAVE_SYSLOG

#include <syslog.h>

result base_syslog_deliver(instance id, dpacket p, void* arg)
{
    int facility = (int)arg;
    char* message = NULL;
    char* type_s = NULL;
    int type = LOG_INFO;

    message = xmlnode_get_data(p->x);
    if (message == NULL) {
       log_debug(ZONE,"base_syslog_deliver error: no message available to log.");
       return r_ERR;
    }

    type_s = xmlnode_get_attrib(p->x, "type");
    if (type_s == NULL) {
	log_debug(ZONE, "base_syslog_deliver error: no type attribute.");
	return r_ERR;
    }

    if (j_strcmp(type_s, "notice") == 0) type = LOG_NOTICE;
    else if (j_strcmp(type_s, "warn") == 0) type = LOG_WARNING;
    else if (j_strcmp(type_s, "alert") == 0) type = LOG_ALERT;
    else if (j_strcmp(type_s, "stat") == 0) type = LOG_INFO;
    else if (j_strcmp(type_s, "info") == 0) type = LOG_INFO;
    else if (j_strcmp(type_s, "emerg") == 0) type = LOG_EMERG;
    else if (j_strcmp(type_s, "crit") == 0) type = LOG_CRIT;
    else if (j_strcmp(type_s, "err") == 0) type = LOG_ERR;
    else if (j_strcmp(type_s, "debug") == 0) type = LOG_DEBUG;

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
        log_debug(ZONE,"base_syslog_config validating configuration");

        if (xmlnode_get_data(x) == NULL)
        {
            log_debug(ZONE,"base_syslog_config error: no facility provided");
            xmlnode_put_attrib(x,"error","'syslog' tag must contain a facility (use daemon, local0, ... local7)");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug(ZONE,"base_syslog configuring instance %s",id->id);

    if(id->type != p_LOG)
    {
        log_alert(NULL,"ERROR in instance %s: <syslog>..</syslog> element only allowed in log sections", id->id);
        return r_ERR;
    }

    /* check which facility to use */
    facility_str = xmlnode_get_data(x);

    if (j_strcmp(facility_str, "daemon") == 0) facility = LOG_DAEMON;
    else if (j_strcmp(facility_str, "local0") == 0) facility = LOG_LOCAL0;
    else if (j_strcmp(facility_str, "local1") == 0) facility = LOG_LOCAL1;
    else if (j_strcmp(facility_str, "local2") == 0) facility = LOG_LOCAL2;
    else if (j_strcmp(facility_str, "local3") == 0) facility = LOG_LOCAL3;
    else if (j_strcmp(facility_str, "local4") == 0) facility = LOG_LOCAL4;
    else if (j_strcmp(facility_str, "local5") == 0) facility = LOG_LOCAL5;
    else if (j_strcmp(facility_str, "local6") == 0) facility = LOG_LOCAL6;
    else if (j_strcmp(facility_str, "local7") == 0) facility = LOG_LOCAL7;
    else if (j_strcmp(facility_str, "auth") == 0) facility = LOG_AUTH;
    else if (j_strcmp(facility_str, "authpriv") == 0) facility = LOG_AUTHPRIV;
    else if (j_strcmp(facility_str, "cron") == 0) facility = LOG_CRON;
    else if (j_strcmp(facility_str, "kern") == 0) facility = LOG_KERN;
    else if (j_strcmp(facility_str, "lpr") == 0) facility = LOG_LPR;
    else if (j_strcmp(facility_str, "mail") == 0) facility = LOG_MAIL;
    else if (j_strcmp(facility_str, "news") == 0) facility = LOG_NEWS;
    else if (j_strcmp(facility_str, "syslog") == 0) facility = LOG_SYSLOG;
    else if (j_strcmp(facility_str, "user") == 0) facility = LOG_USER;
    else if (j_strcmp(facility_str, "uucp") == 0) facility = LOG_UUCP;
    else {
	log_alert(NULL, "base_syslog_config erorr: unknown syslog facility: %s", facility_str);
	return r_ERR;
    }

    /* Register a handler for this instance... */
    register_phandler(id, o_DELIVER, base_syslog_deliver, (void*)facility); 

    return r_DONE;
}
#else
result base_syslog_config(instance id, xmlnode x, void *arg) {
    log_debug(ZONE, "base_syslog_config error: jabberd compiled without syslog support.");
    xmlnode_put_attrib(x, "error", PACKAGE " compiled without syslog support");
    return r_ERR;
}
#endif

void base_syslog(void)
{
    log_debug(ZONE,"base_syslog loading...");
    register_config("syslog",base_syslog_config,NULL);
}
