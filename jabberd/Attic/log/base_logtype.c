/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include "jabberd.h"

result base_logtype_filter(instance id, dpacket p, void* arg)
{
    char* packettype     = xmlnode_get_attrib(p->x, "type");
    if(xmlnode_get_tag(xmlnode_get_parent((xmlnode)arg),packettype)!=NULL)
        return r_PASS;
    return r_LAST;
}

result base_logtype_config(instance id, xmlnode x, void *arg)
{
    char* name = NULL;
    char message[MAX_LOG_SIZE];
    name = xmlnode_get_name(x);
    if(id == NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "validating config: %s\n",name);
        fprintf(stderr, "%s\n", message);
        /* Ensure that the name of the tag is either "notice", "warn", or "alert" */
        if (strcmp(name, "notice") && strcmp(name, "warn") && strcmp(name, "alert"))
        {
            xmlnode_put_attrib(x,"error","Invalid log type filter requested");
            log_debug(ZONE,"base_logtype_config error: invalid log type filter requested (%s)\n", name);
            return r_ERR;
        }
        
        log_debug(ZONE,"base_logtype_config validating configuration\n");
        return r_PASS;
    }

    /* XXX this is an ugly hack, but it's better than a bad config */
    /* XXX needs to be a way to validate this in the checking phase */
    if(id->type!=p_LOG)
    {
        fprintf(stderr,"ERROR: <notice/>,<warn/> and <alert/> elements only allowed in log sections\n");
        exit(1);
    }

    /* Register a conditional handler for this instance, passing the name
     * of the tag as an argument (for comparison in the filter op 
     */
    register_phandler(id, o_COND, base_logtype_filter, (void*)x);

    log_debug(ZONE,"base_logtype_config performing configuration %s\n",xmlnode2str(x));

    return r_PASS;
}

void base_logtype(void)
{
    log_debug(ZONE,"base_logtype loading...\n");

    register_config("notice",base_logtype_config,NULL);
    register_config("warn",base_logtype_config,NULL);
    register_config("alert",base_logtype_config,NULL);
}
