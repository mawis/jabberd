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

result base_to_deliver(instance id,dpacket p,void* arg)
{
    char* log_data=xmlnode_get_data(p->x);
    char* subject;
    xmlnode message;

    if(log_data==NULL)
        return r_ERR;

    message=xmlnode_new_tag("message");
    xmlnode_insert_cdata(xmlnode_insert_tag(message,"body"),log_data,-1);
    subject=spools(xmlnode_pool(message),"Log Packet from ",xmlnode_get_attrib(p->x,"from"),xmlnode_pool(message));
    xmlnode_insert_cdata(xmlnode_insert_tag(message,"thread"),shahash(subject),-1);
    xmlnode_insert_cdata(xmlnode_insert_tag(message,"subject"),subject,-1);
    xmlnode_put_attrib(message,"from",xmlnode_get_attrib(p->x,"from"));
    xmlnode_put_attrib(message,"to",(char*)arg);
    deliver(dpacket_new(message),id);

    pool_free(p->p);
    return r_DONE;
}

result base_to_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        log_debug(ZONE,"base_to_config validating configuration\n");
        if(xmlnode_get_data(x)==NULL)
        {
            xmlnode_put_attrib(x,"error","'to' tag must contain a jid to send log data to");
            log_error(ZONE,"Invalid Configuration for base_to");
            return r_ERR;
        }
        return r_PASS;
    }

    /* XXX this is an ugly hack, but it's better than a bad config */
    /* XXX needs to be a way to validate this in the checking phase */
    if(id->type!=p_LOG)
    {
        fprintf(stderr,"ERROR: <to>..</to> element only allowed in log sections\n");
        exit(1);
    }

    register_phandler(id,o_DELIVER,base_to_deliver,(void*)xmlnode_get_data(x));
    return r_DONE;
}

void base_to(void)
{
    log_debug(ZONE,"base_to loading...\n");

    register_config("to",base_to_config,NULL);
}
