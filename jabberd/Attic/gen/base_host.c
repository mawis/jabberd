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

/*
    <host>hostname.org</host>
    <host>*.polld.isp.net</host> [the . flags any domain matching that]
    <host/>
*/

typedef struct cleanup_struct
{
    instance i;
    char *hostname;
} _cleanup,*cleanup;

void _base_host_shutdown(void *arg)
{
    cleanup c=(cleanup)arg;
    unregister_instance(c->i,c->hostname);
}

result base_host_config(instance id, xmlnode x, void *arg)
{
    cleanup cl_new;
    if(id == NULL)
    {
        log_debug(ZONE,"base_host_config validating configuration %s\n",xmlnode2str(x));
        return r_PASS;
    }

    log_debug(ZONE,"base_host_config registering host %s with section '%s'\n",xmlnode_get_data(x), id->id);
    register_instance(id, xmlnode_get_data(x));
    cl_new=pmalloco(id->p,sizeof(_cleanup));
    cl_new->i=id;
    cl_new->hostname=pstrdup(id->p,xmlnode_get_data(x));
    pool_cleanup(id->p, _base_host_shutdown, (void*)cl_new);

    return r_PASS;
}

void base_host(void)
{
    log_debug(ZONE,"base_host loading...\n");

    register_config("host",base_host_config,NULL);
}
