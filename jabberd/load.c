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
#include <dlfcn.h>
#include "jabberd.h"

xmlnode load__cache = NULL;
int load_ref__count = 0;
typedef void (*load_init)(instance id, xmlnode x);

/* process entire load element, loading each one (unless already cached) */
/* if all loaded, exec each one in order */

/* they register a handler to accept incoming xmlnodes that get delivered to them */

void *load_loader(char *file)
{
    void *so_h;
    char *dlerr;
    char message[MAX_LOG_SIZE];

    /* load the dso */
    so_h = dlopen(file,RTLD_LAZY);

    /* check for a load error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "Loading %s failed: '%s'\n",file,dlerr);
        fprintf(stderr, "%s\n", message);
        return NULL;
    }

    xmlnode_put_vattrib(load__cache, file, so_h); /* fun hack! yes, it's just a nice name-based void* array :) */
    return so_h;
}

void *load_symbol(char *func, char *file)
{
    void (*func_h)(instance i, void *arg);
    void *so_h;
    char *dlerr;
    char message[MAX_LOG_SIZE];

    if(func == NULL || file == NULL)
        return NULL;

    if((so_h = xmlnode_get_vattrib(load__cache, file)) == NULL && (so_h = load_loader(file)) == NULL)
        return NULL;

    /* resolve a reference to the dso's init function */
    func_h = dlsym(so_h, func);

    /* check for error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "Executing %s() in %s failed: '%s'\n",func,file,dlerr);
        fprintf(stderr, "%s\n", message);
        return NULL;
    }

    return func_h;
}

void load_shutdown(void *arg)
{
    load_ref__count--;
    if(load_ref__count != 0)
        return;

    xmlnode_free(load__cache);
    load__cache = NULL;
}

result load_config(instance id, xmlnode x, void *arg)
{
    xmlnode so;
    char *init = xmlnode_get_attrib(x,"main");
    void *f;
    int flag = 0;

    if(load__cache == NULL)
        load__cache = xmlnode_new_tag("so_cache");

    if(id != NULL)
    { /* execution phase */
        load_ref__count++;
        pool_cleanup(id->p, load_shutdown, NULL);
        f = xmlnode_get_vattrib(x, init);
        ((load_init)f)(id, x); /* fire up the main function for this extension */
        return r_PASS;
    }

    
    log_debug(ZONE,"dynamic loader processing configuration %s\n",xmlnode2str(x));

    for(so = xmlnode_get_firstchild(x); so != NULL; so = xmlnode_get_nextsibling(so))
    {
        if(xmlnode_get_type(so) != NTYPE_TAG) continue;

        if(init == NULL && flag)
            return r_ERR; /* you can't have two elements in a load w/o a main attrib */

        f = load_symbol(xmlnode_get_name(so), xmlnode_get_data(so));
        if(f == NULL)
            return r_ERR;
        xmlnode_put_vattrib(x, xmlnode_get_name(so), f); /* hide the function pointer in the <load> element for later use */
        flag = 1;

        /* if there's only one .so loaded, it's the default, unless overridden */
        if(init == NULL)
            xmlnode_put_attrib(x,"main",xmlnode_get_name(so));
    }

    if(!flag) return r_ERR; /* we didn't DO anything, duh */

    return r_PASS;
}


void dynamic_init(void)
{
    log_debug(ZONE,"dynamic component loader initializing...\n");
    register_config("load",load_config,NULL);
}

