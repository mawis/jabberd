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

/* IN-PROCESS component loader */

typedef void (*load_init)(instance id, xmlnode x);
xmlnode load__cache = NULL;
int load_ref__count = 0;

#ifdef STATIC
/* optionally use static hardcoded symbols and don't compile in the dlopen stuff */

void jsm(instance id, xmlnode x);
void pthsock_client(instance i, xmlnode x);
void pthsock_server(instance i, xmlnode x);
void xdb_file(instance i, xmlnode x);
void dnsrv(instance i, xmlnode x);
void mod_echo();
void mod_groups();
void mod_roster();
void mod_time();
void mod_vcard();
void mod_version();
void mod_announce();
void mod_agents();
void mod_admin();
void mod_private();
void mod_filter();
void mod_presence();
void mod_auth_plain();
void mod_auth_digest();
void mod_auth_0k();
void mod_register();
void mod_log();

void *load_symbol(char *func, char *file)
{
    if(j_strcmp(func,"jsm") == 0) return jsm;
    if(j_strcmp(func,"pthsock_client") == 0) return pthsock_client;
    if(j_strcmp(func,"pthsock_server") == 0) return pthsock_server;
    if(j_strcmp(func,"xdb_file") == 0) return xdb_file;
    if(j_strcmp(func,"dnsrv") == 0) return dnsrv;
    if(j_strcmp(func,"mod_echo") == 0) return mod_echo;
    if(j_strcmp(func,"mod_groups") == 0) return mod_groups;
    if(j_strcmp(func,"mod_roster") == 0) return mod_roster;
    if(j_strcmp(func,"mod_time") == 0) return mod_time;
    if(j_strcmp(func,"mod_vcard") == 0) return mod_vcard;
    if(j_strcmp(func,"mod_version") == 0) return mod_version;
    if(j_strcmp(func,"mod_announce") == 0) return mod_announce;
    if(j_strcmp(func,"mod_agents") == 0) return mod_agents;
    if(j_strcmp(func,"mod_admin") == 0) return mod_admin;
    if(j_strcmp(func,"mod_private") == 0) return mod_private;
    if(j_strcmp(func,"mod_filter") == 0) return mod_filter;
    if(j_strcmp(func,"mod_presence") == 0) return mod_presence;
    if(j_strcmp(func,"mod_auth_plain") == 0) return mod_auth_plain;
    if(j_strcmp(func,"mod_auth_digest") == 0) return mod_auth_digest;
    if(j_strcmp(func,"mod_auth_0k") == 0) return mod_auth_0k;
    if(j_strcmp(func,"mod_register") == 0) return mod_register;
    if(j_strcmp(func,"mod_log") == 0) return mod_log;

    return NULL;
}

#else /* STATIC */

/* use dynamic dlopen/dlsym stuff here! */
#include <dlfcn.h>

/* process entire load element, loading each one (unless already cached) */
/* if all loaded, exec each one in order */

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
    char *dlerr, *func2;
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
        /* pregenerate the error, since our stuff below may overwrite dlerr */
        snprintf(message, MAX_LOG_SIZE, "Executing %s() in %s failed: '%s'\n",func,file,dlerr);

        /* ARG! simple stupid string handling in C sucks, there HAS to be a better way :( */
        /* AND no less, we're having to check for an underscore symbol?  only evidence of this is http://bugs.php.net/?id=3264 */
        func2 = malloc(strlen(func) + 2);
        func2[0] = '_';
        func2[1] = '\0';
        strcat(func2,func);
        func_h = dlsym(so_h, func2);
        free(func2);

        if(dlerror() != NULL)
        {
            fprintf(stderr, "%s\n", message);
            return NULL;
        }
    }

    return func_h;
}

#endif /* STATIC */

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

