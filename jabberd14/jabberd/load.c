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

/**
 * @file load.c
 * @brief module loader: handles the loading of components, that are installed as loadable modules
 */

#include "jabberd.h"
/* IN-PROCESS component loader */

typedef void (*load_init)(instance id, xmlnode x);
xmlnode load__cache = NULL;
int load_ref__count = 0;

/* use dynamic dlopen/dlsym stuff here! */
#include <dlfcn.h>

/**
 * process entire load element, loading each one (unless already chached),
 * if all loaded, exec each one in order
 *
 * @param file the dynamic library file to load
 */
void *load_loader(char *file) {
    void *so_h;
    const char *dlerr;
    char message[MAX_LOG_SIZE];

    /* load the dso */
    so_h = dlopen(file,RTLD_LAZY);

    /* check for a load error */
    if(!so_h) {
        dlerr = dlerror();
        snprintf(message, MAX_LOG_SIZE, "Loading %s failed: '%s'\n",file,dlerr);
        fprintf(stderr, "%s\n", message);
        return NULL;
    }

    xmlnode_put_vattrib(load__cache, file, so_h); /* fun hack! yes, it's just a nice name-based void* array :) */
    return so_h;
}

/**
 * load a function from a dynamic library file
 *
 * @param func which function to load
 * @param file the dynamic library file to load
 * @return pointer to the loaded function
 */
void *load_symbol(char *func, char *file) {
    void (*func_h)(instance i, void *arg);
    void *so_h;
    const char *dlerr;
    char *func2;
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

/**
 * cleanup handler, frees our global variables if all instances are unloaded
 *
 * @param arg unused/ignored
 */
void load_shutdown(void *arg)
{
    load_ref__count--;
    if(load_ref__count != 0)
        return;

    xmlnode_free(load__cache);
    load__cache = NULL;
}

/**
 * handler for <load/> elements in the configuration
 *
 * @param id the instance the <load/> element was found in
 * @param x the <load/> element
 * @param arg unused/ignored
 * @return r_ERR on error, r_PASS on success
 */
result load_config(instance id, xmlnode x, void *arg) {
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

    
    log_debug2(ZONE, LOGT_CONFIG|LOGT_DYNAMIC, "dynamic loader processing configuration %s\n", xmlnode2str(x));

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

/**
 * init the module loader
 *
 * register that we want to handle the <load/> element in the configuration
 */
void dynamic_init(void) {
    log_debug2(ZONE, LOGT_DYNAMIC, "dynamic component loader initializing...\n");
    register_config("load",load_config,NULL);
}

