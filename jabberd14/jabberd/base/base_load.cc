/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file base_load.cc
 * @brief module loader: handles the loading of components, that are installed as loadable modules - the &lt;load/&gt; configuration element
 */

#include "jabberd.h"
/* IN-PROCESS component loader */

typedef void (*base_load_init)(instance id, xmlnode x);	/**< prototype for the initialization function of a component */
std::map<std::string, void*> base_load__cache;		/**< map pointing from file names of shared objects to their loaded instances */
std::map<std::string, std::map<std::string, void*> > preloaded_functions; /**< module init functions that have been loaded and not assigned to the instance */
int base_load_ref__count = 0;				/**< counts loaded components. triggers shutdown if all components are unloaded */

/* use dynamic dlopen/dlsym stuff here! */
#include <dlfcn.h>

/**
 * process entire load element, loading each one (unless already chached),
 * if all loaded, exec each one in order
 *
 * @param file the dynamic library file to load
 */
static void *base_load_loader(char *file) {
    void *so_h;
    const char *dlerr;
    char message[MAX_LOG_SIZE];

    // sanity check
    if (!file)
	return NULL;

    /* load the dso */
    so_h = dlopen(file,RTLD_LAZY);

    /* check for a load error */
    if (!so_h) {
        dlerr = dlerror();
        snprintf(message, sizeof(message), "Loading %s failed: '%s'\n",file,dlerr);
        fprintf(stderr, "%s\n", message);
        return NULL;
    }

    // store the loaded object
    base_load__cache[file] = so_h;
    return so_h;
}

/**
 * load a function from a dynamic library file
 *
 * @param func which function to load
 * @param file the dynamic library file to load
 * @return pointer to the loaded function
 */
static void *base_load_symbol(const char *func, char *file) {
    void* func_h;
    void *so_h;
    const char *dlerr;
    char *func2;
    char message[MAX_LOG_SIZE];

    if (func == NULL || file == NULL)
        return NULL;

    // load the module if not already loaded
    if ((so_h = base_load__cache[file]) == NULL && (so_h = base_load_loader(file)) == NULL)
        return NULL;

    /* resolve a reference to the dso's init function */
    func_h = dlsym(so_h, func);

    /* check for error */
    dlerr = dlerror();
    if (dlerr != NULL) {
        /* pregenerate the error, since our stuff below may overwrite dlerr */
        snprintf(message, sizeof(message), "Executing %s() in %s failed: '%s'\n",func,file,dlerr);

        /* ARG! simple stupid string handling in C sucks, there HAS to be a better way :( */
        /* AND no less, we're having to check for an underscore symbol?  only evidence of this is http://bugs.php.net/?id=3264 */
        func2 = static_cast<char*>(malloc(strlen(func) + 2));
        func2[0] = '_';
        func2[1] = '\0';
        strcat(func2,func);
        func_h = dlsym(so_h, func2);
        free(func2);

        if (dlerror() != NULL) {
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
static void base_load_shutdown(void *arg) {
    base_load_ref__count--;
    if (base_load_ref__count != 0)
        return;
}

/**
 * handler for <load/> elements in the configuration
 *
 * @param id the instance the <load/> element was found in
 * @param x the <load/> element
 * @param arg unused/ignored
 * @return r_ERR on error, r_PASS on success
 */
static result base_load_config(instance id, xmlnode x, void *arg) {
    xmlnode so;
    char *init = xmlnode_get_attrib_ns(x, "main", NULL);
    void *f;
    char const* instance_id = xmlnode_get_attrib_ns(xmlnode_get_parent(x), "id", NULL);
    bool something_loaded = false;

    if (!instance_id) {
	log_debug2(ZONE, LOGT_CONFIG, "instance does not have an id");
	return r_ERR;
    }

    if (id != NULL) {
	/* execution phase */

	// copy preloaded_functions for this module to the instance
	for (std::map<std::string, void*>::iterator p = preloaded_functions[instance_id].begin(); p != preloaded_functions[instance_id].end(); ++p) {
	    (*id->module_init_funcs)[p->first] = p->second;
	}

	// load main function of the instance implementation
        base_load_ref__count++;
        pool_cleanup(id->p, base_load_shutdown, NULL);
	f = (*id->module_init_funcs)[init];
        ((base_load_init)f)(id, x); /* fire up the main function for this extension */
        return r_PASS;
    }

    
    log_debug2(ZONE, LOGT_CONFIG|LOGT_DYNAMIC, "dynamic loader processing configuration %s\n", xmlnode_serialize_string(x, xmppd::ns_decl_list(), 0));

    for (so = xmlnode_get_firstchild(x); so != NULL; so = xmlnode_get_nextsibling(so)) {
        if (xmlnode_get_type(so) != NTYPE_TAG) continue;

        if (init == NULL && something_loaded)
            return r_ERR; /* you can't have two elements in a load w/o a main attrib */

        f = base_load_symbol(xmlnode_get_localname(so), xmlnode_get_data(so));
        if (f == NULL)
            return r_ERR;
	/* XXX do not use xmlnode_put_vattrib(), it's deprecated */
	preloaded_functions[instance_id][xmlnode_get_localname(so)] = f; // remember module init functions to run
	something_loaded = true;

        /* if there's only one .so loaded, it's the default, unless overridden */
        if (init == NULL)
            xmlnode_put_attrib_ns(x, "main", NULL, NULL, xmlnode_get_localname(so));
    }

    if (!something_loaded)
	return r_ERR; /* we didn't DO anything, duh */

    return r_PASS;
}

/**
 * init the module loader
 *
 * register that we want to handle the &lt;load/&gt; element in the configuration
 *
 * @param p memory pool used to register memory for the registration of handling the &lt;load/&gt; config element
 */
void base_load(pool p) {
    log_debug2(ZONE, LOGT_DYNAMIC, "dynamic component loader initializing...\n");
    register_config(p, "load", base_load_config, NULL);
}
