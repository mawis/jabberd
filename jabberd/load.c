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


extern xmlnode greymatter__;

void base_host(void);
void base_accept(void);
void base_connect(void);
void base_exec(void);
void base_file(void);
void base_format(void);
void base_load(void);
void base_logtype(void);
void base_ns(void);
void base_to(void);
void base_stderr(void);
void base_stdout(void);

/* load all base modules */
void loader_static(void)
{
    /* XXX-temas:  this will need to be auto defined by configure */
    /* call static modules */
    /* gen_foo(); io_foo(); ... */
    base_host();
    base_accept();
    base_connect();
    base_exec();
    base_file();
    base_format();
    base_load();
    base_logtype();
    base_ns();
    base_to();
    base_stderr();
    base_stdout();
}

void loader_dso(char *so, char *init)
{
    void (*init_h)(void);
    void *so_h;
    char *dlerr;
    char message[MAX_LOG_SIZE];

    /* ignore illegal calls */
    if(so == NULL || init == NULL) return;

    /* load the dso */
    so_h = dlopen(so,RTLD_LAZY);

    /* check for a load error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "Loading %s failed: %s\n",so,dlerr);
        fprintf(stderr, "%s\n", message);
        exit(1);
    }

    /* resolve a reference to the dso's init function */
    init_h = dlsym(so_h,init);

    /* check for error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        snprintf(message, MAX_LOG_SIZE, "Executing %s in %s failed: %s",init,so,dlerr);
        fprintf(stderr, "%s\n", message);
        exit(1);
    }

    /* call the init function */
    (init_h)();

}

void loader(void)
{
    xmlnode base, mod;

    /* fire static modules */
    loader_static();

    /* check for dynamic modules */
    base = xmlnode_get_tag(greymatter__,"base");

    /* if no dsos are configured return */
    if(base == NULL)
        return;

    /* scan through the dso's specified */
    for(mod = xmlnode_get_firstchild(base); mod != NULL; mod = xmlnode_get_nextsibling(mod))
        if(xmlnode_get_type(mod) == NTYPE_TAG)
            loader_dso(xmlnode_get_data(mod), xmlnode_get_name(mod));

}
