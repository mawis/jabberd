/*
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 */

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

    /* ignore illegal calls */
    if(so == NULL || init == NULL) return;

    /* load the dso */
    so_h = dlopen(so,RTLD_LAZY);

    /* check for a load error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        fprintf(stderr,"Loading %s failed: %s\n",so,dlerr);
        exit(1);
    }

    /* resolve a reference to the dso's init function */
    init_h = dlsym(so_h,init);

    /* check for error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        fprintf(stderr,"Executing %s in %s failed: %s",init,so,dlerr);
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
