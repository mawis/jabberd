#include <dlfcn.h>

#include "jabberd.h"


extern xmlnode greymatter__;

/* load all base modules */
void loader_static(void)
{
    /* XXX-temas:  this will need to be auto defined by configure */
    /* call static modules */
    /* gen_foo(); io_foo(); ... */
    base_host();
    base_accept();
    base_cache();
    base_connect();
    base_exec();
    base_file();
    base_fork();
    base_format();
    base_load();
    base_logtype();
    base_ns();
    base_to();
    base_stderr();
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
        printf("Loading %s failed: %s\n",so,dlerr);
        exit(1);
    }

    /* resolve a reference to the dso's init function */
    init_h = dlsym(so_h,init);

    /* check for error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        printf("Executing %s in %s failed: %s",init,so,dlerr);
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
