#include <dlfcn.h>

#include "jabberd.h"

xmlnode base_load__cache = NULL;

/* process entire load element, loading each one (unless already cached) */
/* if all loaded, exec each one in order */

/* they register a handler to accept incoming xmlnodes that get delivered to them */
/* base_load sends packets on when it receives them */

void *base_load_loader(char *file)
{
    void *so_h;
    char *dlerr;

    /* load the dso */
    so_h = dlopen(file,RTLD_LAZY);

    /* check for a load error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        fprintf(stderr,"Loading %s failed: '%s'\n",file,dlerr);
        return NULL;
    }

    xmlnode_put_vattrib(base_load__cache, file, so_h); /* fun hack! yes, it's just a nice name-based void* array :) */
    return so_h;
}

void *base_load_symbol(char *func, char *file)
{
    void (*func_h)(instance i, void *arg);
    void *so_h;
    char *dlerr;

    if(func == NULL || file == NULL)
        return NULL;

    if((so_h = xmlnode_get_vattrib(base_load__cache, file)) == NULL && (so_h = base_load_loader(file)) == NULL)
        return NULL;

    /* resolve a reference to the dso's init function */
    func_h = dlsym(so_h, func);

    /* check for error */
    dlerr = dlerror();
    if(dlerr != NULL)
    {
        fprintf(stderr,"Executing %s() in %s failed: '%s'\n",func,file,dlerr);
        return NULL;
    }

    return func_h;
}

result base_load_config(instance id, xmlnode x, void *arg)
{
    xmlnode so;

    if(id == NULL)
    {
        printf("base_load_config validating configuration\n");
        return r_PASS;
    }

    printf("base_load_config performing configuration %s\n",xmlnode2str(x));
    /* scan through the dso's specified */
    for(so = xmlnode_get_firstchild(x); so != NULL; so = xmlnode_get_nextsibling(so))
        if(xmlnode_get_type(so) == NTYPE_TAG)
            /*loader_dso(xmlnode_get_data(mod), xmlnode_get_name(mod))*/;

    /* with each load section, register a handler for the xdb blocked ring */
}

void base_load(void)
{
    printf("base_load loading...\n");

    /* init global cache */
    base_load__cache = xmlnode_new_tag("so_cache");

    register_config("load",base_load_config,NULL);
}



/************ BELOW IS UTILITY SYMBOLS FOR LOADED MODULES ***************/

/* CREATE an xdb blocked ring
each entry has a new int and is placed as the id="int" value
incoming results are intercepted and that entry is unblocked
some sort of timer that scans the ring oldest to newest, resending stale requests
start sending logs depending on length of staleness
*/

/* blocks until namespace is retrieved, host must map back to this service! */
xmlnode xdb_get(xdbcache xc, char *host, jid to, char *ns)
{
    /* create the xml and deliver the xdb get request */
    /* insert an entry in this instances xdb blocked ring */
    /* if get back type="error" log that */
    /* returns the xmlnode inside <xdb>...</xdb> if success, or NULL if fail */
}

/* sends new xml to replace old */
int xdb_set(xdbcache xc, char *host, jid to, xmlnode data)
{
    /* blocks just like the get, returns non-zero if error */
    /* if get back type="error" log that */
}
