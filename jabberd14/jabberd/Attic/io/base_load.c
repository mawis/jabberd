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
    char *init = xmlnode_get_attrib(x,"main");
    void *f;
    int flag = 0;

    if(id != NULL)
    { /* execution phase */
        f = xmlnode_get_vattrib(x, init);
        ((base_load_init)f)(id, x); /* fire up the main function for this extension */
        return r_PASS;
    }

    printf("base_load_config processing configuration %s\n",xmlnode2str(x));

    for(so = xmlnode_get_firstchild(x); so != NULL; so = xmlnode_get_nextsibling(so))
    {
        if(xmlnode_get_type(so) != NTYPE_TAG) continue;

        f = base_load_symbol(xmlnode_get_name(so), xmlnode_get_data(so));
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
timeout xdb requests after a while, unblock and newx.data is still NULL
start sending logs depending on length of staleness
*/

result xdb_results(instance id, dpacket p, void *arg)
{
    xdbcache xc = (xdbcache)arg;
    xdbcache curx;
    int idnum;
    char *idstr;

    if(p->type != p_NORM || *(xmlnode_get_name(p->x)) != 'x') return r_PASS;

    log_debug(ZONE,"xdb_results checking xdb packet %s",xmlnode2str(p->x));

    if((idstr = xmlnode_get_attrib(p->x,"id")) == NULL) return r_ERR;

    idnum = atoi(idstr);

    for(curx = xc->next; curx->id != idnum && curx != xc; curx = curx->next); /* spin till we are where we started or find our id# */

    /* we got an id we didn't have cached, could be a dup, ignore and move on */
    if(curx->id != idnum)
    {
        pool_free(p->p);
        return r_DONE;
    }

    /* associte packet w/ waiting cache */
    curx->data = p->x;

    /* remove from ring */
    curx->prev->next = curx->next;
    curx->next->prev = curx->prev;

    /* free the thread! */
    curx->preblock = 0;
    if(curx->cond != NULL)
        pth_cond_notify(curx->cond, FALSE);

    return r_DONE; /* we processed it */
}

xdbcache xdb_cache(instance id)
{
    xdbcache newx;

    if(id == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_cache() called with NULL\n");
        return NULL;
    }

    newx = pmalloco(id->p, sizeof(_xdbcache));
    newx->i = id; /* flags it as the top of the ring too */
    newx->next = newx->prev = newx; /* init ring */

    /* register the handler in the instance to filter out xdb results */
    register_phandler(id, o_PRECOND, xdb_results, (void *)newx);

    return newx;
}

/* blocks until namespace is retrieved, host must map back to this service! */
xmlnode xdb_get(xdbcache xc, char *host, jid owner, char *ns)
{
    _xdbcache newx;
    xmlnode x;
    char ids[9];
    pth_mutex_t mutex = PTH_MUTEX_INIT;
    pth_cond_t cond = PTH_COND_INIT;

    if(xc == NULL || owner == NULL || ns == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_get() called with NULL\n");
        return NULL;
    }

    /* init this newx */
    newx.i = NULL;
    newx.data = NULL;
    newx.host = host;
    newx.ns = ns;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    newx.cond = NULL;

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* create the xml and deliver the xdb get request */
    jid_set(owner,ns,JID_RESOURCE);
    x = xmlnode_new_tag("xdb");
    xmlnode_put_attrib(x,"type","get");
    xmlnode_put_attrib(x,"to",jid_full(owner));
    xmlnode_put_attrib(x,"from",host);
    sprintf(ids,"%d",newx.id);
    xmlnode_put_attrib(x,"id",ids); /* to track response */
    deliver(dpacket_new(x), xc->i);

    /* if it hasn't already returned, we should block here until it returns */
    if(newx.preblock)
    {
        newx.cond = &cond;
        pth_mutex_acquire(&mutex, FALSE, NULL);
        pth_cond_await(&cond, &mutex, NULL); /* blocks thread */
    }

    /* newx.data is now the returned xml packet or NULL if it was unsuccessful */

    /* if get back type="error" log that and return NULL */
    if(j_strcmp(xmlnode_get_attrib(newx.data, "type"),"error") == 0)
    {
        log_notice(host,"xdb_get failed for %s to %s",ns,jid_full(owner));
        xmlnode_free(newx.data);
        return NULL;
    }

    /* return the xmlnode inside <xdb>...</xdb> */
    for(x = xmlnode_get_firstchild(newx.data); x != NULL && xmlnode_get_type(x) != NTYPE_TAG; x = xmlnode_get_nextsibling(x));

    return x;
}

/* sends new xml to replace old, data is NOT freed, app responsible for freeing it */
int xdb_set(xdbcache xc, char *host, jid owner, xmlnode data)
{
    _xdbcache newx;
    xmlnode x;
    char ids[9];
    pth_mutex_t mutex = PTH_MUTEX_INIT;
    pth_cond_t cond = PTH_COND_INIT;

    if(xc == NULL || host == NULL || owner == NULL || data == NULL)
    {
        fprintf(stderr,"Programming Error: xdb_set() called with NULL\n");
        return 1;
    }

    /* init this newx */
    newx.i = NULL;
    newx.data = data;
    newx.host = host;
    newx.ns = NULL;
    newx.owner = owner;
    newx.sent = time(NULL);
    newx.preblock = 1; /* flag */
    newx.cond = NULL;

    /* in the future w/ real threads, would need to lock xc to make these changes to the ring */
    newx.id = xc->id++;
    newx.next = xc->next;
    newx.prev = xc;
    newx.next->prev = &newx;
    xc->next = &newx;

    /* create the xml and deliver the xdb get request */
    x = xmlnode_new_tag("xdb");
    xmlnode_put_attrib(x,"type","set");
    xmlnode_put_attrib(x,"to",jid_full(owner));
    xmlnode_put_attrib(x,"from",host);
    sprintf(ids,"%d",newx.id);
    xmlnode_put_attrib(x,"id",ids); /* to track response */
    xmlnode_insert_tag_node(x,data); /* copy in the data */
    deliver(dpacket_new(x), xc->i);

    /* if it hasn't already returned, we should block here until it returns */
    if(newx.preblock)
    {
        newx.cond = &cond;
        pth_mutex_acquire(&mutex, FALSE, NULL);
        pth_cond_await(&cond, &mutex, NULL); /* blocks thread */
    }

    /* newx.data is now the returned xml packet or NULL if it was unsuccessful */

    /* if it didn't actually get set, flag that */
    if(newx.data == NULL)
        return 1;

    return 0;
}
