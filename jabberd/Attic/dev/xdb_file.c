#include <jabberd.h>

/* needs to have a spool section in the config, and make folders for hostnames */


/* store to the file system,
 * should always be the last option since it will always store
 */

struct loader
{
    char *fname;
    xmlnode data;
};

/* internal expat-wrapper thread, since expat is stack unfriendly :) */
int _xdb_file_load(void *arg)
{
    struct loader *l = (struct loader *)arg;

    log_debug(ZONE,"reading data from disk");
    l->data = xmlnode_file(l->fname);
    return 1;
}

/* this function acts as a loader, getting xml data from a file */
xmlnode xdb_file_load(char *fname)
{
    struct loader cur;
    pth_event_t evt;

    if(fname == NULL) return NULL;

    log_debug(ZONE,"loading %s",fname);

    /* load from disk, on seperate thread/stack */
    cur.fname = fname;
    evt = pth_event(PTH_EVENT_FUNC, _xdb_file_load, (void *)&cur,pth_time(0,100000));
    pth_wait(evt);
    pth_event_free(evt, PTH_FREE_THIS);

    /* if there's nothing on disk, create an empty root node */
    if(cur.data == NULL)
        cur.data = xmlnode_new_tag("xdb");

    return cur.data;
}

/* simple utility for concat strings */
char *_xdb_file_full(char *dir, char *file, char *ext)
{
    char *ret;

    ret = malloc(strlen(dir) + strlen(file) + strlen(ext) + 3);
    *ret = '\0';
    strcat(ret,dir);
    strcat(ret,"/");
    strcat(ret,file);
    strcat(ret,".");
    strcat(ret,ext);

    return ret;
}

/* the callback for the XDB api */
int xdb_file_handle(int set, xdb x, udata user, void *arg)
{
    char *full, *query, *spl = (char *)arg;
    xmlnode file, data;
    int ret = 0;

    log_debug(ZONE,"handler set[%d] for %s",set,x->ns);

    /* is this request specific to a user or global data? use that for the file name */
    if(user != NULL)
        full = _xdb_file_full(spl, user->user, "xml");
    else
        full = _xdb_file_full(spl, "global", "xdb");

    /* load the data from disk/cache */
    file = xdb_file_load(full);

    /* just query the relevant namespace */
    query = malloc(strlen(x->ns) + 8);
    *query = '\0';
    strcat(query,"?xdbns=");
    strcat(query,x->ns);
    data = xmlnode_get_tag(file,query);
    free(query);

    if(set)
    {
        if(data != NULL)
            xmlnode_hide(data);

        /* copy the new data into file */
        data = xmlnode_insert_tag_node(file, x->data);
        xmlnode_put_attrib(data,"xdbns",x->ns);

        /* save the file */
        if(xmlnode2file(full,file) < 0)
            log_error("xdb_file","Unable to save to file %s",full);
        else
            ret = 1;
    }else{
        if(data != NULL)
        { /* cool, send em back a copy of the data */
            x->data = xmlnode_dup(data);
            xmlnode_hide_attrib(x->data,"xdbns");
            ret = 1;
        }
    }

    xmlnode_free(file);
    free(full);
    return ret;
}

void xdb_file(void)
{
    char *spl;

    spl = xmlnode_get_data(js_config("spool"));
    if(spl == NULL)
    {
        log_error("xdb_file","No filesystem spool location configured");
        return;
    }

    js_xdb_register(xdb_file_handle, (void *)spl);
}

