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
 
#include <jabberd.h>

#define FILES_PRIME 509

/* 
gcc -fPIC -shared -o xdb_file.so xdb_file.c -I../src

needs to have a spool section in the config:

<load><xdb_file>../load/xdb_file.so</xdb_file></load>
<xdb_file xmlns="jabber:config:xdb_file">
  <spool>/var/spool/jabber</spool>
</xdb_file>

within the spool, xdb_file will make folders for hostnames it has to save data for, and within those save username.xml files containing a user's namespaces

*/

typedef struct cacher_struct
{
    char *fname;
    xmlnode file;
    int lastset;
} *cacher, _cacher;

typedef struct xdbf_struct
{
    char *spool;
    instance i;
    int timeout;
    HASHTABLE cache;
} *xdbf, _xdbf;

int _xdb_file_purge(void *arg, const void *key, void *data)
{
    xdbf xf = (xdbf)arg;
    cacher c = (cacher)data;
    int now = time(NULL);

    if((now - c->lastset) > xf->timeout)
    {
        log_debug(ZONE,"purging %s",c->fname);
        ghash_remove(xf->cache,c->fname);
        xmlnode_free(c->file);
    }

    return 1;
}

/* walk the table looking for stale files to expire */
result xdb_file_purge(void *arg)
{
    xdbf xf = (xdbf)arg;

    log_debug(ZONE,"purge check");
    ghash_walk(xf->cache,_xdb_file_purge,(void *)xf);

    return r_DONE;
}

/* this function acts as a loader, getting xml data from a file */
xmlnode xdb_file_load(char *host, char *fname, HASHTABLE cache)
{
    xmlnode data = NULL;
    cacher c;
    int fd;

    log_debug(ZONE,"loading %s",fname);

    /* first, check the cache */
    if((c = ghash_get(cache,fname)) != NULL)
        return c->file;

    /* test the file first, so we can be more descriptive */
    fd = open(fname,O_RDONLY);
    if(fd < 0)
    {
        log_warn(host,"xdb_file failed to open file %s: %s",fname,strerror(errno));
    }else{
        close(fd);
        data = xmlnode_file(fname);
    }

    /* if there's nothing on disk, create an empty root node */
    if(data == NULL)
        data = xmlnode_new_tag("xdb");

    log_debug(ZONE,"caching %s",fname);
    c = pmalloco(xmlnode_pool(data),sizeof(_cacher));
    c->fname = pstrdup(xmlnode_pool(data),fname);
    c->lastset = time(NULL);
    c->file = data;
    ghash_put(cache,c->fname,c);

    return data;
}

/* simple utility for concat strings */
char *xdb_file_full(int create, pool p, char *spl, char *host, char *file, char *ext)
{
    struct stat s;
    spool sp = spool_new(p);
    char *ret;

    /* path to host-named folder */
    spooler(sp,spl,"/",host,sp);
    ret = spool_print(sp);

    /* ensure that it exists, or create it */
    if(create && stat(ret,&s) < 0 && mkdir(ret, S_IRWXU) < 0)
    {
        log_error(host,"xdb request failed, error accessing spool loaction %s: %s",ret,strerror(errno));
        return NULL;
    }

    /* full path to file */
    spooler(sp,"/",file,".",ext,sp);
    ret = spool_print(sp);

    return ret;
}

int xdb_file_insertcheck(char *ns, xmlnode data, xmlnode dnew)
{
    char *str = NULL;

    /* if there's no new stuff or if the new stuff has a namespace, it's an entire replacement and not an insertion */
    if(dnew == NULL || xmlnode_get_attrib(dnew,"xmlns") != NULL)
        return 0;

    /* some namespaces are just generic insertable ones */
    if(strcmp(ns,NS_OFFLINE) == 0 || strcmp(ns,NS_XDBGINSERT) == 0)
        return 1;

    /* roster and browse items get handled specially, to replace based on jid */
    if((strcmp(ns,NS_ROSTER) == 0 || strcmp(ns,NS_BROWSE) == 0) && (str = xmlnode_get_attrib(dnew,"jid")) != NULL)
    {
        /* remove any old jids, since we insert AND replace */
        xmlnode_hide(xmlnode_get_tag(data, spools(xmlnode_pool(data),"?jid=",str,xmlnode_pool(data))));
        return 1;
    }

    /* the nslist items, well, we don't really need to replace them, we should just return but I'm being lazy and don't want to add a special condition */
    if(strcmp(ns,NS_XDBNSLIST) == 0 && (str = xmlnode_get_data(dnew)) != NULL)
    {
        for(dnew = xmlnode_get_firstchild(data); dnew != NULL; dnew = xmlnode_get_nextsibling(dnew))
            if(j_strcmp(xmlnode_get_data(dnew),str) == 0)
                xmlnode_hide(dnew);

        return 1;
    }

    return 0;
}

/* the callback to handle xdb packets */
result xdb_file_phandler(instance i, dpacket p, void *arg)
{
    char *full, *ns;
    xdbf xf = (xdbf)arg;
    xmlnode file, top, data;
    int ret = 0, flag_set = 0;

    log_debug(ZONE,"handling xdb request %s",xmlnode2str(p->x));

    if((ns = xmlnode_get_attrib(p->x,"ns")) == NULL)
        return r_ERR;

    if(j_strcmp(xmlnode_get_attrib(p->x,"type"), "set") == 0)
        flag_set = 1;

    /* is this request specific to a user or global data? use that for the file name */
    if(p->id->user != NULL)
        full = xdb_file_full(flag_set, p->p, xf->spool, p->id->server, p->id->user, "xml");
    else
        full = xdb_file_full(flag_set, p->p, xf->spool, p->id->server, "global", "xdb");

    if(full == NULL)
        return r_ERR;

    /* load the data from disk/cache */
    top = file = xdb_file_load(p->host, full, xf->cache);

    /* if we're dealing w/ a resource, just get that element */
    if(p->id->resource != NULL)
    {
        if((top = xmlnode_get_tag(top,spools(p->p,"res?id=",p->id->resource,p->p))) == NULL)
        {
            top = xmlnode_insert_tag(file,"res");
            xmlnode_put_attrib(top,"id",p->id->resource);
        }
    }

    /* just query the relevant namespace */
    data = xmlnode_get_tag(top,spools(p->p,"?xdbns=",ns,p->p));

    if(flag_set)
    {
        if(xdb_file_insertcheck(ns, data, xmlnode_get_firstchild(p->x)))
        {
            if(data == NULL)
            { /* we're inserting into something that doesn't exist?!?!? */
                data = xmlnode_insert_tag(top,"foo");
                xmlnode_put_attrib(data,"xdbns",ns);
                xmlnode_put_attrib(data,"xmlns",ns); /* insertable ones must have a top-level xmlns attrib, that's the flag to override insertion */
            }

            /* insert the new chunk into the existing data */
            xmlnode_insert_tag_node(data, xmlnode_get_firstchild(p->x));

        }else{
            /* we replace the old data */
            if(data != NULL)
                xmlnode_hide(data);

            /* copy the new data into file */
            data = xmlnode_insert_tag_node(top, xmlnode_get_firstchild(p->x));
            xmlnode_put_attrib(data,"xdbns",ns);
        }

        /* save the file */
        if(xmlnode2file(full,file) < 0)
            log_error(p->id->server,"xdb request failed, unable to save to file %s",full);
        else
            ret = 1;
    }else{
        /* a get always returns, data or not */
        ret = 1;

        if(data != NULL)
        { /* cool, send em back a copy of the data */
            xmlnode_hide_attrib(xmlnode_insert_tag_node(p->x, data),"xdbns");
        }
    }

    if(ret)
    {
        xmlnode_put_attrib(p->x,"type","result");
        xmlnode_put_attrib(p->x,"to",xmlnode_get_attrib(p->x,"from"));
        xmlnode_put_attrib(p->x,"from",jid_full(p->id));
        deliver(dpacket_new(p->x), NULL); /* dpacket_new() shouldn't ever return NULL */

        /* remove the cache'd item if it was a set or we're not configured to cache */
        if(xf->timeout == 0 || flag_set)
        {
            log_debug(ZONE,"decaching %s",full);
            ghash_remove(xf->cache,full);
            xmlnode_free(file);
        }
        return r_DONE;
    }else{
        return r_ERR;
    }
}

void xdb_file_cleanup(void *arg)
{
    xdbf xf = (xdbf)arg;
    ghash_destroy(xf->cache);
}

void xdb_file(instance i, xmlnode x)
{
    char *spl, *to;
    xmlnode config;
    xdbcache xc;
    xdbf xf;
    int timeout = -1; /* defaults to timeout forever */

    log_debug(ZONE,"xdb_file loading");

    xc = xdb_cache(i);
    config = xdb_get(xc, jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:xdb_file");

    spl = xmlnode_get_tag_data(config,"spool");
    if(spl == NULL)
    {
        log_error(NULL,"xdb_file: No filesystem spool location configured");
        return;
    }
    to = xmlnode_get_tag_data(config,"timeout");
    if(to != NULL)
        timeout = atoi(to);

    xf = pmalloco(i->p,sizeof(_xdbf));
    xf->spool = pstrdup(i->p,spl);
    xf->timeout = timeout;
    xf->i = i;
    xf->cache = ghash_create(j_atoi(xmlnode_get_tag_data(config,"maxfiles"),FILES_PRIME),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);

    register_phandler(i, o_DELIVER, xdb_file_phandler, (void *)xf);
    if(timeout > 0) /* 0 is expired immediately, -1 is cached forever */
        register_beat(30, xdb_file_purge, (void *)xf);

    xmlnode_free(config);
    pool_cleanup(i->p, xdb_file_cleanup, (void*)xf);
}

