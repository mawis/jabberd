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

#include <jabberd.h>

/* 
gcc -fPIC -shared -o xdb_file.so xdb_file.c -I../src

needs to have a spool section in the config:

<load><xdb_file>../load/xdb_file.so</xdb_file></load>
<xdb_file xmlns="jabber:config:xdb_file">
  <spool>/var/spool/jabber</spool>
</xdb_file>

within the spool, xdb_file will make folders for hostnames it has to save data for, and within those save username.xml files containing a user's namespaces

*/


/* this function acts as a loader, getting xml data from a file */
xmlnode xdb_file_load(char *fname)
{
    xmlnode data;

    log_debug(ZONE,"loading %s",fname);

    data = xmlnode_file(fname);

    /* if there's nothing on disk, create an empty root node */
    if(data == NULL)
        data = xmlnode_new_tag("xdb");

    return data;
}

/* simple utility for concat strings */
char *xdb_file_full(int create, char *spl, char *host, char *file, char *ext)
{
    struct stat s;
    char *ret;

    /* path to host-named folder */
    ret = malloc(strlen(spl) + strlen(host) + strlen(file) + strlen(ext) + 4);
    *ret = '\0';
    strcat(ret,spl);
    strcat(ret,"/");
    strcat(ret,host);

    /* ensure that it exists, or create it */
    if(create && stat(ret,&s) < 0 && mkdir(ret, S_IRWXU) < 0)
    {
        log_error(host,"xdb request failed, error accessing spool loaction %s: %s",ret,strerror(errno));
        free(ret);
        return NULL;
    }

    /* full path to file */
    strcat(ret,"/");
    strcat(ret,file);
    strcat(ret,".");
    strcat(ret,ext);

    return ret;
}

/* the callback to handle xdb packets */
result xdb_file_phandler(instance i, dpacket p, void *arg)
{
    char *full, *query, *spl = (char *)arg;
    xmlnode file, data;
    int ret = 0, flag_set = 0;

    log_debug(ZONE,"handling xdb request %s",xmlnode2str(p->x));

    if(j_strcmp(xmlnode_get_attrib(p->x,"type"), "set") == 0)
        flag_set = 1;

    /* is this request specific to a user or global data? use that for the file name */
    if(p->id->user != NULL)
        full = xdb_file_full(flag_set, spl, p->id->server, p->id->user, "xml");
    else
        full = xdb_file_full(flag_set, spl, p->id->server, "global", "xdb");

    if(full == NULL)
        return r_ERR;

    /* load the data from disk/cache */
    file = xdb_file_load(full);

    /* just query the relevant namespace */
    query = malloc(strlen(p->id->resource) + 8);
    *query = '\0';
    strcat(query,"?xdbns=");
    strcat(query,p->id->resource);
    data = xmlnode_get_tag(file,query);
    free(query);

    if(flag_set)
    {
        if(data != NULL)
            xmlnode_hide(data);

        /* copy the new data into file */
        data = xmlnode_insert_tag_node(file, xmlnode_get_firstchild(p->x));
        xmlnode_put_attrib(data,"xdbns",p->id->resource);

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

    xmlnode_free(file);
    free(full);

    if(ret)
    {
        xmlnode_put_attrib(p->x,"type","result");
        xmlnode_put_attrib(p->x,"to",xmlnode_get_attrib(p->x,"from"));
        xmlnode_put_attrib(p->x,"from",jid_full(p->id));
        deliver(dpacket_new(p->x), NULL); /* dpacket_new() shouldn't ever return NULL */
        return r_DONE;
    }else{
        return r_ERR;
    }
}

void xdb_file(instance i, xmlnode x)
{
    char *spl;
    xmlnode config;
    xdbcache xc;

    log_debug(ZONE,"xdb_file loading");

    xc = xdb_cache(i);
    config = xdb_get(xc, NULL, jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:xdb_file");

    spl = xmlnode_get_tag_data(config,"spool");
    if(spl == NULL)
    {
        log_error(NULL,"xdb_file: No filesystem spool location configured");
        return;
    }

    register_phandler(i, o_DELIVER, xdb_file_phandler, (void *)pstrdup(i->p,spl));
    xmlnode_free(config);
}

