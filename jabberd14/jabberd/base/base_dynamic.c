/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
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
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

#include "jabberd.h"

/* 

  <dynamic><folder>/path/to/folder</folder><match>user</match></dynamic>

  match is by default user, but can be configured to resource instead
*/

typedef struct dcfg_struct
{
    int match;
    char *folder;
    xht cache;
} *dcfg, _dcfg;

typedef struct dfile_struct
{
    _instance i; /* yay, C hackage! */
    char *file;
    int mtime;
    jid id;
} *dfile, _dfile;

void *load_symbol(char *func, char *file);
result base_exec_config(instance id, xmlnode x, void *arg);

result base_dynamic_deliver(instance i, dpacket p, void* arg)
{
    dcfg d = (dcfg)arg;
    char *match, *file;
    struct stat m;
    dfile f;
    pool pnew;
    void (*so)(instance,xmlnode) = NULL;
    xmlnode x;

    if(d->match)
        match = p->id->resource;
    else
        match = p->id->user;

    /* check for an existing instance */
    f = xhash_get(d->cache, match);

    /* if this is a new match or the old one dissappeared or was replaced */
    if(f == NULL || stat(f->file, &m) != 0 || m.st_mtime > f->mtime)
    {
        file = spools(p->p, d->folder, "/", match, p->p);
        if(stat(file,&m) != 0) /* check for a file directly */
        {
            file = spools(p->p, d->folder, "/", match, ".so", p->p);
            if(stat(file,&m) != 0)
            {
                log_alert(p->host,"Unable to locate dynamic handler %s in folder %s",match,d->folder);
                deliver_fail(p,"Unable to locate handler");
                return r_DONE;
            }
            if((so = load_symbol(match, file)) == NULL)
            {
                log_alert(p->host,"Unable to load dynamic handler %s in file %s",match,file);
                deliver_fail(p,"Unable to start handler");
                return r_DONE;
            }
        }else if(!(S_IXUSR & m.st_mode)){ /* check for executability on file */
            log_alert(p->host,"Execuate bit is not set on dynamic handler for %s",file);
            deliver_fail(p,"Unable to start handler");
            return r_DONE;
        }

        /* if there was an old one, free it, that's _supposed_ to flag anything depending on it to clean up */
        if(f != NULL)
            pool_free(f->i.p);

        /* now we know we have a valid handler */
        pnew = pool_new();
        f = pmalloco(pnew, sizeof(_dfile));
        f->file = pstrdup(pnew, file);
        f->mtime = m.st_mtime;
        f->id = jid_new(pnew, jid_full(p->id));
        if(d->match)
        {
            jid_set(f->id,NULL,JID_USER);
            xhash_put(d->cache, f->id->resource, (void *)f);
        }else{
            jid_set(f->id,NULL,JID_RESOURCE);
            xhash_put(d->cache, f->id->user, (void *)f);
        }
        f->i.p = pnew;
        f->i.id = jid_full(f->id);
        f->i.type = p_NORM;
        f->i.x = i->x; /* I guess, if one of the dynamic handlers wants to have xdb config in the file, it's tracked on this instance so we should point to the parent one, could be a problem someday :) */

        /* now, the fun part, start up the actual modules! */
        if(so != NULL)
        {
            (so)(&(f->i), NULL);
        }else{
            x = xmlnode_new_tag_pool(f->i.p,"exec");
            xmlnode_insert_cdata(x,f->file,-1);
            base_exec_config(&(f->i), x, NULL);
        }

        /* now we should have a deliver handler registered on here */
        if(f->i.hds == NULL)
        {
            log_alert(p->host,"Dynamic initialization failed for %s",file);
            deliver_fail(p,"Unable to start handler");
            pool_free(pnew);
            xhash_zap(d->cache, match);
            return r_DONE;
        }
    }

    deliver_instance(&(f->i), p);

    return r_DONE;
}

result base_dynamic_config(instance i, xmlnode x, void *arg)
{
    dcfg d;
    struct stat m;

    if(i == NULL)
    {
        if(xmlnode_get_tag_data(x,"folder") == NULL || stat(xmlnode_get_tag_data(x,"folder"),&m) != 0 || !S_ISDIR(m.st_mode))
        {
            xmlnode_put_attrib(x, "error", "<dynamic> must contain a <folder>/path/to/folder</folder> with a valid folder in it");
            return r_ERR;
        }
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_dynamic configuring instance %s", i->id);

    if(i->type != p_NORM)
    {
        log_alert(NULL, "ERROR in instance %s: <dynamic>..</dynamic> element only allowed in service sections", i->id);
        return r_ERR;
    }

    d = pmalloco(i->p, sizeof(_dcfg));
    d->folder = xmlnode_get_tag_data(x,"folder");
    d->cache = xhash_new(j_atoi(xmlnode_get_tag_data(x,"maxfiles"),101));
    if(j_strcmp(xmlnode_get_tag_data(x,"match"),"resource") == 0)
        d->match = 1;

    register_phandler(i, o_DELIVER, base_dynamic_deliver, (void*)d);

    return r_DONE;
}

void base_dynamic(void)
{
    log_debug2(ZONE, LOGT_INIT, "base_dynamic loading...");
    register_config("dynamic",base_dynamic_config,NULL);
}
