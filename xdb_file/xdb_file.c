/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * --------------------------------------------------------------------------*/
 
#include <jabberd.h>
#include <dirent.h>

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
    int sizelimit;
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

/**
 * calculate the left-most four digits of the SHA-1 hash over a filename
 *
 * @param filename the filename
 * @param digit01 where to place the first two digits (size 3 chars!)
 * @param digit23 where to place the next two digits (size 3 chars!)
 */
void _xdb_get_hashes(const char *filename, char digit01[3], char digit23[3])
{
    char hashedfilename[9];
    
    /* generate a hash over the filename */
    bzero(hashedfilename, sizeof(hashedfilename));
    bzero(digit01, sizeof(digit01));
    bzero(digit23, sizeof(digit23));
    crc32_r(filename, hashedfilename);
    log_debug(ZONE, "hash of %s is %s", filename, hashedfilename);
    memcpy(digit01, hashedfilename+1, 2);
    memcpy(digit23, hashedfilename+4, 2);

    return;
}

/**
 * create folders in the spool
 *
 * @param spoolroot the root of the spool
 * @param host the host for which the directory should be created
 * @param hash1 the hash for the first subdirectory
 * @param hash2 the second subdirectory
 * @param use_subdirs true if file should be located in subdirectories
 * @return 1 on success, 0 on failure
 */
int _xdb_gen_dirs(spool sp, const char *spoolroot, char *host, const char *hash1, const char *hash2, int use_subdirs)
{
    struct stat s;
    char *tmp;

    /* check that the root of the spool structure exists */
    if (stat(spoolroot, &s) < 0)
    {
	log_error(host, "the spool root directory %s does not seem to exist", spoolroot);
	return 0;
    }

    /* check and create the host-named folder */
    spooler(sp, spoolroot, "/", host, sp);
    tmp = spool_print(sp);
    if(stat(tmp,&s) < 0 && mkdir(tmp, S_IRWXU) < 0)
    {
	log_error(host, "could not create spool folder %s: %s", tmp, strerror(errno));
	return 0;
    }

    if (use_subdirs)
    {
	/* check or create the first level subdirectory */
	spooler(sp, "/", hash1, sp);
	tmp = spool_print(sp);
	if(stat(tmp,&s) < 0 && mkdir(tmp, S_IRWXU) < 0)
	{
	    log_error(host, "could not create spool folder %s: %s", tmp, strerror(errno));
	    return 0;
	}

	/* check or create the second level subdirectory */
	spooler(sp, "/", hash2, sp);
	tmp = spool_print(sp);
	if(stat(tmp,&s) < 0 && mkdir(tmp, S_IRWXU) < 0)
	{
	    log_error(host, "could not create spool folder %s: %s", tmp, strerror(errno));
	    return 0;
	}
    }

    return 1;
}

/**
 * utility that generates the filename for a spool file
 *
 * @param create true if the directory for the file should be generated
 * @param p pool that should be used for string operations
 * @param spl location for the spool root
 * @param host host of the xdb request (the 'spool folder')
 * @param file the basename of the xdb file
 * @param ext the extension for the xdb file
 * @param use_subdirs true if file should be located in subdirectories
 * @return concatenated string of the form spl+"/"+somehashes+"/"+file+"."+ext
 */
char *xdb_file_full(int create, pool p, char *spl, char *host, char *file, char *ext, int use_subdirs)
{
    spool sp = spool_new(p);
    char digit01[3], digit23[3];
    char *ret;
    char *filename;

    filename = spools(p, file, ".", ext, p);

    _xdb_get_hashes(filename, digit01, digit23);

    /* is the creation of the folder requested? */
    if(create)
    {
	if (!_xdb_gen_dirs(sp, spl, host, digit01, digit23, use_subdirs))
	{
	    log_error(host, "xdb request failed, necessary directory was not created");
	    return NULL;
	}
    } else if (use_subdirs) {
	spooler(sp, spl, "/", host, "/", digit01, "/", digit23, sp);
    } else {
	spooler(sp, spl, "/", host, sp);
    }

    /* full path to file */
    spooler(sp,"/",filename, sp);
    ret = spool_print(sp);

    return ret;
}

/* the callback to handle xdb packets */
result xdb_file_phandler(instance i, dpacket p, void *arg)
{
    char *full, *ns, *act, *match;
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
        full = xdb_file_full(flag_set, p->p, xf->spool, p->id->server, p->id->user, "xml", 1);
    else
        full = xdb_file_full(flag_set, p->p, xf->spool, p->id->server, "global", "xdb", 0);

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
	act = xmlnode_get_attrib(p->x,"action");
	match = xmlnode_get_attrib(p->x,"match");
        if(act != NULL)
        {
            switch(*act)
            {
            case 'i': /* insert action */
                if(data == NULL)
                { /* we're inserting into something that doesn't exist?!?!? */
                    data = xmlnode_insert_tag(top,"foo");
                    xmlnode_put_attrib(data,"xdbns",ns);
                    xmlnode_put_attrib(data,"xmlns",ns); /* should have a top-level xmlns attrib */
                }
                xmlnode_hide(xmlnode_get_tag(data,match)); /* any match is a goner */
                /* insert the new chunk into the existing data */
                xmlnode_insert_tag_node(data, xmlnode_get_firstchild(p->x));
                break;
            case 'c': /* check action */
                if(match != NULL)
                    data = xmlnode_get_tag(data,match);
                if(j_strcmp(xmlnode_get_data(data),xmlnode_get_data(xmlnode_get_firstchild(p->x))) != 0)
                {
                    log_debug(ZONE,"xdb check action returning error to signify unsuccessful check");
                    return r_ERR;
                }
                flag_set = 0;
                break;
            default:
                log_warn("xdb_file","unable to handle unknown xdb action '%s'",act);
                return r_ERR;
            }
        }else{
            if(data != NULL)
                xmlnode_hide(data);

            /* copy the new data into file */
            data = xmlnode_insert_tag_node(top, xmlnode_get_firstchild(p->x));
            xmlnode_put_attrib(data,"xdbns",ns);
        }

        /* save the file if we still want to */
	if (flag_set)
	{
	    int tmp = xmlnode2file_limited(full,file,xf->sizelimit);
	    if (tmp == 0)
		log_notice(p->id->server,"xdb request failed, due to the size limit of %i to file %s", xf->sizelimit, full);
	    else if (tmp < 0)
		log_error(p->id->server,"xdb request failed, unable to save to file %s",full);
	    else
		ret = 1;
	}
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

/**
 * convert a spool directory for a given host from the old format
 * to the new one which distributes the files over several subdirs
 *
 * @param p the memory pool we can use
 * @param spoolroot the root folder of the spool
 * @param host the host for which we should try to convert
 */
void _xdb_convert_hostspool(pool p, const char *spoolroot, char *host)
{
    DIR *sdir;
    struct dirent *dent;
    char digit01[3], digit23[3];
    char *hostspool;

    /* get the dir location */
    hostspool = spools(p, spoolroot, "/", host, p);

    log_notice(ZONE, "trying to convert spool %s (this may take some time)", hostspool);

    /* we have to convert the spool */
    sdir = opendir(hostspool);
    if (sdir == NULL)
    {
	log_error("xdb_file", "failed to open directory %s for conversion: %s", hostspool, strerror(errno));
	return;
    }

    while ((dent = readdir(sdir))!=NULL)
    {
	char *str_ptr;
	size_t filenamelength = strlen(dent->d_name);

	if (filenamelength<4)
	    continue;

	str_ptr = (dent->d_name)+filenamelength-4;

	/* do we have to convert this file? */
	if (j_strcmp(str_ptr, ".xml") == 0)
	{
	    char *oldname, *newname;
	    _xdb_get_hashes(dent->d_name, digit01, digit23);

	    oldname = spools(p, hostspool, "/", dent->d_name, p);
	    newname = spools(p, hostspool, "/", digit01, "/", digit23, "/", dent->d_name, p);

	    if (!_xdb_gen_dirs(spool_new(p), spoolroot, host, digit01, digit23, 1))
		log_error("xdb_file", "failed to create necessary directory for conversion");
	    else if (rename(oldname, newname) < 0)
		log_error("xdb_file", "failed to move %s to %s while converting spool: %s", oldname, newname, strerror(errno));
	}
    }

    /* close the directory */
    closedir(sdir);
}

/**
 * convert a spool directory from the old format to the new one
 * which distributes the files over several subdirs
 *
 * @param spoolroot the root folder of the spool
 */
void _xdb_convert_spool(const char *spoolroot)
{
    DIR *sdir;
    struct dirent *dent;
    pool p;
    char *flagfile;
    struct stat s;
    FILE *flagfileh;

    /* use our own memory pool */
    p = pool_new();

    /* check if we already converted this spool */
    flagfile = spools(p, spoolroot, "/.hashspool", p);
    if (stat(flagfile, &s) == 0)
    {
	log_debug(ZONE,"there is already a new hashspool");
	pool_free(p);
	return;
    }

    /* what is in this directory? */
    sdir = opendir(spoolroot);

    if (sdir == NULL)
    {
	pool_free(p);
	return;
    }

    while ((dent = readdir(sdir)) != NULL)
    {
	struct stat s;
	char *dirname = spools(p, spoolroot, "/", dent->d_name, p);

	if (stat(dirname, &s)<0)
	    continue;

	/* we only care about directories */
	if (!S_ISDIR(s.st_mode))
	    continue;

	if (dent->d_name[0]!='\0' && dent->d_name[0]!='.')
	    _xdb_convert_hostspool(p, spoolroot, dent->d_name);
    }
    closedir(sdir);

    /* write the flag that we converted the spool */
    flagfileh = fopen(flagfile, "w");
    if (flagfileh != NULL)
    {
	fwrite("Please do not delete this file.\n", 1, 32, flagfileh);
	fclose(flagfileh);
    }

    /* cleanup */
    pool_free(p);
}

void xdb_file(instance i, xmlnode x)
{
    char *spl, *to;
    xmlnode config;
    xdbcache xc;
    xdbf xf;
    int timeout = -1; /* defaults to timeout forever */
    int sizelimit = 0; /* defaults to no size limit */

    log_debug(ZONE,"xdb_file loading");

    xc = xdb_cache(i);
    config = xdb_get(xc, jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:xdb_file");

    spl = xmlnode_get_tag_data(config,"spool");
    if(spl == NULL)
    {
        log_error(NULL,"xdb_file: No filesystem spool location configured");
        return;
    }

    _xdb_convert_spool(spl);

    sizelimit = j_atoi(xmlnode_get_tag_data(config, "sizelimit"), 0);
    
    to = xmlnode_get_tag_data(config,"timeout");
    if(to != NULL)
        timeout = atoi(to);

    xf = pmalloco(i->p,sizeof(_xdbf));
    xf->spool = pstrdup(i->p,spl);
    xf->timeout = timeout;
    xf->sizelimit = sizelimit;
    xf->i = i;
    xf->cache = ghash_create(j_atoi(xmlnode_get_tag_data(config,"maxfiles"),FILES_PRIME),(KEYHASHFUNC)str_hash_code,(KEYCOMPAREFUNC)j_strcmp);

    register_phandler(i, o_DELIVER, xdb_file_phandler, (void *)xf);
    if(timeout > 0) /* 0 is expired immediately, -1 is cached forever */
        register_beat(timeout, xdb_file_purge, (void *)xf);

    xmlnode_free(config);
    pool_cleanup(i->p, xdb_file_cleanup, (void*)xf);
}

