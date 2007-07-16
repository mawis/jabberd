/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
 *
 * This file is part of jabberd14.
 *
 * This software is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

/**
 * @file xdb_file.cc
 * @brief implements storage in XML files
 *
 * @todo the xdbns attribute in the spool files should be contained in its own namespace
 *
 * The xdb_file module can be used to store XML in files - one per user. It is the traditional storage module of the jabberd14 server.
 */
 
#include <jabberd.h>
#include <dirent.h>

#define FILES_PRIME 509

/**
 * an item in the hash of cached data
 */
typedef struct cacher_struct {
    char *fname;	/**< file name of the cached file */
    xmlnode file;	/**< content of the cached file */
    int lastset;	/**< when the data has been last accessed (set or get is counted, not just set) */
} *cacher, _cacher;

/**
 * xdb_file internal data
 *
 * created for each instance of xdb_file
 */
typedef struct xdbf_struct {
    char *spool;
    instance i;
    int timeout;
    xht cache;
    int sizelimit;
    int use_hashspool;
    xht std_ns_prefixes;
} *xdbf, _xdbf;

/**
 * xhash_walker function. Called for each cached content. Decides if it has to be expired.
 *
 * @param h the xhash containing the cached content of xdb_file
 * @param key key in the hash (filename of the cached file)
 * @param data value in the hash (type is ::cacher)
 * @param arg pointer to the xdb_file internal component instance data
 */
void _xdb_file_purge(xht h, const char *key, void *data, void *arg) {
    xdbf xf = (xdbf)arg;
    cacher c = (cacher)data;
    int now = time(NULL);

    if ((now - c->lastset) > xf->timeout) {
        log_debug2(ZONE, LOGT_STORAGE, "purging %s",c->fname);
        xhash_zap(xf->cache,c->fname);
        xmlnode_free(c->file);
    }
}

/**
 * check for cached content, that has expired
 *
 * This function gets called regulary as a function, that is registered with heartbeat.
 * It removes expired content from the caching hash.
 *
 * @param arg pointer to xdb_local component instance data (type is ::xdbf)
 * @return always r_DONE
 */
result xdb_file_purge(void *arg) {
    xdbf xf = (xdbf)arg;

    log_debug2(ZONE, LOGT_STORAGE, "purge check");
    xhash_walk(xf->cache,_xdb_file_purge,(void *)xf);

    return r_DONE;
}

/* this function acts as a loader, getting xml data from a file */
/**
 * load an XML file
 *
 * @param host the host to load the file for (just for generating log messages)
 * @param fname the filename of the file, that should be loaded
 * @param cache a hash containing the cached files, that do not need to get loaded and parsed again
 * @return the loaded (or cached) ::xmlnode
 */
xmlnode xdb_file_load(char *host, char *fname, xht cache) {
    xmlnode data = NULL;
    cacher c;
    int fd;

    log_debug2(ZONE, LOGT_STORAGE, "loading %s",fname);

    /* first, check the cache */
    if ((c = static_cast<cacher>(xhash_get(cache,fname))) != NULL)
        return c->file;

    /* test the file first, so we can be more descriptive */
    fd = open(fname,O_RDONLY);
    if (fd < 0) {
	if (errno == ENOENT) {
	    log_debug2(ZONE, LOGT_STORAGE, "xdb_file failed to open file %s: %s", fname, strerror(errno));
	} else {
	    log_warn(host,"xdb_file failed to open file %s: %s",fname,strerror(errno));
	}
    } else {
        close(fd);
        data = xmlnode_file(fname);
    }

    /* if there's nothing on disk, create an empty root node */
    if (data == NULL) {
        data = xmlnode_new_tag_ns("xdb", NULL, NS_JABBERD_XDB);
    } else {
	/* did we load an old spool file? update the namespace then */
	const char *root_element_namespace = xmlnode_get_namespace(data);

	if (root_element_namespace == NULL || j_strcmp(root_element_namespace, NS_SERVER) == 0) {
	    xmlnode_change_namespace(data, NS_JABBERD_XDB);
	}
    }

    log_debug2(ZONE, LOGT_STORAGE, "caching %s",fname);
    c = static_cast<cacher>(pmalloco(xmlnode_pool(data),sizeof(_cacher)));
    c->fname = pstrdup(xmlnode_pool(data),fname);
    c->lastset = time(NULL);
    c->file = data;
    xhash_put(cache,c->fname,c);

    return data;
}

/**
 * calculate the left-most four digits of the SHA-1 hash over a filename
 *
 * @param filename the filename
 * @param digit01 where to place the first two digits (size 3 chars!)
 * @param digit23 where to place the next two digits (size 3 chars!)
 */
void _xdb_get_hashes(const char *filename, char digit01[3], char digit23[3]) {
    char hashedfilename[9];
    
    /* generate a hash over the filename */
    bzero(hashedfilename, sizeof(hashedfilename));
    bzero(digit01, sizeof(char[3]));
    bzero(digit23, sizeof(char[3]));
    crc32_r(filename, hashedfilename);
    log_debug2(ZONE, LOGT_STORAGE, "hash of %s is %s", filename, hashedfilename);
    memcpy(digit01, hashedfilename+1, 2);
    memcpy(digit23, hashedfilename+4, 2);

    return;
}

/**
 * create folders in the spool
 *
 * @param sp spool to write the result to
 * @param spoolroot the root of the spool
 * @param host the host for which the directory should be created
 * @param hash1 the hash for the first subdirectory
 * @param hash2 the second subdirectory
 * @param use_subdirs true if file should be located in subdirectories
 * @return 1 on success, 0 on failure
 */
int _xdb_gen_dirs(spool sp, const char *spoolroot, const char *host, const char *hash1, const char *hash2, int use_subdirs) {
    struct stat s;
    char *tmp;

    /* check that the root of the spool structure exists */
    if (stat(spoolroot, &s) < 0) {
	log_error(host, "the spool root directory %s does not seem to exist", spoolroot);
	return 0;
    }

    /* check and create the host-named folder */
    spooler(sp, spoolroot, "/", host, sp);
    tmp = spool_print(sp);
    if(stat(tmp,&s) < 0 && mkdir(tmp, S_IRWXU) < 0) {
	log_error(host, "could not create spool folder %s: %s", tmp, strerror(errno));
	return 0;
    }

    if (use_subdirs) {
	/* check or create the first level subdirectory */
	spooler(sp, "/", hash1, sp);
	tmp = spool_print(sp);
	if(stat(tmp,&s) < 0 && mkdir(tmp, S_IRWXU) < 0) {
	    log_error(host, "could not create spool folder %s: %s", tmp, strerror(errno));
	    return 0;
	}

	/* check or create the second level subdirectory */
	spooler(sp, "/", hash2, sp);
	tmp = spool_print(sp);
	if(stat(tmp,&s) < 0 && mkdir(tmp, S_IRWXU) < 0) {
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
char *xdb_file_full(int create, pool p, const char *spl, const char *host, const char *file, const char *ext, int use_subdirs) {
    spool sp = spool_new(p);
    char digit01[3], digit23[3];
    char *ret;
    char *filename;

    filename = spools(p, file, ".", ext, p);

    _xdb_get_hashes(filename, digit01, digit23);

    /* is the creation of the folder requested? */
    if(create) {
	if (!_xdb_gen_dirs(sp, spl, host, digit01, digit23, use_subdirs)) {
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

/**
 * handle packets (request) we get from the XML router inside of jabberd
 *
 * This function is the heart of xdb_file. It gets the requests of jabberd14, processes them, and sends replies
 *
 * @param i the ::instance data of this instance of the component
 * @param p the ::dpacket that contains the request
 * @param arg xdb_file internal data of this instance of xdb::file (type is ::xdbf)
 * @return r_DONE if the request has been handled, r_ERR on failure
 */
result xdb_file_phandler(instance i, dpacket p, void *arg) {
    char *full, *ns, *act, *match;
    char *matchpath = NULL;
    char *matchns = NULL;
    xdbf xf = (xdbf)arg;
    xmlnode file, top, data;
    int ret = 0, flag_set = 0;

    log_debug2(ZONE, LOGT_STORAGE|LOGT_DELIVER, "handling xdb request %s", xmlnode_serialize_string(p->x, xmppd::ns_decl_list(), 0));

    /* the request needs to have a defined namespace, that it is querying */
    if ((ns = xmlnode_get_attrib_ns(p->x, "ns", NULL)) == NULL)
        return r_ERR;

    /* is it a get or a set request? */
    if (j_strcmp(xmlnode_get_attrib_ns(p->x, "type", NULL), "set") == 0)
        flag_set = 1;

    /* create the filename of the responsible file */
    /* is this request specific to a user or global data? */
    if (p->id->user != NULL)
        full = xdb_file_full(flag_set, p->p, xf->spool, p->id->server, p->id->user, "xml", xf->use_hashspool);
    else
	/* global data, not data for a user: never put it inside the hash directories (use global.xdb file) */
        full = xdb_file_full(flag_set, p->p, xf->spool, p->id->server, "global", "xdb", 0);

    /* no filename? -> error */
    if (full == NULL)
        return r_ERR;

    /* load the data from disk/cache */
    top = file = xdb_file_load(p->host, full, xf->cache);

    /* if we're dealing w/ a resource, just get that element <res id='resource'/> inside <xdb/> */
    if (p->id->resource != NULL) {
	top = xmlnode_get_list_item(xmlnode_get_tags(top, spools(p->p, "res[@id='", p->id->resource, "']", p->p), xf->std_ns_prefixes), 0);
	if (top == NULL) {
            top = xmlnode_insert_tag_ns(file, "res", NULL, NS_JABBERD_XDB);
            xmlnode_put_attrib_ns(top, "id", NULL, NULL, p->id->resource);
        }
    }

    /* just query the relevant namespace */
    data = xmlnode_get_list_item(xmlnode_get_tags(top, spools(p->p, "*[@xdbns='", ns, "']", p->p), xf->std_ns_prefixes), 0);

    if (flag_set) {
	act = xmlnode_get_attrib_ns(p->x, "action", NULL);
	match = xmlnode_get_attrib_ns(p->x, "match", NULL);
	matchpath = xmlnode_get_attrib_ns(p->x, "matchpath", NULL);
	matchns = xmlnode_get_attrib_ns(p->x, "matchns", NULL);
        if (act != NULL) {
	    xht namespaces = NULL;

	    if (matchns != NULL) {
		xmlnode namespacesxml = NULL;
		namespacesxml = xmlnode_str(matchns, j_strlen(matchns));
		namespaces = xhash_from_xml(namespacesxml);
		xmlnode_free(namespacesxml);
	    }
            switch (*act) {
		case 'i': /* insert action */
		    if (data == NULL) {
			/* we're inserting into something that doesn't exist?!?!? */
			data = xmlnode_insert_tag_ns(top, "foo", NULL, ns);
			xmlnode_put_attrib_ns(data, "xdbns", NULL, NULL, ns);
		    }
		    if (matchpath != NULL) {
			xmlnode_list_item match_item = NULL;

			for (match_item = xmlnode_get_tags(data, matchpath, namespaces); match_item != NULL; match_item = match_item->next) {
			    xmlnode_hide(match_item->node);
			}
		    } else {
			xmlnode_hide(xmlnode_get_tag(data, match)); /* any match is a goner */
		    }
		    /* insert the new chunk into the existing data */
		    xmlnode_insert_tag_node(data, xmlnode_get_firstchild(p->x));
		    break;
		case 'c': /* check action */
		    if (matchpath != NULL) {
			data = xmlnode_get_list_item(xmlnode_get_tags(data, matchpath, namespaces), 0);
		    } else if(match != NULL) {
			data = xmlnode_get_tag(data, match);
		    }
		    if(j_strcmp(xmlnode_get_data(data),xmlnode_get_data(xmlnode_get_firstchild(p->x))) != 0) {
			log_debug2(ZONE, LOGT_STORAGE|LOGT_DELIVER, "xdb check action returning error to signify unsuccessful check");
			if (namespaces)
			    xhash_free(namespaces);
			return r_ERR;
		    }
		    flag_set = 0;

		    /*
		     * XXX Is there a bug here?
		     *
		     * I suspect that the check action will always return r_ERR!
		     * Up to this point the ret variable has not been changed, and if
		     * we arrived here I cannot imagine how it should be changed afterwards.
		     * This means that the function will return r_ERR too.
		     * I expect this is a bug and something like "ret = 1;" should be inserted
		     * at this point.
		     *
		     * The problem is that I am not completely sure what the check action is
		     * supposed to do. What I imagine is:
		     * It is intended to compare the content of xdb with the content of the
		     * xdb request and return r_ERR if it is different and r_DONE if it
		     * is the same.
		     *
		     * It is only used in jsm/modules/mod_auth_plain.c in the function
		     * mod_auth_plain_jane(...) function. At this function there is already
		     * a check if the password is the same some lines above ... so it
		     * would make no sence to call the check action if it does what I said
		     * above as it would be always result in being different - in which
		     * case it is no surprize that we have no problem, that this function
		     * always returns r_ERR (which would signal that it's different too).
		     *
		     * It should be checked if the xdb_act(...) in mod_auth_plain_jane(...)
		     * is needed. If it isn't, we could remove the check action from
		     * xdb completely.
		     *
		     * Please see also:
		     * http://web.archive.org/web/20020601233959/http://jabberd.jabberstudio.org/1.4/142changelog.html
		     * In that case it seems to be a bug here ...
		     */
		    break;
		default:
		    log_warn(p->host, "unable to handle unknown xdb action '%s'", act);
		    return r_ERR;
            }
	    if (namespaces)
		xhash_free(namespaces);
        } else {
            if (data != NULL)
                xmlnode_hide(data);

            /* copy the new data into file */
            data = xmlnode_insert_tag_node(top, xmlnode_get_firstchild(p->x));
            xmlnode_put_attrib_ns(data, "xdbns", NULL, NULL, ns);
        }

        /* save the file if we still want to */
	if (flag_set) {
	    int tmp = xmlnode2file_limited(full,file,xf->sizelimit);
	    if (tmp == 0)
		log_notice(p->id->server,"xdb request failed, due to the size limit of %i to file %s", xf->sizelimit, full);
	    else if (tmp < 0)
		log_error(p->id->server,"xdb request failed, unable to save to file %s",full);
	    else
		ret = 1;
	}
    } else {
        /* a get always returns, data or not */
        ret = 1;

        if (data != NULL) {
	    /* cool, send em back a copy of the data */
            xmlnode_hide_attrib_ns(xmlnode_insert_tag_node(p->x, data), "xdbns", NULL);
        }
    }

    if (ret) {
        xmlnode_put_attrib_ns(p->x, "type", NULL, NULL, "result");
        xmlnode_put_attrib_ns(p->x, "to", NULL, NULL, xmlnode_get_attrib(p->x,"from"));
        xmlnode_put_attrib_ns(p->x, "from", NULL, NULL, jid_full(p->id));
        deliver(dpacket_new(p->x), NULL); /* dpacket_new() shouldn't ever return NULL */

        /* remove the cache'd item if it was a set or we're not configured to cache */
        if (xf->timeout == 0 || flag_set) {
            log_debug2(ZONE, LOGT_STORAGE, "decaching %s",full);
            xhash_zap(xf->cache,full);
            xmlnode_free(file);
        }
        return r_DONE;
    } else {
        return r_ERR;
    }
}

/**
 * cleanup xdb_file on server shutdown
 *
 * @param arg the instance configuration of this component
 */
void xdb_file_cleanup(void *arg) {
    xdbf xf = (xdbf)arg;
    xhash_free(xf->cache);
}

/**
 * convert a spool directory for a given host from the old format
 * to the new one which distributes the files over several subdirs
 *
 * @param p the memory pool we can use
 * @param spoolroot the root folder of the spool
 * @param host the host for which we should try to convert
 */
void _xdb_convert_hostspool(pool p, const char *spoolroot, char *host) {
    DIR *sdir;
    struct dirent *dent;
    char digit01[3], digit23[3];
    char *hostspool;

    /* get the dir location */
    hostspool = spools(p, spoolroot, "/", host, p);

    log_notice(host, "trying to convert spool %s (this may take some time)", hostspool);

    /* we have to convert the spool */
    sdir = opendir(hostspool);
    if (sdir == NULL) {
	log_error(host, "failed to open directory %s for conversion: %s", hostspool, strerror(errno));
	return;
    }

    while ((dent = readdir(sdir))!=NULL) {
	char *str_ptr;
	size_t filenamelength = strlen(dent->d_name);

	if (filenamelength<4)
	    continue;

	str_ptr = (dent->d_name)+filenamelength-4;

	/* do we have to convert this file? */
	if (j_strcmp(str_ptr, ".xml") == 0) {
	    char *oldname, *newname;
	    _xdb_get_hashes(dent->d_name, digit01, digit23);

	    oldname = spools(p, hostspool, "/", dent->d_name, p);
	    newname = spools(p, hostspool, "/", digit01, "/", digit23, "/", dent->d_name, p);

	    if (!_xdb_gen_dirs(spool_new(p), spoolroot, host, digit01, digit23, 1))
		log_error(host, "failed to create necessary directory for conversion");
	    else if (rename(oldname, newname) < 0)
		log_error(host, "failed to move %s to %s while converting spool: %s", oldname, newname, strerror(errno));
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
void xdb_convert_spool(const char *spoolroot) {
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
    if (stat(flagfile, &s) == 0) {
	log_debug2(ZONE, LOGT_STORAGE, "there is already a new hashspool");
	pool_free(p);
	return;
    }

    /* what is in this directory? */
    sdir = opendir(spoolroot);

    if (sdir == NULL) {
	pool_free(p);
	return;
    }

    while ((dent = readdir(sdir)) != NULL) {
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
    if (flagfileh != NULL) {
	fwrite("Please do not delete this file.\n", 1, 32, flagfileh);
	fclose(flagfileh);
    }

    /* cleanup */
    pool_free(p);
}

/**
 * load the xdb_file module
 *
 * This gets called by the component loader of jabberd. It configures the instance,
 * and registers all callbacks with jabberd.
 *
 * @param i ::instance data of this component
 * @param x ::xmlnode containing the loading information
 */
extern "C" void xdb_file(instance i, xmlnode x) {
    char *spl = NULL;
    xmlnode config = NULL;
    xmlnode node_ptr = NULL;
    xdbcache xc = NULL;
    xdbf xf = NULL;
    int timeout = 3600; /* defaults to timeout in 3600 seconds */
    int sizelimit = 500000; /* defaults to 500000 bytes */

    log_debug2(ZONE, LOGT_INIT, "xdb_file loading");

    /* get the configuration of this component */
    xc = xdb_cache(i);
    config = xdb_get(xc, jid_new(xmlnode_pool(x),"config@-internal"),"jabber:config:xdb_file");

    /* define standard namespace prefixes */
    xf = static_cast<xdbf>(pmalloco(i->p,sizeof(_xdbf)));
    xf->std_ns_prefixes = xhash_new(7);
    xhash_put(xf->std_ns_prefixes, "", const_cast<char*>(NS_JABBERD_XDB));
    xhash_put(xf->std_ns_prefixes, "conf", const_cast<char*>(NS_JABBERD_CONFIG_XDBFILE));

    /* where to store all the files (base directory) */
    spl = xmlnode_get_list_item_data(xmlnode_get_tags(config, "conf:spool", xf->std_ns_prefixes), 0);
    if (spl == NULL) {
        log_error(i->id,"xdb_file: No filesystem spool location configured: %s", xmlnode_serialize_string(config, xmppd::ns_decl_list(), 0));
        return;
    }

    /* maximum size of a user file */
    node_ptr = xmlnode_get_list_item(xmlnode_get_tags(config, "conf:sizelimit", xf->std_ns_prefixes), 0);
    if (node_ptr != NULL) {
	/* default (0): disable file size limit */
	sizelimit = j_atoi(xmlnode_get_data(node_ptr), 0);
    }

    /* is there a caching timeout? */
    node_ptr = xmlnode_get_list_item(xmlnode_get_tags(config, "conf:timeout", xf->std_ns_prefixes), 0);
    if (node_ptr != NULL) {
	/* default (-1): disable timeout */
	timeout = j_atoi(xmlnode_get_data(node_ptr), -1);
    }

    /* keep our configuration in an instance of _xdbf, allocate memory for it */
    xf->spool = pstrdup(i->p,spl);
    xf->timeout = timeout;
    xf->sizelimit = sizelimit;
    xf->i = i;
    xf->cache = xhash_new(j_atoi(xmlnode_get_list_item_data(xmlnode_get_tags(config, "conf:maxfiles", xf->std_ns_prefixes), 0), FILES_PRIME));
    xf->use_hashspool = xmlnode_get_list_item(xmlnode_get_tags(config, "conf:use_hierarchical_spool", xf->std_ns_prefixes), 0) ? 1 : 0;

    /* if we are using the hashed directory layout, we might have to convert an existing spool */
    if (xf->use_hashspool)
	xdb_convert_spool(spl);

    /* register our callback, that gets the requests passed to */
    register_phandler(i, o_DELIVER, xdb_file_phandler, (void *)xf);

    /* register a regulary call of xdb_file_purge if caching is enabled */
    if (timeout > 0) /* 0 is expired immediately, -1 is cached forever */
        register_beat(timeout, xdb_file_purge, (void *)xf);

    /* we do not need this xmlnode anymore */
    xmlnode_free(config);

    /* register xdb_file_cleanup() to get called on shutdown */
    pool_cleanup(i->p, xdb_file_cleanup, (void*)xf);
}
