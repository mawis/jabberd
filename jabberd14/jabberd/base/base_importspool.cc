/*
 * Copyrights
 * 
 * Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file base_importspool.cc
 * @brief base module base_importspool: reads a filespool and sets all contained data using the configured xdb handler.
 *
 * This module is used internally by jabberd14 if you request it to import data from an existing filespool.
 */

#include "jabberd.h"
#include <dirent.h>

/**
 * hold data this instance of base_dir needs to be passed as void* pointer
 */
typedef struct base_importspool_struct {
    instance	id;		/**< the instance this base_dir is running in */
    char*	importspool;	/**< the base directory of the spool */
    xdbcache	xc;		/**< xdbcache to use */
    xht		std_namespace_prefixes;	/**< namespace prefixes used by this base handler */
    time_t	importstart;	/**< time when importing data has started */
} *base_importspool_st, _base_importspool_st;

/**
 * processing outgoing stanzas
 *
 * bounce them
 */
static result base_importspool_deliver(instance id, dpacket p, void *arg) {
    deliver_fail(p, messages_get(xmlnode_get_lang(p->x), N_("This is no valid destination.")));
    return r_DONE;
}

/**
 * check if a character is a hex digit
 *
 * @param c the character
 * @return 1 if a hex digit, 0 else
 */
static int is_hexdigit(char c) {
    if (c>='0' && c<='9')
	return 1;
    if (c>='A' && c<='F')
	return 1;
    if (c>='a' && c<='f')
	return 1;
    return 0;
}

/**
 * show some progress to the user while importing data
 *
 * @param steps_done how many steps of the expected number of steps have been done
 * @param needed_steps how many steps are expected to be needed
 * @param yield_counter used to check when progress should be updated and when we are cooperative
 */
static void print_progress(int steps_done, int needed_steps, int* yield_counter, time_t importstart) {
    int bar_done = 0;
    int i = 0;
    int expected_time_left = 0;
    if (--(*yield_counter) > 0)
	return;

    *yield_counter = 10;


    if (needed_steps > 0) {
	time_t now = time(NULL);
	time_t over = now-importstart;

	bar_done = 40 * steps_done / needed_steps;
	if (over > 10) {
	    expected_time_left = (over * needed_steps) / steps_done - over;
	}
    } else {
	bar_done = 40;
    }

    printf("\rImport: |");
    for (i = 0; i<40; i++) {
	printf(i<bar_done ? "#" : "-");
    }
    printf("|");

    if (needed_steps == steps_done) {
	printf(" Done.                  ");
    } else if (expected_time_left > 0) {
	printf(" Remaining: ");
	if (expected_time_left > 3600) {
	    printf("%d h, ", expected_time_left/3600);
	    expected_time_left %= 3600;
	}
	printf("%02d min, ", expected_time_left/60);
	expected_time_left %= 60;
	printf("%02d s        ", expected_time_left);
    } else {
	printf("                        ");
    }

    printf("\r");

    pth_yield(NULL);
}

/**
 * import a single file
 *
 */
static void import_file(instance i, xdbcache xc, xht std_namespace_prefixes, const char* filename, const char* domain, const char* user) {
    xmlnode spoolfile = NULL;
    xmlnode data_element = NULL;
    pool p = NULL;
    jid userid = NULL;

    /* read the spool file */
    spoolfile = xmlnode_file(filename);
    if (spoolfile == NULL) {
	log_debug2(ZONE, LOGT_IO, "spoolfile could not be read: %s", filename);
	return;
    }

    /* create user's JID */
    p = pool_new();
    userid = jid_new(p, domain);
    jid_set(userid, user, JID_USER);
    if (userid == NULL || userid->user == NULL) {
	log_debug2(ZONE, LOGT_IO, "invalid user: %s@%s - skipping", user, domain);
	xmlnode_free(spoolfile);
	pool_free(p);
	return;
    }

    /* iterate on the data in the spoolfile */
    for (data_element = xmlnode_get_firstchild(spoolfile); data_element != NULL; data_element = xmlnode_get_nextsibling(data_element)) {
	const char* ns = NULL;

	if (data_element->type != NTYPE_TAG)
	    continue;

	/* handle data dependant on namespace */
	ns = xmlnode_get_namespace(data_element);
	if (j_strcmp(ns, NS_LAST) == 0
		|| j_strcmp(ns, NS_AUTH) == 0
		|| j_strcmp(ns, NS_JABBERD_STOREDPRESENCE) == 0
		|| j_strcmp(ns, NS_REGISTER) == 0
		|| j_strcmp(ns, NS_ROSTER) == 0
		|| j_strcmp(ns, NS_BROWSE) == 0
		|| j_strcmp(ns, NS_VCARD) == 0) {
	    /* this is data we can just set to the configured storage */
	    xdb_set(xc, userid, ns, data_element);
	    continue;
	}

	/* some data that is accessed with xdb_act ... */

	/* stored subscription requests */
	if (j_strcmp(ns, NS_JABBERD_STOREDREQUEST) == 0) {
	    xmlnode request = NULL;

	    /* insert each request individually */
	    for (request = xmlnode_get_firstchild(data_element); request != NULL; request = xmlnode_get_nextsibling(request)) {
		if (request->type != NTYPE_TAG)
		    continue;

		xdb_act_path(xc, userid, NS_JABBERD_STOREDREQUEST, "insert", spools(p, "presence[@from='", xmlnode_get_attrib_ns(request, "from", NULL), "']", p), std_namespace_prefixes, request);
	    }
	    continue;
	}

	/* offline messages */
	if (j_strcmp(ns, NS_OFFLINE) == 0) {
	    xmlnode message = NULL;

	    /* insert each offline message individually */
	    for (message = xmlnode_get_firstchild(data_element); message != NULL; message = xmlnode_get_nextsibling(message)) {
		if (message->type != NTYPE_TAG)
		    continue;

		xdb_act_path(xc, userid, NS_OFFLINE, "insert", NULL, NULL, message);
	    }
	    continue;
	}

	/* message history */
	if (j_strcmp(ns, NS_JABBERD_HISTORY) == 0) {
	    xmlnode message = NULL;

	    /* insert each offline message individually */
	    for (message = xmlnode_get_firstchild(data_element); message != NULL; message = xmlnode_get_nextsibling(message)) {
		if (message->type != NTYPE_TAG)
		    continue;

		xdb_act_path(xc, userid, NS_JABBERD_HISTORY, "insert", NULL, NULL, message);
	    }
	    continue;
	}

	/* private data */
	if (j_strcmp(ns, NS_PRIVATE) == 0) {
	    xmlnode item = NULL;

	    /* insert each offline message individually */
	    for (item = xmlnode_get_firstchild(data_element); item != NULL; item = xmlnode_get_nextsibling(item)) {
		if (item->type != NTYPE_TAG)
		    continue;

		xdb_act_path(xc, userid, NS_PRIVATE, "insert", spools(p, "private:query[@jabberd:ns='", xmlnode_get_namespace(item), "']", p), std_namespace_prefixes, item);
	    }
	    continue;
	}

	/* privacy lists */
	if (j_strcmp(ns, NS_PRIVACY) == 0) {
	    xmlnode list = NULL;

	    /* insert each offline message individually */
	    for (list = xmlnode_get_firstchild(data_element); list != NULL; list = xmlnode_get_nextsibling(list)) {
		if (list->type != NTYPE_TAG)
		    continue;

		xdb_act_path(xc, userid, NS_PRIVACY, "insert", spools(p, "privacy:list[@name='", xmlnode_get_attrib_ns(list, "name", NULL), "']", p), std_namespace_prefixes, list);

	    }
	    continue;
	}

	/* ignore privacy namespace lists ... they are not used anymore */
	if (j_strcmp(ns, NS_XDBNSLIST) == 0)
	    continue;

	/* all other data gets stored in the private namespace */
	xdb_act_path(xc, userid, NS_PRIVATE, "insert", spools(p, "private:query[@jabberd:ns='", xmlnode_get_namespace(data_element), "']", p), std_namespace_prefixes, data_element);
    }

    /* free memory */
    xmlnode_free(spoolfile);
    pool_free(p);
}

/**
 * thread that does the actual import of data from the filespool
 *
 * @param arg pointer to the configuration data
 * @return allways NULL
 */
static void *base_importspool_worker(void *arg) {
    DIR* basedir = NULL;
    struct dirent* basedir_entry = NULL;
    base_importspool_st conf_data = (base_importspool_st)arg;
    int needed_steps = 0;
    int steps_done = 0;
    int yield_counter = 0;

    /* sanity check */
    if (conf_data == NULL) {
	return NULL;
    }

    /* show a first sign of life */
    printf("Importing filespool: %s\n", conf_data->importspool);

    /* open the spool directory */
    basedir = opendir(conf_data->importspool);
    if (basedir == NULL) {
	printf("Could not open this directory: %s\nNot importing anything ...\n", strerror(errno));
	return NULL;
    }

    /* tell what we are doing */
    printf("Checking which directories we have to import ...\n");

    /* iterate the directory */
    while (basedir_entry = readdir(basedir)) {
	DIR* domaindir = NULL;
	struct dirent* domaindir_entry = NULL;
	char cur_domaindir[1024];

	/* skip hidden directory entries */
	if (basedir_entry->d_name[0] == '.')
	    continue;

	/* skip files and directories that are not readable */
	snprintf(cur_domaindir, sizeof(cur_domaindir), "%s/%s", conf_data->importspool, basedir_entry->d_name);
	domaindir = opendir(cur_domaindir);
	if (domaindir == NULL)
	    continue;

	/* (roughtly) calculating the number of steps we need for this directory */
	while (domaindir_entry = readdir(domaindir)) {
	    needed_steps++;
	}

	printf("%s\n", basedir_entry->d_name);

	closedir(domaindir);

	/* being cooperative */
	pth_yield(NULL);
    }

    /* tell what we are doing */
    printf("Okay ... starting to import data ...\n");

    /* rewind directory */
    rewinddir(basedir);

    /* iterate again */
    while (basedir_entry = readdir(basedir)) {
	DIR* domaindir = NULL;
	struct dirent* domaindir_entry = NULL;
	char cur_domaindir[1024];

	/* skip hidden directory entries */
	if (basedir_entry->d_name[0] == '.')
	    continue;

	/* skip files and directories that are not readable */
	snprintf(cur_domaindir, sizeof(cur_domaindir), "%s/%s", conf_data->importspool, basedir_entry->d_name);
	domaindir = opendir(cur_domaindir);
	if (domaindir == NULL)
	    continue;

	/* iterate the files in the domain directory */
	while (domaindir_entry = readdir(domaindir)) {
	    steps_done++;

	    /* hashspool entry? */
	    if (strlen(domaindir_entry->d_name) == 2) {
		DIR* domainsubdir1 = NULL;
		struct dirent* domainsubdir1_entry = NULL;
		char cur_domainsubdir1[1024];

		/* only if two hex digits */
		if (!is_hexdigit(domaindir_entry->d_name[0]) || !is_hexdigit(domaindir_entry->d_name[1]))
		    continue;

		/* open the first subdir of the domaindir */
		snprintf(cur_domainsubdir1, sizeof(cur_domainsubdir1), "%s/%s", cur_domaindir, domaindir_entry->d_name);
		domainsubdir1 = opendir(cur_domainsubdir1);
		if (domainsubdir1 == NULL)
		    continue;

		/* iterate the entries in the first subdirectory of a domain directory (should be second level subdirs) */
		while (domainsubdir1_entry = readdir(domainsubdir1)) {
		    DIR* domainsubdir2 = NULL;
		    struct dirent* domainsubdir2_entry = NULL;
		    char cur_domainsubdir2[1024];

		    /* check if it is a second level subdir */
		    if (!is_hexdigit(domainsubdir1_entry->d_name[0]) || !is_hexdigit(domainsubdir1_entry->d_name[1]) || domainsubdir1_entry->d_name[2] != 0)
			continue;

		    /* open the second subdir of the domaindir */
		    snprintf(cur_domainsubdir2, sizeof(cur_domainsubdir2), "%s/%s", cur_domainsubdir1, domainsubdir1_entry->d_name);
		    domainsubdir2 = opendir(cur_domainsubdir2);
		    if (domainsubdir2 == NULL)
			continue;

		    /* iterate the entries in the second subdirectory of a domain directory (should contain the spool files) */
		    while (domainsubdir2_entry = readdir(domainsubdir2)) {
			if (strlen(domainsubdir2_entry->d_name) <= 4)
			    continue;

			if (strcmp(domainsubdir2_entry->d_name + strlen(domainsubdir2_entry->d_name) - 4, ".xml") == 0) {
			    char filename[2048];
			    char user[1028];

			    /* import this file */
			    snprintf(filename, sizeof(filename), "%s/%s", cur_domainsubdir2, domainsubdir2_entry->d_name);
			    snprintf(user, sizeof(user), "%s", domainsubdir2_entry->d_name);
			    user[strlen(user)-4] = 0;
			    import_file(conf_data->id, conf_data->xc, conf_data->std_namespace_prefixes, filename, basedir_entry->d_name, user);

			    /* update output */
			    print_progress(steps_done, needed_steps, &yield_counter, conf_data->importstart);
			}
		    }

		    closedir(domainsubdir2);
		}

		closedir(domainsubdir1);
		continue;
	    }

	    /* no hashspool entry, check if it is an XML file */
	    if (strlen(domaindir_entry->d_name) > 4) {
		if (strcmp(domaindir_entry->d_name + strlen(domaindir_entry->d_name) - 4, ".xml") == 0) {
		    char filename[2048];
		    char user[1028];

		    /* import this file */
		    snprintf(filename, sizeof(filename), "%s/%s", cur_domaindir, domaindir_entry->d_name);
		    snprintf(user, sizeof(user), "%s", domaindir_entry->d_name);
		    user[strlen(user)-4] = 0;
		    import_file(conf_data->id, conf_data->xc, conf_data->std_namespace_prefixes, filename, basedir_entry->d_name, user);

		    /* update output */
		    print_progress(steps_done, needed_steps, &yield_counter, conf_data->importstart);
		}
	    }
	}

	closedir(domaindir);
    }

    /* tell what we are doing */
    yield_counter = 0;
    print_progress(steps_done, needed_steps, &yield_counter, conf_data->importstart);
    printf("\nFinished importing data ...\n");

    /* close the spool directory */
    closedir(basedir);
    return NULL;
}

/**
 * delete the std_namespace_prefixes hash, when instance is freed
 *
 * @param arg xht pointer to the std_namespace_prefixes hash
 */
static void free_ns_prefixes(void *arg) {
    xht std_namespace_prefixes = (xht)arg;

    if (std_namespace_prefixes != NULL)
	xhash_free(std_namespace_prefixes);
}

/**
 * configuration handling
 *
 * @param id the instance to handle the configuration for, NULL for only validating the configuration
 * @param x the <importspool/> element that has to be processed
 * @param arg unused/ignored
 * @return r_ERR on error, r_PASS on success
 */
static result base_importspool_config(instance id, xmlnode x, void *arg) {
    base_importspool_st conf_data = NULL;
    
    /* nothing has to be done for configuration validation */
    if (id == NULL) {
        return r_PASS;
    }

    log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "base_importspool configuring instance %s", id->id);

    /* process configuration */
    conf_data = static_cast<base_importspool_st>(pmalloc(id->p, sizeof(_base_importspool_st)));
    conf_data->id = id;
    conf_data->importspool = xmlnode_get_data(x);
    conf_data->xc = xdb_cache(id);
    conf_data->importstart = time(NULL);
    conf_data->std_namespace_prefixes = xhash_new(5);
    xhash_put(conf_data->std_namespace_prefixes, "", const_cast<char*>(NS_SERVER));
    xhash_put(conf_data->std_namespace_prefixes, "private", const_cast<char*>(NS_PRIVATE));
    xhash_put(conf_data->std_namespace_prefixes, "jabberd", const_cast<char*>(NS_JABBERD_WRAPPER));
    xhash_put(conf_data->std_namespace_prefixes, "privacy", const_cast<char*>(NS_PRIVACY));
    pool_cleanup(id->p, free_ns_prefixes, conf_data->std_namespace_prefixes);

    /* start thread that does the import */
    pth_spawn(PTH_ATTR_DEFAULT, base_importspool_worker, conf_data);

    return r_DONE;
}

/**
 * load the base_importspool base module by registering a configuration handler for &lt;importspool/&gt;
 *
 * @param p memory pool used to register the configuration handler (must be available for the livetime of jabberd)
 */
void base_importspool(pool p) {
    log_debug2(ZONE, LOGT_INIT, "base_importspool loading...");
    register_config(p, "importspool", base_importspool_config, NULL);
}
