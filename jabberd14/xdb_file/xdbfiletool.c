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
#include <dlfcn.h>
#include <popt.h>

/**
 * @file xdbfilepath.c
 * @brief small utility that prints out the location of a spool file inside the root spool directory
 */

/* XXX very big hack, to be able to link against libjabberd
 *     we have to remove these globals (or at least move them
 *     inside the library
 */
xht debug__zones;

/* end of hack */

/* handle of the shared object */
void *so_h = NULL;

/* functions in libjabberdxdbfile.so used */
char* (*xdb_file_full)(int create, pool p, const char *spl, char *host, const char *file, char *ext, int use_subdirs);
void (*xdb_convert_spool)(const char *spoolroot);
xmlnode (*xdb_file_load)(char *host, char *fname, xht cache);

int main(int argc, const char **argv) {
    pool p;
    char *host = NULL;
    char *error = NULL;
    char *cfgfile = CONFIG_DIR "/jabber.xml";
    char *basedir = NULL;
    int show_version = 0;
    poptContext pCtx = NULL;
    int pReturn = 0;
    xht std_namespace_prefixes = NULL;
    int convert = 0;
    char *getpath = NULL;
    int hashspool = 0;

    struct poptOption options[] = {
	{ "convert", 0, POPT_ARG_NONE, &convert, 0, "convert from plain spool to hashspool", NULL},
	{ "getpath", 0, POPT_ARG_STRING, &getpath, 0, "get the path to a file of a user", "JabberID"},
	{ "basedir", 'b', POPT_ARG_STRING, &basedir, 0, "base dir of the spool", "path"},
	{ "hashspool", 'h', POPT_ARG_NONE, &hashspool, 0, "use hashed spool directory", NULL},
        { "config", 'c', POPT_ARG_STRING, &cfgfile, 0, "configuration file to use", "path and filename"},
        { "version", 'V', POPT_ARG_NONE, &show_version, 0, "print server version", NULL},
        { NULL, 'v', POPT_ARG_NONE|POPT_ARGFLAG_DOC_HIDDEN, &show_version, 0, "print server version", NULL},
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    /* parse command line options */
    pCtx = poptGetContext(NULL, argc, argv, options, 0);
    while ((pReturn = poptGetNextOpt(pCtx)) >= 0) {
	/* nothing at present */
    }

    /* error? */
    if (pReturn < -1) {
	fprintf(stderr, "%s: %s\n", poptBadOption(pCtx, POPT_BADOPTION_NOALIAS), poptStrerror(pReturn));
	return 1;
    }

    /* show version information? */
    if (show_version != 0) {
	fprintf(stdout, "xdbfiletool out of " PACKAGE " version " VERSION "\n");
	fprintf(stdout, "Default config file is: %s\n", CONFIG_DIR "/jabber.xml");
	fprintf(stdout, "For more information please visit http://jabberd.org/\n");
	return 0;
    }

    std_namespace_prefixes = xhash_new(13);
    xhash_put(std_namespace_prefixes, "conf", NS_JABBERD_CONFIGFILE);
    xhash_put(std_namespace_prefixes, "xdbfile", NS_JABBERD_CONFIG_XDBFILE);

    pth_init();
    jid_init_cache();

    /* open module */
    /* XXX well using dlopen is not very portable, but jabberd does itself at present
     * we should change to libltdl for jabberd as well as for this
     */
    so_h = dlopen("libjabberdxdbfile.so", RTLD_LAZY);
    if (so_h == NULL) {
	fprintf(stderr, "While loading libjabberdxdbfile.so: %s\n", dlerror());
	return 3;
    }
    dlerror();

    /* load the needed functions */
    *(void **) (&xdb_file_full) = dlsym(so_h, "xdb_file_full");
    if ((error = dlerror()) != NULL) {
	fprintf(stderr, "While loading xdb_file_full: %s\n", dlerror());
	return 3;
    }
    *(void **) (&xdb_convert_spool) = dlsym(so_h, "xdb_convert_spool");
    if ((error = dlerror()) != NULL) {
	fprintf(stderr, "While loading xdb_convert_spool: %s\n", dlerror());
	return 3;
    }
    *(void **) (&xdb_file_load) = dlsym(so_h, "xdb_file_load");
    if ((error = dlerror()) != NULL) {
	fprintf(stderr, "While loading xdb_file_load: %s\n", dlerror());
	return 3;
    }

    /* get the base directory */
    if (basedir == NULL) {
	xmlnode_list_item basedir_node = NULL, hashspool_node = NULL;
	xmlnode configfile = xmlnode_file(cfgfile);

	/* load configuration file */
	if (configfile == NULL) {
	    fprintf(stderr, "You have not specified a basedir, and config file ('%s') could not be loaded:\n%s\n", cfgfile, xmlnode_file_borked(cfgfile));
	    return 1;
	}

	hashspool_node = xmlnode_get_tags(configfile, "conf:xdb/xdbfile:xdb_file/xdbfile:use_hierarchical_spool", std_namespace_prefixes);
	if (hashspool_node != NULL)
	    hashspool = 1;

	basedir_node = xmlnode_get_tags(configfile, "conf:xdb/xdbfile:xdb_file/xdbfile:spool/*", std_namespace_prefixes);

	if (basedir_node == NULL) {
	    fprintf(stderr, "Basedir could not be found in the config file ('%s'). Please use --basedir to specify base directory.\n", cfgfile);
	    return 1;
	}
	if (basedir_node->node->type == NTYPE_TAG
		&& j_strcmp(xmlnode_get_localname(basedir_node->node), "cmdline") == 0
		&& j_strcmp(xmlnode_get_namespace(basedir_node->node), NS_JABBERD_CONFIGFILE_REPLACE) == 0) {
	    basedir_node->node = xmlnode_get_firstchild(basedir_node->node);
	}
	if (basedir_node->node == NULL || basedir_node->node->type != NTYPE_CDATA) {
	    fprintf(stderr, "Could not determine base directory for spool using config file ('%s'). Please use --basedir to specify base directory.\n", cfgfile);
	    return 1;
	}
	basedir = xmlnode_get_data(basedir_node->node);
	if (basedir_node->next != NULL) {
	    fprintf(stderr, "Could not determine base directory, found different possibilities. Please use --basedir to specify base directory.\n");
	    return 1;
	}
	if (basedir == NULL) {
	    fprintf(stderr, "Could not automatically determine base directory, please use --basedir to specify base directory.\n");
	    return 1;
	}
    }

    if (convert) {
	printf("Converting xdb_file's spool directories in %s ... this may take some time!\n", basedir);
	(*xdb_convert_spool)(basedir);
	printf("Done.\n");
	return 0;
    }

    if (getpath != NULL) {
	pool p = pool_new();
	jid user = jid_new(p, getpath);
	
	if (user == NULL) {
	    fprintf(stderr, "Problem processing specified JabberID: %s\n", getpath);
	    return 1;
	}
	printf("%s\n", (*xdb_file_full)(0, p, basedir, user->server, user->user, "xml", hashspool));
	pool_free(p);

	return 0;
    }

    if ((argc == 5 && strcmp(argv[1], "set") == 0) || (argc == 4 && (strcmp(argv[1], "get")==0 || strcmp(argv[1], "del") == 0))) {
	char *spoolfile = NULL;
	xmlnode file = NULL;

	host = strchr(argv[3], '@');
	if (host == NULL) {
	    printf("%s is no valid JID\n", argv[3]);
	    return 2;
	}
	*(host++) = 0;
	p = pool_new();

	spoolfile = (*xdb_file_full)(0, p, basedir, host, argv[3], "xml", hashspool);

	/* load the spool file */
	file = (*xdb_file_load)(NULL, spoolfile, NULL);

	if (file == NULL) {
	    fprintf(stderr, "No such user.\n");
	    return 4;
	}

	if (strcmp(argv[1], "get") == 0) {
	    char *tagdata = NULL;

	    tagdata = xmlnode_get_tag_data(file, argv[2]);

	    if (tagdata == NULL) {
		fprintf(stderr, "No such data for this user.\n");
		return 4;
	    }

	    printf("%s\n", tagdata);
	} else {
	    xmlnode element = NULL;

	    element = xmlnode_get_tag(file, argv[2]);

	    if (element == NULL) {
		fprintf(stderr, "No such element!\n");
		return 5;
	    }

	    if (strcmp(argv[1], "del") == 0) {
		/* for deletion we just hide */
		xmlnode_hide(element);
	    } else {
		/* for update we hide only CDATA children and set new CDATA */
		xmlnode iter_element = NULL;

		for (iter_element = xmlnode_get_firstchild(element); iter_element!=NULL; iter_element = xmlnode_get_nextsibling(iter_element)) {
		    if (xmlnode_get_type(iter_element) == NTYPE_CDATA) {
			xmlnode_hide(iter_element);
		    }
		}
		xmlnode_insert_cdata(element, argv[4], strlen(argv[4]));
	    }

	    /* write the file back */
	    if (xmlnode2file_limited(spoolfile, file, 0) <= 0) {
		fprintf(stderr, "Failed to write spoolfile\n");
	    }
	}
	
	return 0;
    }

    printf("%s --help\n", argv[0]);
    printf("%s get ?xdbns=jabber:iq:auth <user>\n", argv[0]);
    printf("%s set ?xdbns=jabber:iq:auth <user> <newvalue>\n", argv[0]);
    printf("%s del ?xdbns=jabber:iq:auth <user>\n", argv[0]);
    return 1;
}
