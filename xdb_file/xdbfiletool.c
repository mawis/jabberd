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
    char *host = NULL;
    char *error = NULL;
    char *cfgfile = CONFIG_DIR "/jabber.xml";
    char *basedir = NULL;
    char *do_get = NULL;
    char *do_set = NULL;
    char *do_del = NULL;
    char *jid = NULL;
    int show_version = 0;
    poptContext pCtx = NULL;
    int pReturn = 0;
    xht namespace_prefixes = NULL;
    xht std_namespace_prefixes = NULL;
    int convert = 0;
    char *getpath = NULL;
    int hashspool = 0;
    pool p = NULL;
    struct jid_struct *parsed_jid = NULL;

    struct poptOption options[] = {
	{ "convert", 0, POPT_ARG_NONE, &convert, 0, "convert from plain spool to hashspool", NULL},
	{ "getpath", 0, POPT_ARG_STRING, &getpath, 0, "get the path to a file of a user", "JabberID"},
	{ "get", 'g', POPT_ARG_STRING, &do_get, 0, "get a node in the spool file", "path"},
	{ "set", 's', POPT_ARG_STRING, &do_set, 0, "set a node in the spool file", "path value"},
	{ "del", 'd', POPT_ARG_STRING, &do_del, 0, "delete a node in the spool file", "path"},
	{ "jid", 'j', POPT_ARG_STRING, &jid, 0, "JabberID for get/set/del operation", "JID"},
	{ "basedir", 'b', POPT_ARG_STRING, &basedir, 0, "base dir of the spool", "path"},
	{ "hashspool", 'h', POPT_ARG_NONE, &hashspool, 0, "use hashed spool directory", NULL},
	{ "namespace", 'n', POPT_ARG_STRING, NULL, 1, "define a namespace prefix", "prefix:IRI"},
        { "config", 'c', POPT_ARG_STRING, &cfgfile, 0, "configuration file to use", "path and filename"},
        { "version", 'V', POPT_ARG_NONE, &show_version, 0, "print server version", NULL},
        { NULL, 'v', POPT_ARG_NONE|POPT_ARGFLAG_DOC_HIDDEN, &show_version, 0, "print server version", NULL},
        POPT_AUTOHELP
        POPT_TABLEEND
    };

    /* init the libraries */
    pth_init();
    jid_init_cache();

    p = pool_new();
    namespace_prefixes = xhash_new(101);

    /* parse command line options */
    pCtx = poptGetContext(NULL, argc, argv, options, 0);
    while ((pReturn = poptGetNextOpt(pCtx)) >= 0) {
	char *prefix = NULL;
	char *ns_iri = NULL;

	switch (pReturn) {
	    case 1:
		prefix = pstrdup(namespace_prefixes->p, poptGetOptArg(pCtx));
		if (prefix == NULL) {
		    fprintf(stderr, "Problem processing namespace prefix declaration ...\n");
		    return 1;
		}
		ns_iri = strchr(prefix, ':');
		if (ns_iri == NULL) {
		    fprintf(stderr, "Invalid namespace prefix declaration ('%s'). Required format is prefix:IRI ...\n", prefix);
		    return 1;
		}
		ns_iri[0] = 0;
		ns_iri++;
		xhash_put(namespace_prefixes, prefix, ns_iri);
		break;
	}
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
	struct jid_struct *user = jid_new(p, getpath);
	
	if (user == NULL) {
	    fprintf(stderr, "Problem processing specified JabberID: %s\n", getpath);
	    return 1;
	}
	printf("%s\n", (*xdb_file_full)(0, p, basedir, user->server, user->user, "xml", hashspool));
	pool_free(p);

	return 0;
    }

    if (jid == NULL && (do_get != NULL || do_set != NULL || do_del != NULL)) {
	fprintf(stderr, "When doing a get/set/del operation, you have to specify the JabberID of the user using --jid\n");
	return 1;
    }

    if (jid != NULL) {
	parsed_jid = jid_new(p, jid);

	if (parsed_jid == NULL) {
	    fprintf(stderr, "Could not parse the JID %s\n", jid);
	    return 1;
	}
    }

    if (do_get != NULL || do_set != NULL || do_del != NULL) {
	char *spoolfile = NULL;
	xmlnode_list_item result_item = NULL;
	xmlnode file = NULL;
	const char *path = do_get ? do_get : do_set ? do_set : do_del;
	const char *replacement = do_set ? poptGetArg(pCtx) : NULL;
	int is_updated = 0;

	if (do_set != NULL && replacement == NULL) {
	    fprintf(stderr, "You have to specify a replacement for the --set operation.\n");
	    return 1;
	}

	spoolfile = (*xdb_file_full)(0, p, basedir, parsed_jid->server, parsed_jid->user, "xml", hashspool);
	file = (*xdb_file_load)(NULL, spoolfile, NULL);

	if (file == NULL) {
	    fprintf(stderr, "Could not load the spool file (%s). No such user?\n", spoolfile);
	    return 1;
	}

	for (result_item = xmlnode_get_tags(file, path, namespace_prefixes); result_item != NULL; result_item = result_item -> next) {
	    if (do_get) {
		switch (result_item->node->type) {
		    case NTYPE_TAG:
			fprintf(stdout, "%s\n", xmlnode_serialize_string(result_item->node, NULL, NULL, 0));
			break;
		    case NTYPE_CDATA:
		    case NTYPE_ATTRIB:
			fprintf(stdout, "%s\n", xmlnode_get_data(result_item->node));
			break;
		}
	    } else {
		/* del, or set: hide the old content */
		xmlnode_hide(result_item->node);
		is_updated=1;

		/* if it's a set, place the new content */
		if (do_set) {
		    xmlnode parent = xmlnode_get_parent(result_item->node);
		    xmlnode x = NULL;

		    switch (result_item->node->type) {
			case NTYPE_CDATA:
			    xmlnode_insert_cdata(parent, replacement, -1);
			    break;
			case NTYPE_ATTRIB:
			    xmlnode_put_attrib_ns(parent, xmlnode_get_localname(result_item->node), xmlnode_get_nsprefix(result_item->node), xmlnode_get_namespace(result_item->node), replacement);
			    break;
			case NTYPE_TAG:
			    x = xmlnode_str(replacement, -1);
			    xmlnode_insert_node(parent, x);
			    xmlnode_free(x);
			    x = NULL;
			    break;
		    }
		}
	    }
	}

	/* write an updated file back to disk */
	if (is_updated) {
	    xmlnode2file(spoolfile, file);
	}

	return 0;
    }
}
