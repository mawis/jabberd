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

/**
 * @file xdbfilepath.c
 * @brief small utility that prints out the location of a spool file inside the root spool directory
 */

/* XXX very big hack, to be able to link against libjabberd
 *     we have to remove these globals (or at least move them
 *     inside the library
 */
xht debug__zones;
pool jabberd__runtime = NULL;
int jabberd__signalflag = 0;

void jabberd_signal(void)
{
}
/* end of hack */

/* handle of the shared object */
void *so_h = NULL;

/* functions in libjabberdxdbfile.so used */
char* (*xdb_file_full)(int create, pool p, char *spl, char *host, char *file, char *ext, int use_subdirs);
void (*xdb_convert_spool)(const char *spoolroot);
xmlnode (*xdb_file_load)(char *host, char *fname, xht cache);

int main(int argc, char **argv) {
    pool p;
    char *host = NULL;
    char *error = NULL;

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
	fprintf(stderr, "Whilte loading xdb_convert_spool: %s\n", dlerror());
	return 3;
    }
    *(void **) (&xdb_file_load) = dlsym(so_h, "xdb_file_load");
    if ((error = dlerror()) != NULL) {
	fprintf(stderr, "Whilte loading xdb_file_load: %s\n", dlerror());
	return 3;
    }

    if (argc == 3 && strcmp(argv[1], "convert")==0) {
	printf("Converting xdb_file's spool directories in %s ... this may take some time!\n", argv[2]);
	(*xdb_convert_spool)(argv[2]);
	printf("Done.\n");
	return 0;
    }

    if ((argc == 7 && strcmp(argv[1], "set") == 0) || (argc == 6 && (strcmp(argv[1], "get")==0 || strcmp(argv[1], "del") == 0))) {
	char *spoolfile = NULL;
	xmlnode file = NULL;

	host = strchr(argv[5], '@');
	if (host == NULL) {
	    printf("%s is no valid JID\n", argv[5]);
	    return 2;
	}
	*(host++) = 0;
	p = pool_new();

	spoolfile = (*xdb_file_full)(0, p, argv[4], host, argv[5], "xml", j_strcmp(argv[3], "flat")==0 ? 0 : 1);

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
		xmlnode_insert_cdata(element, argv[6], strlen(argv[6]));
	    }

	    /* write the file back */
	    if (xmlnode2file_limited(spoolfile, file, 0) <= 0) {
		fprintf(stderr, "Failed to write spoolfile\n");
	    }
	}
	
	return 0;
    }

    if (argc != 2) {
	printf("%s <user>\n", argv[0]);
	printf("%s convert <basedir>\n", argv[0]);
	printf("%s get ?xdbns=jabber:iq:auth hash|flat <basedir> <user>\n", argv[0]);
	printf("%s set ?xdbns=jabber:iq:auth hash|flat <basedir> <user> <newvalue>\n", argv[0]);
	printf("%s del ?xdbns=jabber:iq:auth hash|flat <basedir> <user>\n", argv[0]);
	return 1;
    }

    host = strchr(argv[1], '@');
    if (host == NULL) {
	printf("%s is no valid JID\n", argv[1]);
	return 2;
    }
    *(host++) = 0;

    p=pool_new();
    printf("%s\n", (*xdb_file_full)(0, p, "", host, argv[1], "xml", 1)+1);
    pool_free(p);

    return 0;
}
