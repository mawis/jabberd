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

#include <jabberdxdbfile.h>

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

char *xdb_file_full(int create, pool p, char *spl, char *host, char *file, char *ext, int use_subdirs);

int main(int argc, char **argv) {
    pool p;
    char *host = NULL;

    if (argc == 3 && strcmp(argv[1], "convert")==0) {
	printf("Converting xdb_file's spool directories in %s ... this may take some time!\n", argv[2]);
	xdb_convert_spool(argv[2]);
	printf("Done.\n");
	return 0;
    }

    if (argc != 2) {
	printf("%s <user>\n", argv[0]);
	printf("%s convert <basedir>\n", argv[0]);
	return 1;
    }

    host = strchr(argv[1], '@');
    if (host == NULL) {
	printf("%s is no valid JID\n", argv[1]);
	return 2;
    }
    *(host++) = 0;

    p=pool_new();
    printf("%s\n", xdb_file_full(0, p, "", host, argv[1], "xml", 1)+1);
    pool_free(p);

    return 0;
}
