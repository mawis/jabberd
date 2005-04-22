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

    if (argc == 3 && strcmp(argv[1], "convert")==0) {
	printf("Converting xdb_file's spool directories in %s ... this may take some time!\n", argv[2]);
	(*xdb_convert_spool)(argv[2]);
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
    printf("%s\n", (*xdb_file_full)(0, p, "", host, argv[1], "xml", 1)+1);
    pool_free(p);

    return 0;
}
