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
char *xdb_file_full(int create, pool p, char *spl, char *host, char *file, char *ext, int use_subdirs);

/**
 * convert a spool directory from the old format to the new one
 * which distributes the files over several subdirs
 *
 * @param spoolroot the root folder of the spool
 */
void xdb_convert_spool(const char *spoolroot);
