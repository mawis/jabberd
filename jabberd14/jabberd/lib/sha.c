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

#include <openssl/sha.h>

/**
 * calculate the hex ASCII representation of the SHA-1 hash value for a given zero terminated string
 *
 * @deprecated this function is not thread safe, the result will be overwritten by each call to this function:
 * shahash_r is a threadsave version of this call
 *
 * @param str the string for which the SHA-1 hash should be calculated
 * @return string that represents the hash value
 */
char *shahash(char *str) {
    unsigned char binaryresult[SHA_DIGEST_LENGTH];
    static char result[41];
    int c = 0;
    char *ptr = result;

    /* calculate hash */
    SHA1(str, j_strlen(str), binaryresult);

    /* convert to ASCII */
    for (c=0; c<SHA_DIGEST_LENGTH; c++) {
	/* check buffer size */
	if (sizeof(result)-(ptr-result) < 0)
	    break;
	snprintf(ptr, sizeof(result)-(ptr-result), "%02x", binaryresult[c]);
	ptr += 2;
    }

    return result;
}

/**
 * calculate the hex ASCII representation of the SHA-1 hash value for a given zero terminated string
 *
 * @param str the string for which the SHA-1 hash should be calculated
 * @param hashbuf where the result string can be written to
 */
void shahash_r(const char* str, char hashbuf[41]) {
    unsigned char binaryresult[SHA_DIGEST_LENGTH];
    int c = 0;
    char *ptr = hashbuf;

    /* calculate hash */
    SHA1(str, j_strlen(str), binaryresult);

    /* convert to ASCII */
    for (c=0; c<SHA_DIGEST_LENGTH; c++) {
	/* check buffer size */
	if (sizeof(hashbuf)-(ptr-hashbuf) < 0)
	    break;
	snprintf(ptr, sizeof(hashbuf)-(ptr-hashbuf), "%02x", binaryresult[c]);
	ptr += 2;
    }
}
