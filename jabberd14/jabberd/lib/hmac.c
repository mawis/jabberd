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
 * (C) 2006 Matthias Wimmer
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
 * --------------------------------------------------------------------------*/

#include "jabberdlib.h"

static void hmac_sha1_r(char *secret, unsigned char *message, size_t len, unsigned char hmac[20]) {
    unsigned char key[20];
    unsigned char innerhash[20];
    unsigned char outerhash[20];
    unsigned char ipadded[20];
    unsigned char opadded[20];
    int i = 0;
    j_SHA_CTX ctx;

    /* sanity check */
    if (secret == NULL || message == NULL || hmac == NULL)
	return;

    /* hash our key for HMAC-SHA1 usage */
    shaBlock(secret, j_strlen(secret), key);

    /* generate inner and outer pad */
    for (i = 0; i<20; i++) {
	ipadded[i] = key[i] ^ 0x36;
	opadded[i] = key[i] ^ 0x5C;
    }

    /* calculate inner hash */
    shaInit(&ctx);
    shaUpdate(&ctx, ipadded, 20);
    shaUpdate(&ctx, message, len);
    shaFinal(&ctx, innerhash);

    /* calculate outer hash */
    shaInit(&ctx);
    shaUpdate(&ctx, opadded, 20);
    shaUpdate(&ctx, innerhash, 20);
    shaFinal(&ctx, hmac);
}

void hmac_sha1_ascii_r(char *secret, unsigned char *message, size_t len, char hmac[41]) {
    unsigned char hmac_bin[20];
    int i = 0;
    char *ptr = hmac;

    /* sanity check */
    if (secret == NULL || message == NULL || hmac == NULL)
	return;

    /* calculate the hmac-sha1 */
    hmac_sha1_r(secret, message, len, hmac_bin);

    /* convert to ASCII */
    for (i = 0; i < 20; i++) {
	snprintf(ptr, 3, "%02x", hmac_bin[i]);
	ptr += 2;
    }
}
