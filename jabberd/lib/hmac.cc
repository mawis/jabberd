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

#include "jabberdlib.h"

static void hmac_sha1_r(char *secret, unsigned char *message, size_t len, unsigned char hmac[20]) {
    std::vector<uint8_t> key;
    xmppd::sha1 innerhash;
    xmppd::sha1 outerhash;
    char ipadded[20];
    char opadded[20];
    int i = 0;
    j_SHA_CTX ctx;

    /* sanity check */
    if (secret == NULL || message == NULL || hmac == NULL)
	return;

    /* hash our key for HMAC-SHA1 usage */
    xmppd::sha1 keyhasher;
    keyhasher.update(secret);
    key = keyhasher.final();

    /* generate inner and outer pad */
    for (i = 0; i<20; i++) {
	ipadded[i] = key[i] ^ 0x36;
	opadded[i] = key[i] ^ 0x5C;
    }

    /* calculate inner hash */
    innerhash.update(std::string(ipadded, 20));
    innerhash.update(reinterpret_cast<char*>(message));

    /* calculate outer hash */
    outerhash.update(std::string(opadded, 20));
    outerhash.update(innerhash.final());

    /* copy hmac to the result buffer */
    std::vector<uint8_t> result = outerhash.final();
    for (int i=0; i<20; i++) {
	hmac[i] = result[i];
    }
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
