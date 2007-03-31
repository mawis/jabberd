/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
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

#include <jabberdlib.h>

/**
 * @file base64.cc
 * @brief Functions to handle Base64 encoding and decoding
 *
 * The function to decode base64 data is base64_decode(), the general encoding function is base64_encode(). If the data that should get encoded is not
 * binary data, but zero terminated character data, the str_b64decode() function can be used instead, which does not require the caller to specify the
 * length of that data that should get encoded.
 */

/**
 * characters used for Base64 encoding
 */
const char *BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * encode three bytes using base64 (RFC 3548)
 *
 * @param triple three bytes that should be encoded
 * @param result buffer of four characters where the result is stored
 */
static void _base64_encode_triple(unsigned char triple[3], char result[4]) {
    int tripleValue, i;

    tripleValue = triple[0];
    tripleValue *= 256;
    tripleValue += triple[1];
    tripleValue *= 256;
    tripleValue += triple[2];

    for (i=0; i<4; i++) {
	result[3-i] = BASE64_CHARS[tripleValue%64];
	tripleValue /= 64;
    }
}

/**
 * encode an array of bytes using Base64 (RFC 3548)
 *
 * @param source the source buffer
 * @param sourcelen the length of the source buffer
 * @param target the target buffer
 * @param targetlen the length of the target buffer
 * @return 1 on success, 0 otherwise
 */
int base64_encode(unsigned char *source, size_t sourcelen, char *target, size_t targetlen) {
    /* check if the result will fit in the target buffer */
    if ((sourcelen+2)/3*4 > targetlen-1)
	return 0;

    /* encode all full triples */
    while (sourcelen >= 3) {
	_base64_encode_triple(source, target);
	sourcelen -= 3;
	source += 3;
	target += 4;
    }

    /* encode the last one or two characters */
    if (sourcelen > 0) {
	unsigned char temp[3];
	memset(temp, 0, sizeof(temp));
	memcpy(temp, source, sourcelen);
	_base64_encode_triple(temp, target);
	target[3] = '=';
	if (sourcelen == 1)
	    target[2] = '=';

	target += 4;
    }

    /* terminate the string */
    target[0] = 0;

    return 1;
}

/**
 * decode a base64 string and put the result in the same buffer as the source
 *
 * This function does not handle decoded data that contains the null byte
 * very well as the size of the decoded data is not returned.
 *
 * The result will be zero terminated.
 *
 * @deprecated use base64_decode instead
 *
 * @param str buffer for the source and the result
 */
void str_b64decode(char* str) {
    size_t decoded_length;

    decoded_length = base64_decode(str, (unsigned char *)str, strlen(str));
    str[decoded_length] = '\0';
}

/**
 * decode base64 encoded data
 *
 * @param source the encoded data (zero terminated)
 * @param target pointer to the target buffer
 * @param targetlen length of the target buffer
 * @return length of converted data on success, -1 otherwise
 */
size_t base64_decode(const char *source, unsigned char *target, size_t targetlen) {
    const char *cur;
    unsigned char *dest, *max_dest;
    int d, dlast, phase;
    unsigned char c;
    static int table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
    };

    d = dlast = phase = 0;
    dest = target;
    max_dest = dest+targetlen;

    for (cur = source; *cur != '\0' && dest<max_dest; ++cur ) {
        d = table[(int)*cur];
        if(d != -1) {
            switch(phase) {
		case 0:
		    ++phase;
		    break;
		case 1:
		    c = ((dlast << 2) | ((d & 0x30) >> 4));
		    *dest++ = c;
		    ++phase;
		    break;
		case 2:
		    c = (((dlast & 0xf) << 4) | ((d & 0x3c) >> 2));
		    *dest++ = c;
		    ++phase;
		    break;
		case 3:
		    c = (((dlast & 0x03 ) << 6) | d);
		    *dest++ = c;
		    phase = 0;
		    break;
	    }
            dlast = d;
        }
    }

    /* we decoded the whole buffer */
    if (*cur == '\0') {
	return dest-target;
    }

    /* we did not convert the whole data, buffer was to small */
    return -1;
}
