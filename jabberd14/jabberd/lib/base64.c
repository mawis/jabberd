/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include "lib.h"

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
void base64_encode_triple(unsigned char triple[3], char result[4])
{
    int tripleValue, i;

    tripleValue = triple[0];
    tripleValue *= 256;
    tripleValue += triple[1];
    tripleValue *= 256;
    tripleValue += triple[2];

    for (i=0; i<4; i++)
    {
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
int base64_encode(unsigned char *source, size_t sourcelen, unsigned char *target, size_t targetlen)
{
    /* check if the result will fit in the target buffer */
    if ((sourcelen+2)/3*4 > targetlen-1)
	return 0;

    /* encode all full triples */
    while (sourcelen >= 3)
    {
	base64_encode_triple(source, target);
	sourcelen -= 3;
	source += 3;
	target += 4;
    }

    /* encode the last one or two characters */
    if (sourcelen > 0)
    {
	unsigned char temp[3];
	memset(temp, 0, sizeof(temp));
	memcpy(temp, source, sourcelen);
	base64_encode_triple(temp, target);
	target[3] = '=';
	if (sourcelen == 1)
	    target[2] = '=';

	target += 4;
    }

    /* terminate the string */
    target[0] = 0;

    return 1;
}
