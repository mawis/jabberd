/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is SHA 180-1 Reference Implementation (Compact version)
 * 
 * The Initial Developer of the Original Code is Paul Kocher of
 * Cryptography Research.  Portions created by Paul Kocher are 
 * Copyright (C) 1995-9 by Cryptography Research, Inc.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 *
 */

/**
 * @file sha.c
 * @brief calculate SHA-1 hash values
 *
 * SHA-1 hash values are used very much in the Jabber protocols and in this file
 * the SHA-1 hash algorithm is implemented
 */

#include <jabberdlib.h>

static void shaHashBlock(j_SHA_CTX *ctx);

/**
 * initialize the calculation of a SHA-1 value
 *
 * @param ctx the context to be used
 */
void shaInit(j_SHA_CTX *ctx) {
  int i;

  ctx->lenW = 0;
  ctx->sizeHi = ctx->sizeLo = 0;

  /* Initialize H with the magic constants (see FIPS180 for constants)
   */
  ctx->H[0] = 0x67452301L;
  ctx->H[1] = 0xefcdab89L;
  ctx->H[2] = 0x98badcfeL;
  ctx->H[3] = 0x10325476L;
  ctx->H[4] = 0xc3d2e1f0L;

  for (i = 0; i < 80; i++)
    ctx->W[i] = 0;
}

/**
 * expand the byte string for which we want to know the SHA-1 hash value
 *
 * @param ctx the context to be used
 * @param dataIn the data that should be added
 * @param len length of the data
 */
void shaUpdate(j_SHA_CTX *ctx, unsigned char *dataIn, int len) {
  int i;

  /* Read the data into W and process blocks as they get full
   */
  for (i = 0; i < len; i++) {
    ctx->W[ctx->lenW / 4] <<= 8;
    ctx->W[ctx->lenW / 4] |= (unsigned long)dataIn[i];
    if ((++ctx->lenW) % 64 == 0) {
      shaHashBlock(ctx);
      ctx->lenW = 0;
    }
    ctx->sizeLo += 8;
    ctx->sizeHi += (ctx->sizeLo < 8);
  }
}

/**
 * get back the SHA-1 hash value that has been calculated with the
 * previous calls to shaUpdate()
 *
 * @param ctx the context that has been used to calculate the SHA-1 hash value
 * @param hashout where to store the result of the hashing (binary, 20 bytes)
 */
void shaFinal(j_SHA_CTX *ctx, unsigned char hashout[20]) {
  unsigned char pad0x80 = 0x80;
  unsigned char pad0x00 = 0x00;
  unsigned char padlen[8];
  int i;

  /* Pad with a binary 1 (e.g. 0x80), then zeroes, then length
   */
  padlen[0] = (unsigned char)((ctx->sizeHi >> 24) & 255);
  padlen[1] = (unsigned char)((ctx->sizeHi >> 16) & 255);
  padlen[2] = (unsigned char)((ctx->sizeHi >> 8) & 255);
  padlen[3] = (unsigned char)((ctx->sizeHi >> 0) & 255);
  padlen[4] = (unsigned char)((ctx->sizeLo >> 24) & 255);
  padlen[5] = (unsigned char)((ctx->sizeLo >> 16) & 255);
  padlen[6] = (unsigned char)((ctx->sizeLo >> 8) & 255);
  padlen[7] = (unsigned char)((ctx->sizeLo >> 0) & 255);
  shaUpdate(ctx, &pad0x80, 1);
  while (ctx->lenW != 56)
    shaUpdate(ctx, &pad0x00, 1);
  shaUpdate(ctx, padlen, 8);

  /* Output hash
   */
  for (i = 0; i < 20; i++) {
    hashout[i] = (unsigned char)(ctx->H[i / 4] >> 24);
    ctx->H[i / 4] <<= 8;
  }

  /*
   *  Re-initialize the context (also zeroizes contents)
   */
  shaInit(ctx); 
}

/**
 * function that calles everything needed to calculate the SHA-1 hash value for a byte string
 *
 * @param dataIn the byte array containing the data that should be hashed
 * @param len the length of the input array
 * @param hashout where to store the result of the hashing (binary, 20 bytes)
 */
void shaBlock(unsigned char *dataIn, int len, unsigned char hashout[20]) {
  j_SHA_CTX ctx;

  shaInit(&ctx);
  shaUpdate(&ctx, dataIn, len);
  shaFinal(&ctx, hashout);
}


#define SHA_ROTL(X,n) ((((X) << (n)) | ((X) >> (32-(n)))) & 0xffffffffL)

/**
 * this function is internally used by shaUpdate and should not be called from outside this file
 *
 * @param ctx the context
 */
static void shaHashBlock(j_SHA_CTX *ctx) {
  int t;
  unsigned long A,B,C,D,E,TEMP;

  for (t = 16; t <= 79; t++)
    ctx->W[t] =
      SHA_ROTL(ctx->W[t-3] ^ ctx->W[t-8] ^ ctx->W[t-14] ^ ctx->W[t-16], 1);

  A = ctx->H[0];
  B = ctx->H[1];
  C = ctx->H[2];
  D = ctx->H[3];
  E = ctx->H[4];

  for (t = 0; t <= 19; t++) {
    TEMP = (SHA_ROTL(A,5) + (((C^D)&B)^D)     + E + ctx->W[t] + 0x5a827999L) & 0xffffffffL;
    E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
  }
  for (t = 20; t <= 39; t++) {
    TEMP = (SHA_ROTL(A,5) + (B^C^D)           + E + ctx->W[t] + 0x6ed9eba1L) & 0xffffffffL;
    E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
  }
  for (t = 40; t <= 59; t++) {
    TEMP = (SHA_ROTL(A,5) + ((B&C)|(D&(B|C))) + E + ctx->W[t] + 0x8f1bbcdcL) & 0xffffffffL;
    E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
  }
  for (t = 60; t <= 79; t++) {
    TEMP = (SHA_ROTL(A,5) + (B^C^D)           + E + ctx->W[t] + 0xca62c1d6L) & 0xffffffffL;
    E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
  }

  ctx->H[0] += A;
  ctx->H[1] += B;
  ctx->H[2] += C;
  ctx->H[3] += D;
  ctx->H[4] += E;
}

/*----------------------------------------------------------------------------
 *
 * This code added by Thomas "temas" Muldowney for Jabber compatability
 *
 *---------------------------------------------------------------------------*/

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
    static char final[41];
    char *pos;
    unsigned char hashval[20];
    int x;

    if(!str || strlen(str) == 0)
        return NULL;

    shaBlock((unsigned char *)str, strlen(str), hashval);

    pos = final;
    for(x=0;x<20;x++)
    {
        snprintf(pos, 3, "%02x", hashval[x]);
        pos += 2;
    }
    return (char *)final;
}

/**
 * calculate the hex ASCII representation of the SHA-1 hash value for a given zero terminated string
 *
 * @param str the string for which the SHA-1 hash should be calculated
 * @param hashbuf where the result string can be written to
 */
void shahash_r(const char* str, char hashbuf[41])
{
    int x;
    char *pos;
    unsigned char hashval[20];
    
    if(!str || strlen(str) == 0)
        return;

    shaBlock((unsigned char *)str, strlen(str), hashval);

    pos = hashbuf;
    for(x=0;x<20;x++)
    {
        snprintf(pos, 3, "%02x", hashval[x]);
        pos += 2;
    }

    return;
}
