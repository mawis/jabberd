/*
 * Licence
 *
 * Copyright (c) 2006 Matthias Wimmer,
 *                    mailto:m@tthias.eu, xmpp:mawis@amessage.info
 *
 * You can use the content of this file using one of the following licences:
 *
 * - Version 1.0 of the Jabber Open Source Licence ("JOSL")
 * - GNU GENERAL PUBLIC LICENSE, Version 2 or any newer version of this licence at your choice
 * - Apache Licence, Version 2.0
 * - GNU Lesser General Public License, Version 2.1 or any newer version of this licence at your choice
 * - Mozilla Public License 1.1
 */

/**
 * @file hash.cc
 * @brief hashing algorithms
 *
 * This file currently only implements the SHA-1 hashing algorithm. The implementation is based
 * on the method 1 in RFC 3174.
 */

#include "util.h"

namespace xmppd {
    std::string hash::final_hex() {
	std::vector<uint8_t> binary = final();

	std::ostringstream result;
	result << std::hex;
	for (int i=0; i<binary.size(); i++) {
	    result.width(2);
	    result.fill('0');
	    result << static_cast<unsigned int>(binary[i]);
	}

	return result.str();
    }

    void sha1::update(const std::string& data) {
	// after SHA-1 has been calcularted, you cannot add more data
	if (padded) {
	    throw std::domain_error("Updating the SHA-1 is not possible after it has been calculated.");
	}

	// get it byte for byte
	std::string::size_type characters = data.length();
	for (int i=0; i<characters; i++) {
	    uint8_t current_byte = data[i];

	    // move the content of the relevant W[] 8 bits to the left so that we have all at the right bit in this W[] after adding 4 bytes
	    W[W_pos/4] <<= 8;

	    // move in the new byte
	    W[W_pos/4] |= current_byte;

	    // one more byte has been added
	    l += 8; // note: we have added an octet, which has 8 bit
	    W_pos++;

	    // did we complete a block of 64 bytes now?
	    if (W_pos == 64) {
		hash_block(); // hash the block
		W_pos = 0;    // start at the first byte in W[] again
	    }
	}
    }

    uint32_t sha1::circular_shift(uint32_t X, int n) {
	return (X << n) | (X >> (32-n));
    }

    uint32_t sha1::f_0_19(uint32_t B, uint32_t C, uint32_t D) {
	return (B & C) | ((0xFFFFFFFFL ^ B) & D);
    }

    uint32_t sha1::f_20_39(uint32_t B, uint32_t C, uint32_t D) {
	return B ^ C ^ D;
    }

    uint32_t sha1::f_40_59(uint32_t B, uint32_t C, uint32_t D) {
	return (B & C) | (B & D) | (C & D);
    }

    uint32_t sha1::f_60_79(uint32_t B, uint32_t C, uint32_t D) {
	return f_20_39(B, C, D);
    }

    void sha1::hash_block() {
	uint32_t A;
	uint32_t B;
	uint32_t C;
	uint32_t D;
	uint32_t E;
	uint32_t TEMP;

	// step b
	for (int t = 16; t < 80; t++) {
	    W[t] = circular_shift(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
	}

	// step c
	A=H[0];
	B=H[1];
	C=H[2];
	D=H[3];
	E=H[4];

	// step d
	for (int t = 0; t < 20; t++) {
	    TEMP = circular_shift(A, 5) + f_0_19(B, C, D) + E + W[t] + 0x5A827999L;
	    E = D;
	    D = C;
	    C = circular_shift(B, 30);
	    B = A;
	    A = TEMP;
	}
	for (int t = 20; t < 40; t++) {
	    TEMP = circular_shift(A, 5) + f_20_39(B, C, D) + E + W[t] + 0x6ED9EBA1L;
	    E = D;
	    D = C;
	    C = circular_shift(B, 30);
	    B = A;
	    A = TEMP;
	}
	for (int t = 40; t < 60; t++) {
	    TEMP = circular_shift(A, 5) + f_40_59(B, C, D) + E + W[t] + 0x8F1BBCDCL;
	    E = D;
	    D = C;
	    C = circular_shift(B, 30);
	    B = A;
	    A = TEMP;
	}
	for (int t = 60; t < 80; t++) {
	    TEMP = circular_shift(A, 5) + f_60_79(B, C, D) + E + W[t] + 0xCA62C1D6L;
	    E = D;
	    D = C;
	    C = circular_shift(B, 30);
	    B = A;
	    A = TEMP;
	}

	// step e
	H[0] += A;
	H[1] += B;
	H[2] += C;
	H[3] += D;
	H[4] += E;
    }

    std::vector<uint8_t> sha1::final() {
	// has the data already been padded?
	if (!padded) {
	    // we do not count the padding in the length
	    uint64_t message_length = l;

	    // pad with a single bit set first ... this is always the character 0x80 as we are only adding octects
	    update("\x80");

	    // pad with that many 0 bits, that we can just add the message length and get a complete block
	    std::string update_character("\0", 1);
	    while (W_pos != 56) {
		update(update_character);
	    }

	    // finally add the message length (high byte first)
	    for (int i=7; i>=0; i--) {
		update_character[0] = (message_length >> i*8);
		update(update_character);
	    }

	    padded = true;
	}

	// copy the hash to the result vector
	std::vector<uint8_t> result(20);
	for (int i=0; i<20; i++) {
	    result[i] = H[i/4] >> ((3 - i%4)*8);
	}

	// return the result vector
	return result;
    }

    sha1::sha1() : padded(false), W(80), W_pos(0), H(5), l(0) {
	H[0] = 0x67452301L;
	H[1] = 0xEFCDAB89L;
	H[2] = 0x98BADCFEL;
	H[3] = 0x10325476L;
	H[4] = 0xC3D2E1F0L;
    }
}
