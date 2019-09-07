/*
 * Copyrights
 *
 * Copyright (c) 2006-2019 Matthias Wimmer
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
#ifndef __HASH_HH
#define __HASH_HH

#include <string>
#include <set>
#include <vector>

namespace xmppd {
/* ******************** Hashing algorithms ****************** */

/**
 * generic base class for a hash function
 */
class hash {
  public:
    virtual void update(const std::string &data) = 0;
    virtual std::vector<uint8_t> final() = 0;
    std::string final_hex();
};

/**
 * the SHA-1 hashing algorithm
 */
class sha1 : public hash {
  public:
    /**
     * construct a SHA-1 hashing instance
     */
    sha1();

    /**
     * add data to what the hash should be calculated for
     *
     * @param data the data that should get added
     */
    void update(const std::string &data);

    /**
     * add data to what the hash should be calculated for
     *
     * @param data the data that should get added
     */
    void update(const std::vector<uint8_t> data);

    /**
     * signal that all data has been added and request the hash
     *
     * @note use final_hex() to do the same but get a string result (hex version
     * of the result)
     *
     * @return the hash value (binary)
     */
    std::vector<uint8_t> final();

  private:
    /**
     * if set to true, the hash has been padded and no more data can be added
     */
    bool padded;

    /**
     * temporarily storage for blocks that have not yet been completed
     */
    std::vector<uint8_t> current_block;

    /**
     * W[0] to W[79] as defined in the SHA-1 standard
     */
    std::vector<uint32_t> W;

    /**
     * which byte of a block we are currently adding
     *
     * W_pos because this defines where in W where are adding the byte
     */
    unsigned W_pos;

    /**
     * H0 to H4 as defined in the SHA-1 standard
     */
    std::vector<uint32_t> H;

    /**
     * do the hashing calculations on a complete block, that is now in W[]
     */
    void hash_block();

    /**
     * the function S^n as defined in the SHA-1 standard
     */
    inline static uint32_t circular_shift(uint32_t X, int n);

    /**
     * the function f(t;B,C,D) for 0 <= t <= 19 as defined in the SHA-1 standard
     */
    inline static uint32_t f_0_19(uint32_t B, uint32_t C, uint32_t D);

    /**
     * the function f(t;B,C,D) for 20 <= t <= 39 as defined in the SHA-1
     * standard
     */
    inline static uint32_t f_20_39(uint32_t B, uint32_t C, uint32_t D);

    /**
     * the function f(t;B,C,D) for 40 <= t <= 59 as defined in the SHA-1
     * standard
     */
    inline static uint32_t f_40_59(uint32_t B, uint32_t C, uint32_t D);

    /**
     * the function f(t;B,C,D) for 60 <= t <= 79 as defined in the SHA-1
     * standard
     */
    inline static uint32_t f_60_79(uint32_t B, uint32_t C, uint32_t D);

    /**
     * the length of the message (l in the SHA-1 standard as well)
     */
    uint64_t l;
};
} // namespace xmppd

char *shahash(char const *str);                    /* NOT THREAD SAFE */
void shahash_r(const char *str, char hashbuf[41]); /* USE ME */
void shaBlock(unsigned char *dataIn, int len, unsigned char hashout[20]);

#endif // __HASH_HH
