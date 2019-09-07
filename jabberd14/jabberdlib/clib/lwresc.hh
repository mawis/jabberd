/*
 * Copyrights
 *
 * Copyright (c) 2007-2019 Matthias Wimmer
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

#ifndef __LWRESC_HH
#define __LWRESC_HH

#include <arpa/nameser.h>
#include <iostream>
#include <stdexcept>
#include <vector>

namespace xmppd {
namespace lwresc {

class invalid_packet : public std::logic_error {
  public:
    invalid_packet(const std::string &__arg);
};

// forward declaration
class lwquery;

/**
 * function to serialize a lwquery to a std::ostream
 */
std::ostream &operator<<(std::ostream &os, const lwquery &lwq);

/**
 * query to a lwresd
 */
class lwquery {
  public:
    friend std::ostream &operator<<(std::ostream &os, const lwquery &lwq);

    uint32_t getSerial() const;

  protected:
    /**
     * Constructor for a lwquery. As a lwquery instance should (and cannot)
     * be created, this is only to be called by child classes
     */
    lwquery();

    /**
     * Cleanup the data of the base class
     */
    virtual ~lwquery();

    /**
     * writes the lwpacket header
     *
     * @param os where to write to
     * @param opcode the opcode for the light-weight resolver query
     * @param rdata_len length of the data, that will follow the lwpacket header
     */
    void write_header(std::ostream &os, uint32_t opcode,
                      size_t rdata_len) const;

    /**
     * helper to serialize a 16 bit value to a stream in network byte order
     *
     * @param os the stream to serialize to
     * @param value the value to serialize
     */
    static void write_uint16(std::ostream &os, uint16_t value);

    /**
     * helper to serialize a 32 bit value to a stream in network byte order
     *
     * @param os the stream to serialize to
     * @param value the value to serialize
     */
    static void write_uint32(std::ostream &os, uint32_t value);

    /**
     * packet flags
     */
    uint16_t flags;

    /**
     * query serial number
     */
    uint32_t serial;

  private:
    /**
     * real implementation for the functionality of the operator<<()
     * for serializing a lwquery to a std::ostream.
     *
     * @param os the stream where to serialize this lwquery to
     */
    virtual void write_to_stream(std::ostream &os) const = 0;

    /**
     * the next query serial, that should be used
     */
    static int next_serial;
};

/**
 * rrsetbyname query
 */
class rrsetbyname : public lwquery {
  public:
    /**
     * construct a query for a resource record set using the lwres protocol
     */
    rrsetbyname(const std::string &hostname, ::ns_class qclass,
                ::ns_type qtype);

  private:
    /**
     * the hostname that has to be queried
     */
    std::string hostname;

    /**
     * the DNS class, that has to be queried
     */
    ::ns_class qclass;

    /**
     * the DNS type, that has to be queried
     */
    ::ns_type qtype;

    /**
     * write the binary representation of this query to an std::ostream
     *
     * @param os where to write to
     */
    void write_to_stream(std::ostream &os) const;
};

class rrecord {
  public:
    virtual ~rrecord();
};

class srv_record : public rrecord {
  public:
    srv_record(std::istream &is);

    // accessor functions
    uint16_t getPrio() const;
    uint16_t getWeight() const;
    uint16_t getPort() const;
    const std::string &getDName() const;

  private:
    uint16_t prio;
    uint16_t weight;
    uint16_t port;
    std::string dname;
};

class aaaa_record : public rrecord {
  public:
    aaaa_record(std::istream &is);

    // accessor functions
    const std::string &getAddress() const;

  private:
    std::string address;
};

class a_record : public rrecord {
  public:
    a_record(std::istream &is);

    // accessor functions
    const std::string &getAddress() const;

  private:
    std::string address;
};

class lwresult_rdata {
  public:
    virtual ~lwresult_rdata();
};

class lwresult_rrset : public lwresult_rdata {
  public:
    lwresult_rrset(std::istream &is, uint32_t rdata_len);
    ~lwresult_rrset();

    // accessor functions
    uint32_t getTTL() const;
    std::vector<rrecord *> getRR() const;

  private:
    uint32_t flags;
    ::ns_class rclass;
    ::ns_type rtype;
    uint32_t ttl;
    uint16_t number_rr;
    uint16_t number_sig;
    std::string real_name;

    std::vector<rrecord *> rr;
};

/**
 * base class for results to lwqueries.
 */
class lwresult {
  public:
    /**
     * construct a lwresult class by reading a result from an istream
     *
     * @param is the std::istream to read the result from
     */
    lwresult(std::istream &is);

    /**
     * destruct an instance of a lwresult
     */
    ~lwresult();

    /**
     * read a 16 bit value in network byte order from a stream
     *
     * @param is the stream to read from
     * @return the value that has been read
     * @throws std::runtime_error if no value was readable
     */
    static uint16_t read_uint16(std::istream &is);

    /**
     * read a 32 bit value in network byte order from a stream
     *
     * @param is the stream to read from
     * @return the value that has been read
     * @throws std::runtime_error if no value was readable
     */
    static uint32_t read_uint32(std::istream &is);

    /**
     * read a string (16 bit length field, string, zero byte)
     *
     * @note this method does not unread anything if it could not read the
     * string successfully
     *
     * @param is the stream to read from
     * @return the string that has been read
     * @throws std::runtime_error if no string was readable
     */
    static std::string read_string(std::istream &is);

    /**
     * read a qname (sequence of labels, terminated by a zero label)
     *
     * @note this method does not unread anything if it could not read the
     * string successfully
     *
     * @param is the stream to read from
     * @return the string that has been read
     * @throws std::runtime_error if no string was readable
     */
    static std::string read_qname(std::istream &is);

    /**
     * possible result values
     */
    enum QueryResult {
        res_success = 0,
        res_nomemory = 1,
        res_timeout = 2,
        res_notfound = 3,
        res_unexpectedend = 4,
        res_failure = 5,
        res_ioerror = 6,
        res_notimplemented = 7,
        res_unexpected = 8,
        res_trailingdata = 9,
        res_incomplete = 10,
        res_retry = 11,
        res_typenotfound = 12,
        res_toolarge = 13
    };

    // accessor functions

    uint32_t getSerial() const;
    QueryResult getResult() const;
    lwresult_rdata const *getRData() const;

  private:
    uint32_t length;
    uint16_t version;
    uint16_t flags;
    uint32_t serial;
    uint32_t opcode;
    uint32_t result;
    uint32_t recv_len;
    uint16_t auth_type;
    uint16_t auth_len;

    lwresult_rdata *rdata;
};

} // namespace lwresc
} // namespace xmppd

#endif // __LWRESC_HH
