/*
 * Copyrights
 *
 * Copyright (c) 2007 Matthias Wimmer
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

/**
 * @file lwresc.cc
 * @brief accessing a lwresd
 *
 * This file implements the code needed to access lwresd (light-weight resolving
 * daemon) used to do asyncronous DNS resolving)
 */

#include <lwresc.hh>

#include <sstream>

namespace xmppd {
namespace lwresc {
invalid_packet::invalid_packet(const std::string &__arg)
    : std::logic_error(__arg){};

void lwquery::write_uint16(std::ostream &os, uint16_t value) {
    os.put(value / 256);
    os.put(value % 256);
}

void lwquery::write_uint32(std::ostream &os, uint32_t value) {
    write_uint16(os, value / 0x10000);
    write_uint16(os, value % 0x10000);
}

void lwquery::write_header(std::ostream &os, uint32_t opcode,
                           size_t rdata_len) const {
    write_uint32(os,
                 4 + 2 + 2 + 4 + 4 + 4 + 4 + 2 + 2 +
                     rdata_len); // packet length
    write_uint16(os, 0);         // version
    write_uint16(os, flags);     // packet flags
    write_uint32(os, serial);    // query serial
    write_uint32(os, opcode);    // type of query
    write_uint32(os, 0);         // result code (0 = success)
    write_uint32(os, 0x4000);    // receive length
    write_uint16(os, 0);         // auth type
    write_uint16(os, 0);         // auth length
}

lwquery::lwquery() : flags(0), serial(next_serial++) {}

int lwquery::next_serial = 1;

lwquery::~lwquery() {}

uint32_t lwquery::getSerial() const { return serial; }

std::ostream &operator<<(std::ostream &os, const lwquery &lwq) {
    lwq.write_to_stream(os);
    return os;
}

rrsetbyname::rrsetbyname(const std::string &hostname, ::ns_class qclass,
                         ::ns_type qtype)
    : lwquery(), hostname(hostname), qclass(qclass), qtype(qtype) {}

void rrsetbyname::write_to_stream(std::ostream &os) const {
    // calculate own size
    size_t rdata_size = 4 + 2 + 2 + 2 + hostname.length() + 1;

    // write the lwpacket header
    write_header(os, 0x10003, rdata_size);

    // write our own data
    write_uint32(os, 0);      // flags
    write_uint16(os, qclass); // class
    write_uint16(os, qtype);  // type
    write_uint16(os, hostname.length());
    os << hostname; // the hostname to query
    os.put('\0');   // string terminator
}

uint16_t lwresult::read_uint16(std::istream &is) {
    char first_char = 0;
    char second_char = 0;

    // try to read the first byte
    if (!is.get(first_char)) {
        throw std::runtime_error(
            "No data available to be read from the stream");
    }
    // try to read the second byte
    if (!is.get(second_char)) {
        is.unget(); // try to put back the first byte
        throw std::runtime_error(
            "No data available to be read from the stream");
    }

    return static_cast<unsigned char>(first_char) * 0x100 +
           static_cast<unsigned char>(second_char);
}

uint32_t lwresult::read_uint32(std::istream &is) {
    uint16_t first_half = 0;
    uint16_t second_half = 0;

    // read the first two bytes
    first_half = read_uint16(is);

    // read the second two bytes
    try {
        second_half = read_uint16(is);
    } catch (std::runtime_error&) {
        // not enought data available, try to put back the first two bytes
        is.unget();
        is.unget();

        // pass the exception
        throw;
    }

    return first_half * 0x10000 + second_half;
}

std::string lwresult::read_string(std::istream &is) {
    std::ostringstream result;

    // read labels
    uint16_t string_length = read_uint16(is);
    if (!is)
        throw std::runtime_error("Could not read string length value");

    for (uint16_t bytes_read = 0; bytes_read < string_length; bytes_read++) {
        char one_byte;
        if (!is.get(one_byte))
            throw std::runtime_error("Could not read a string.");
        result.put(one_byte);
    }

    is.get();
    if (!is)
        throw std::runtime_error("Could not read termination byte of string");

    return result.str();
}

std::string lwresult::read_qname(std::istream &is) {
    std::ostringstream result;
    char label_length = 0;
    bool first_label = true;

    // read labels
    for (is.get(label_length); is && label_length; is.get(label_length)) {
        if (!first_label)
            result << ".";
        else
            first_label = false;

        for (unsigned char bytes_read = 0;
             bytes_read < static_cast<unsigned char>(label_length);
             bytes_read++) {
            char one_byte;
            if (!is.get(one_byte)) {
                std::ostringstream exception_message;
                exception_message
                    << "Could not read a qname while reading a character "
                    << static_cast<unsigned>(bytes_read) << "/"
                    << static_cast<unsigned>(label_length);
                throw std::runtime_error(exception_message.str());
            }
            result.put(one_byte);
        }
    }

    return result.str();
}

lwresult::lwresult(std::istream &is) : rdata(NULL) {
    std::stringstream buffer;

    // read the length of the packet
    length = read_uint32(is);
    if (length < 7 * 4) {
        // read packet size is smaller then even the lwpacket header
        throw invalid_packet("Packet size error. Reading out of sync?");
    }

    // copy the lwpacket to our buffer
    for (uint32_t bytes_read = 4; bytes_read < length; bytes_read++) {
        char one_byte;
        if (!is.get(one_byte)) {
            // try to unread - may not work in many cases, caller has to check
            // state of is after catching the exception
            for (uint32_t i = 0; i < bytes_read; i++) {
                is.unget();
            }
            std::ostringstream exception_message;
            exception_message << "Packet not yet fully available: Expecting "
                              << length << " B / got " << bytes_read << " B";
            throw std::runtime_error(exception_message.str());
        }
        buffer.put(one_byte);
    }

    try {
        // try to read the packet version
        version = read_uint16(buffer);
        if (version != 0) {
            throw invalid_packet("Unsupported packet version");
        }

        // try to read packet flags
        flags = read_uint16(buffer);

        // try to read the serial
        serial = read_uint32(buffer);

        // try to read the opcode
        opcode = read_uint32(buffer);

        // try to read result code
        result = read_uint32(buffer);

        // try to read the receive length
        recv_len = read_uint32(buffer);

        // try to read auth type
        auth_type = read_uint16(buffer);

        // try to read the auth len
        auth_len = read_uint16(buffer);

        // try to read auth data - by just skipping it
        for (uint16_t bytes_read = 0; bytes_read < auth_len; bytes_read++) {
            if (!buffer.get())
                throw std::runtime_error("Not enough data in buffer");
        }

        // only read body if result is success
        if (result != 0)
            return;

        // try to read the rdata
        uint32_t rdata_length = length - 28 - auth_len;
        switch (opcode) {
            case 0x10003: // getrdatabyname
                rdata = new lwresult_rrset(buffer, rdata_length);
                break;
            default:
                for (uint32_t bytes_read = 0; bytes_read < rdata_length;
                     bytes_read++) {
                    if (!buffer.get())
                        throw std::runtime_error("Not enough data in buffer");
                }
        }
    } catch (std::runtime_error &re) {
        if (rdata)
            delete rdata;
        rdata = NULL;

        throw invalid_packet(std::string("Received corrupted packet: ") +
                             re.what());
    }
}

// free resources on destruction
lwresult::~lwresult() {
    if (rdata)
        delete rdata;
    rdata = NULL;
}

uint32_t lwresult::getSerial() const { return serial; }

lwresult::QueryResult lwresult::getResult() const {
    return static_cast<lwresult::QueryResult>(result);
}

lwresult_rdata const *lwresult::getRData() const { return rdata; }

lwresult_rdata::~lwresult_rdata() {}

uint32_t lwresult_rrset::getTTL() const { return ttl; }

std::vector<rrecord *> lwresult_rrset::getRR() const { return rr; }

lwresult_rrset::lwresult_rrset(std::istream &is, uint32_t rdata_len) {
    flags = lwresult::read_uint32(is);
    rclass = static_cast<::ns_class>(lwresult::read_uint16(is));
    rtype = static_cast<::ns_type>(lwresult::read_uint16(is));
    ttl = lwresult::read_uint32(is);
    number_rr = lwresult::read_uint16(is);
    number_sig = lwresult::read_uint16(is);
    real_name = lwresult::read_string(is);

    // read resource records
    for (uint16_t rr_read = 0; rr_read < number_rr; rr_read++) {
        // we do handle only record class IN yet
        if (rclass != ns_c_in)
            break;

        rrecord *new_record = NULL;

        try {
            switch (rtype) {
                case ns_t_srv:
                    new_record = new srv_record(is);
                    break;
                case ns_t_aaaa:
                    new_record = new aaaa_record(is);
                    break;
                case ns_t_a:
                    new_record = new a_record(is);
                    break;
                default:
                    break;
            }
        } catch (std::runtime_error &re) {
            std::vector<rrecord *>::iterator p;
            for (p = rr.begin(); p != rr.end(); ++p) {
                if (*p)
                    delete *p;
                *p = NULL;
            }
            std::ostringstream exception_message;
            exception_message << "Error while creating record " << (rr_read + 1)
                              << "/" << number_rr << ": " << re.what();
            throw std::runtime_error(exception_message.str());
        }

        if (new_record) {
            rr.push_back(new_record);
        }
    }

    // read signatures
    /* not yet
    for (uint16_t sigs_read = 0; sigs_read < number_sig; sigs_read) {
    }
    */
}

lwresult_rrset::~lwresult_rrset() {
    std::vector<rrecord *>::iterator p;
    for (p = rr.begin(); p != rr.end(); ++p) {
        if (*p)
            delete *p;
    }
}

rrecord::~rrecord() {}

srv_record::srv_record(std::istream &is) {
    try {
        lwresult::read_uint16(is);
    } catch (std::runtime_error&) {
        throw std::runtime_error("Error reading rrlen");
    }
    try {
        prio = lwresult::read_uint16(is);
    } catch (std::runtime_error&) {
        throw std::runtime_error("Error reading prio");
    }
    try {
        weight = lwresult::read_uint16(is);
    } catch (std::runtime_error&) {
        throw std::runtime_error("Error reading weight");
    }
    try {
        port = lwresult::read_uint16(is);
    } catch (std::runtime_error&) {
        throw std::runtime_error("Error reading port");
    }
    try {
        dname = lwresult::read_qname(is);
    } catch (std::runtime_error &re) {
        throw std::runtime_error(std::string("Error reading qname: ") +
                                 re.what());
    }
}

uint16_t srv_record::getPrio() const { return prio; }

uint16_t srv_record::getWeight() const { return weight; }

uint16_t srv_record::getPort() const { return port; }

const std::string &srv_record::getDName() const { return dname; }

const std::string &aaaa_record::getAddress() const { return address; }

aaaa_record::aaaa_record(std::istream &is) {
    lwresult::read_uint16(is); // should always be 0x10
    std::ostringstream address_stream;

    address_stream << std::hex; // IPv6 addresses are written in hex

    for (int i = 0; i < (128 / 16); i++) {
        if (i)
            address_stream << ":";
        address_stream << lwresult::read_uint16(is);
    }

    address = address_stream.str();
}

const std::string &a_record::getAddress() const { return address; }

a_record::a_record(std::istream &is) {
    lwresult::read_uint16(is); // should always be 4
    std::ostringstream address_stream;

    for (int i = 0; i < 4; i++) {
        if (i)
            address_stream << ".";
        char one_byte;
        if (!is.get(one_byte))
            throw std::runtime_error("Error reading A record");
        address_stream << (static_cast<unsigned>(one_byte) & 0xFF);
    }

    address = address_stream.str();
}
} // namespace lwresc
} // namespace xmppd
