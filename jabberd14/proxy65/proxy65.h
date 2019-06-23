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

#include <jabberd.h>
#include <map>
#include <set>
#include <sigc++/sigc++.h>

namespace xmppd {
namespace proxy65 {

// forward declaration
class socks5stub;

/**
 * @brief connects two sockets to each other
 */
class connected_sockets {
  public:
    /**
     * create a new instance by connecting two sockets
     *
     * - The passed sockets (socket1 and socket2) get deleted by this
     * constructor if no exception is thrown.
     * - The two sockets need to have a connection
     *
     * @param socket1 the one socket that gets connected
     * @param socket2 the other socket that gets connected
     * @param identifier an identifier for this connection (this identifier can
     * later be requested with get_identifier())
     */
    connected_sockets(socks5stub *socket1, socks5stub *socket2,
                      const std::string &identifier);

    /**
     * destruct an instance of connected sockets, this will
     * also close the connection if it is still present
     */
    ~connected_sockets();

    /**
     * event that signals that the connection has been closed
     *
     * a pointer to the instance that has been closed gets passed with the event
     */
    sigc::signal<void, connected_sockets *> &event_closed() { return closed; }

    /**
     * get the amount of traffic that has been forwarded already
     *
     * @return the traffic in bytes
     */
    size_t get_forwarded_traffic() { return forwarded_traffic; }

    /**
     * get the identifier for this connection
     *
     * @return the identifier of the connection
     */
    const std::string &get_identifier() { return identifier; }

  private:
    /**
     * the identifier for this connection
     */
    std::string identifier;

    /**
     * Counter to remember the amount of bytes that have been forwarded
     */
    size_t forwarded_traffic;

    /**
     * array of the two sockets this instance is interconnecting
     */
    mio sockets[2];

    /**
     * static function, that can be registered as mio event handler,
     * will redirect the events to instance methods
     *
     * @param m the mio this event is caused by
     * @param state the type of event
     * @param arg the connected_socket instance this call is for
     * @param unused1 not used
     * @param buffer for MIO_BUFFER events this is the pointer to the read data
     * @param bufferlen for MIO_BUFFER events this is the length of the read
     * data
     */
    static void mio_event_wrapper(mio m, int state, void *arg, xmlnode unused1,
                                  char *buffer, int bufferlen);

    /**
     * the event that handles if one of the connected sockets get closed
     *
     * @param socketindex the index of the socket that has been closed (either 0
     * or 1)
     */
    void on_closed(int socketindex);

    /**
     * the event that handles data that has been received on one of the sockets,
     * that are connected
     *
     * @param socketindex the index of the socket on which the data has been
     * received
     * @param received_data the data that has been received
     */
    void on_data(int socketindex, const std::string &received_data);

    /**
     * this signal gets fired if the connection of the two sockets ended
     *
     * A pointer to the instance that got disconnected is passed
     */
    sigc::signal<void, connected_sockets *> closed;

    /**
     * closed the sockets that are connected, if they are not already closed
     */
    void close_sockets();
};

/**
 * @brief handles an accepted xep-0065-socks5 connection
 */
class socks5stub {
  public:
    /**
     * construct a new instance for a mio connection
     *
     * @param m the connection the instance should be created for
     */
    socks5stub(mio m);

    /**
     * destruct an instance
     */
    ~socks5stub();

    /**
     * get reference to the protocol_done signal
     *
     * @return reference to the signal
     */
    sigc::signal<void, socks5stub *> &event_protocol_done() {
        return protocol_done;
    }

    /**
     * get reference to the disconnected signal
     *
     * @return reference to the signal
     */
    sigc::signal<void, socks5stub *> &event_disconnected() {
        return disconnected;
    }

    /**
     * get the id of this connection
     *
     * The ID is what the client sent as destination address and that is
     * typically a sha1 hash in lowercase (we converted) hex
     */
    std::string get_connection_id() { return connection_id; }

  private:
    /**
     * signal that gets fired if a client finished the socks5 protocol part
     *
     * The signal handler gets passed the instance that represents the client
     * connection.
     */
    sigc::signal<void, socks5stub *> protocol_done;

    /**
     * signal that gets fired if the connection gets disconnected
     *
     * This signal handler gets passed the intance that represents the client
     * connection.
     */
    sigc::signal<void, socks5stub *> disconnected;

    /**
     * state of handling the SOCKS5 protocol part
     */
    enum state {
        state_connected, /**< connection just accepted, no (complete) version
                            identifier from client received yet */
        state_accepted_auth,    /**< received version identifier from client and
                                   client supports the X'00' auth */
        state_accepted_connect, /**< received a connect request from the client
                                 */
        state_error /**< there has been a problem with this connection, we had
                       to reject it */
    };

    /**
     * what has been already done on the incoming connection
     */
    state current_state;

    /**
     * data that has been received on this socket, but that is not yet
     * consumed/processed
     */
    std::string unprocessed_data;

    /**
     * event that gets fired when new data has been read on the connection
     *
     * @param received_data the bytes that have been read
     */
    void on_data(const std::string &received_data);

    /**
     * event that gets fired when the connection has been closed
     */
    void on_closed();

    /**
     * callback we register with mio
     *
     * This callback function delivers the event to the correct instance method
     *
     * @param m the mio this event is for
     * @param state the event type
     * @param arg the instance this event is for
     * @param unused1 not used but part of the mio event handler prototype
     * @param buffer received data when MIO_BUFFER event
     * @param bufferlen number of received bytes when MIO_BUFFER event
     */
    static void mio_event_wrapper(mio m, int state, void *arg, xmlnode unused1,
                                  char *buffer, int bufferlen);

    /**
     * the mio this instance handles
     */
    mio m;

    /**
     * The connection identifier
     *
     * This is the 'destination address' the connecting entity used. The
     * protocol specifies, that this is the sha1 hash of the two JIDs we will
     * interconnect and the session id. Therefore this id is not unique,
     * normally we will get twice the same id.
     *
     * Until the 'destination address' is received, this is the empty string
     */
    std::string connection_id;

    /**
     * close the socket of this instance (if it owns any)
     */
    void close_socket();

    friend class connected_sockets;
};

/**
 * @brief proxy65 component implementation
 *
 * This class implements a proxy to be used with XEP-0065. The main use-case
 * currently is to allow users to establish a file transfer if both sides are
 * behind a NAT router or if one side is IPv4-only and the other side is
 * IPv6-only.
 */
class proxy65 : public instance_base {
  public:
    /**
     * construct a proxy65 instance
     *
     * @param i the ::instance to construct a proxy65 for
     * @param x the configuration element that caused the instance to be created
     */
    proxy65(instance i, xmlnode x);

  private:
    /**
     * Signal handler that handles disconnected connections that where currently
     * doing the socks5 protocol
     *
     * @param stub the socks5stub instance that was handling the connection
     */
    void connecting_connection_disconnected(socks5stub *stub);

    /**
     * Signal handler that handles disconnected established connections
     *
     * @param conn the connected_sockets instance that has received a close
     */
    void active_connection_disconnected(connected_sockets *conn);

    /**
     * Signal handler that handles connections that finished the socks5 protocol
     *
     * @param stub the socks5stub instance that was handling the connection
     */
    void connecting_connection_protocol_done(socks5stub *stub);

    /**
     * the connections, that have not yet finished the socks5 protocol
     *
     * Key in the map is the socks5stub instance that handles the connection,
     * value is the time when the connection has been accepted
     */
    std::map<socks5stub *, time_t> connecting_connections;

    /**
     * the connections, that have finished the socks5 protocol but are not yet
     * interconnected
     *
     * Key is the connection id, value is a pair of the socks5stub instance and
     * the time when the socks5 protocol has been finished
     */
    std::multimap<std::string, std::pair<socks5stub *, time_t>>
        waiting_connections;

    /**
     * the connections, that have been connected together
     */
    std::set<connected_sockets *> active_connections;

    /**
     * method that handles newly accepted connections
     *
     * @param m the newly accepted connection's ::mio object
     */
    void connection_accepted(mio m);

    /**
     * handling received iq stanzas
     *
     * @param p the received stanza
     * @return always r_DONE
     */
    result on_iq_stanza(jpacket p);

    /**
     * handling an iq request in the disco#info namespace
     *
     * @param p the received stanza
     * @return always r_DONE
     */
    result iq_disco_info(jpacket p);

    /**
     * handling an iq request in the disco#items namespace
     *
     * @param p the received stanza
     * @return always r_DONE
     */
    result iq_disco_items(jpacket p);

    /**
     * handling an iq request in the bytestreams namespace
     *
     * @param p the received stanza
     * @return always r_DONE
     */
    result iq_bytestreams(jpacket p);

    /**
     * handling of an iq request to activate a bytestream
     *
     * @param p the received stanza
     * @return always r_DONE
     */
    result iq_bytestreams_activate(jpacket p);

    /**
     * callback we register with mio for notifying us, that a new connection has
     * been accepted
     *
     * @param m the ::mio of the new connection
     * @param state should always be MIO_NEW
     * @param arg the ::proxy65 instance this notification is for
     * @param unused1 not used, only required by callback function prototype
     * @param unused2 not used, only required by callback function prototype
     * @param unused3 not used, only required by callback function prototype
     */
    static void conn_accepted_wrapper(mio m, int state, void *arg,
                                      xmlnode unused1, char *unused2,
                                      int unused3);

    /**
     * the hash of namespace prefixes
     */
    xht std_namespace_prefixes;
};
} // namespace proxy65
} // namespace xmppd
