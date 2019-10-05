/*
 * Copyrights
 *
 * Copyright (c) 2008 Matthias Wimmer
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

#include <lwresc.hh>

namespace xmppd {
namespace resolver {

/**
 * @brief a SRV service to resolve and the resend destinations
 *
 * This class stores the configuration for a service to resolve in DNS. Each
 * instance of this class represent the configuration data of a single
 * &lt;resend/&gt; element in the resolver configuration
 */
class resend_service {
  public:
    /**
     * construct a resend_service
     *
     * @param resend the xmlnode of the &lt;resend/&gt; element that should be
     * represented by this instance
     * @throws std::invalid_argument if configuration is not correct
     */
    resend_service(xmlnode resend);

    /**
     * does this represent a service lookup (or plain AAAA+A resolving?)
     *
     * @return true if this is for SRV lookups, false for plain AAAA+A lookup
     * service
     */
    bool is_explicit_service() const;

    /**
     * get the service prefix for SRV records that have to be resolved
     */
    Glib::ustring const &get_service_prefix() const;

    /**
     * select one of the resend_hosts for this service
     *
     * @return choosen resend_host
     */
    xmppd::jabberid get_resend_host() const;

  private:
    /**
     * the service to resolve, empty string for no service but plain AAAA/A
     * lookups
     */
    Glib::ustring service;

    /**
     * the hosts to use as destination for the resend
     */
    std::list<std::pair<int, xmppd::jabberid>> resend_hosts;

    /**
     * weight sum of the resend_hosts
     *
     * the weight sum is stored for performance reasons, it is the sum of all
     * weights in resend_hosts
     */
    int weight_sum;
};

// forward declaration
class resolver;

/**
 * @brief class holding pending jobs and the packets waiting for its
 * completition
 *
 * This class stores all packets for a given destination, resolves the IP
 * address for this destination and then resends the packets to a s2s component
 * including the resolved addresses
 */
class resolver_job {
  public:
    /**
     * create a new resolving job
     *
     * @param dp the packet resolving is started for
     * @throws std::invalid_argument on failed sanity checks
     */
    resolver_job(resolver &owner, dpacket dp);

    /**
     * destructor
     */
    ~resolver_job();

    /**
     * add a packet that waits for the job to be completed
     *
     * @param dp the packet that is waiting
     * @throws std::invalid_argument if the packet has a different destination,
     * that what is being resolved by this job
     */
    void add_packet(dpacket dp);

    /**
     * get the waiting packets
     *
     * @return list of waiting packets
     */
    std::list<dpacket> const &get_packets() const;

    /**
     * register for being notified on finishing the job
     *
     * @param callback what should get notified on finishing the job
     */
    sigc::connection register_result_callback(
        sigc::signal<void, resolver_job &>::slot_type const &callback);

    /**
     * get the resolving result
     *
     * @return string containing IP/port pairs as the result to connect to
     */
    Glib::ustring get_result() const;

    /**
     * get the service where to send packets to that have been resolved by this
     * job
     *
     * @return the service
     */
    xmppd::jabberid get_resend_host() const;

  private:
    /**
     * the destination, that is being resolved by this job
     */
    Glib::ustring destination;

    /**
     * the resolver instance, that is using this job
     */
    resolver &owner;

    /**
     * the packets that wait for the job to be completed
     */
    std::list<dpacket> waiting_packets;

    /**
     * copy of the service and resend configuration
     *
     * we make a copy as the main configuration of the resolver could get
     * changed while this job is running
     */
    std::list<resend_service> resend_services;

    /**
     * the service that is currently resolved
     */
    std::list<resend_service>::const_iterator current_service;

    /**
     * start resolving of a service
     *
     * this starts resolving of the service current_service points to
     */
    void start_resolving_service();

    /**
     * list storing the result of the SRV lookup step
     *
     * first element in pair is the host, second element is the service (port)
     */
    std::list<std::pair<Glib::ustring, Glib::ustring>> providing_hosts;

    /**
     * the providing host, that is currently resolved
     */
    std::list<std::pair<Glib::ustring, Glib::ustring>>::const_iterator
        current_providing_host;

    /**
     * do AAAA and A lookups for the hosts in providing_hosts
     *
     * This gets called after providing_hosts has been filled, either explicitly
     * with destination and port 5269 if there was no SRV records to resolve, or
     * by the result of a SRV lookup.
     */
    void resolve_providing_hosts();

    /**
     * do AAAA and A lookups for the current_current_providing host
     *
     * This get called while iterating the entries in providing_hosts after
     * updating current_providing_host
     */
    void resolve_current_providing_host();

    /**
     * do the remaining A lookup after the AAAA lookup has been done for the
     * current_current_providing host
     */
    void resolve_current_providing_host_a();

    /**
     * list of signals to disconnect on destruction
     */
    std::list<sigc::connection> connected_signals;

    /**
     * handle results of SRV queries to the DNS
     */
    void on_srv_query_result(xmppd::lwresc::lwresult const &result);

    /**
     * handle results of AAAA queries to the DNS
     */
    void on_aaaa_query_result(xmppd::lwresc::lwresult const &result);

    /**
     * handle results of A queries to the DNS
     */
    void on_a_query_result(xmppd::lwresc::lwresult const &result);

    /**
     * buffer taking the result of resolving the job
     */
    std::ostringstream result_buffer;

    /**
     * listeners to get notified if the resolver_job is finished
     */
    std::list<sigc::signal<void, resolver_job &>> result_listeners;

    /**
     * timestamp when the resolver job has been generated
     */
    time_t timestamp;

    /**
     * ID of the resolver job
     */
    long serial;

    /**
     * the next serial that will be used for a new job
     */
    static long next_serial;

    friend std::ostream &operator<<(std::ostream &out, resolver_job &job);
};

std::ostream &operator<<(std::ostream &out, resolver_job &job);

/**
 * @brief resolver component implementation
 *
 * This class implements a component to the xmppd that does the resolving for
 * the server. The component implements the XMPP/xmppd specific tasks and
 * delegates the actual resolving to an instance of lwresd (which has to be
 * installed and configured separately.
 */
class resolver : public instance_base {
  public:
    /**
     * construct a resolver instance
     *
     * @param i the ::instance to construct a resolver for
     * @param x the configuration element that caused the instance to be created
     */
    resolver(instance i, xmlnode x);

    /**
     * get the list of services and resend destinations
     *
     * @return the list of services to resolve and there resend destinations
     */
    std::list<resend_service> const &get_resend_services();

    /**
     * sends a query to the lwresd
     *
     * @param query the query to send
     */
    void send_query(xmppd::lwresc::lwquery const &query);

    /**
     * registers a callback function for query results
     */
    sigc::connection register_result_callback(
        uint32_t serial,
        sigc::signal<void, xmppd::lwresc::lwresult const &>::slot_type const
            &callback);

  private:
    /**
     * resend a resolved packet to the configured service
     *
     * the packet may overwrite the destination where it wants to get resent to
     *
     * @param pkt the packet to resend
     * @param ips the resolving result to add to the packet
     * @param to the service to send the packet to (if not overwritten by the
     * pkt itself)
     */
    void resend_packet(xmlnode pkt, Glib::ustring ips, Glib::ustring to);

    /**
     * handles completed resolvings
     *
     * @param job the resolver_job that completed
     */
    void handle_completed_job(resolver_job &job);

    /**
     * handle received stanzas
     *
     * @param dp the stanza to handle
     * @return r_DONE when handled, r_ERR on error
     */
    result on_stanza_packet(dpacket dp);

    /**
     * handle received routed packets
     */
    result on_route_packet(dpacket dp);

    /**
     * create socket for lwresd access
     */
    void open_lwresd_socket();

    /**
     * callback for mio events
     *
     * @param m the mio that called the event
     * @param state the state that is signaled by this event
     * @param arg the resolver instance this event is for
     * @param x unused here
     * @param buffer possibly received data (depending on state)
     * @param bufsz size of the received data
     */
    static void mio_callback(mio m, int state, void *arg, xmlnode x,
                             char *buffer, int bufsz);

    /**
     * handler for mio events
     */
    void mio_event(mio m, int state, std::string const &buffer);

    /**
     * handler for MIO_BUFFER event
     */
    void mio_event_buffer(mio m, std::string const &buffer);

    /**
     * handler for MIO_CLOSED event
     */
    void mio_event_closed(mio m);

    /**
     * handler for MIO_ERROR event
     */
    void mio_event_error(mio m);

    /**
     * mio wrapped socket to the lwresd
     */
    mio lwresd_socket;

    /**
     * load configuration
     */
    void configurate();

    /**
     * the services to be tried for resolving and the resend destinations for
     * them
     */
    std::list<resend_service> resend_services;

    /**
     * resolving timeout
     *
     * time to wait at least (in seconds) for a resolving result)
     */
    int queue_timeout;

    /**
     * host lwresd is running on
     */
    Glib::ustring lwresd_host;

    /**
     * service lwresd is running as (i.e. port)
     */
    Glib::ustring lwresd_service;

    /**
     * the jobs currently being executed (resolving in progress) including the
     * packets that are waiting for the completition
     */
    xmppd::xhash<std::shared_ptr<resolver_job>> pending_jobs;

    /**
     * map containing the listeners for resolver results
     *
     * the key is the query serial which will be in the result
     * the value is a pair of the query time (for expiring) and the signal
     */
    std::map<
        uint32_t,
        std::pair<time_t, sigc::signal<void, xmppd::lwresc::lwresult const &>>>
        result_listeners;
};
} // namespace resolver
} // namespace xmppd
