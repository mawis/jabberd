/*
 * Copyright (c) 2008-2019 Matthias Wimmer
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

#ifndef __JABBERID_HH
#define __JABBERID_HH

namespace xmppd {

/**
 * The jabberid class represents a jid address on the xmpp network
 */
class jabberid {
  public:
    /**
     * create a new jabberid instance initializing the address by parsing a
     * string
     *
     * @param jid the initial address value
     * @throws std::invalid_argument if the jid cannot be prepared
     */
    jabberid(const Glib::ustring &jid);

    /**
     * sets the node part of a jabberid
     *
     * @param node the node to set (empty string to clear node)
     * @throws std::invalid_argument if the node cannot be prepared
     */
    void set_node(const Glib::ustring &node);

    /**
     * sets the domain part of a jabberid
     *
     * @param domain the domain to set
     * @throws std::invalid_argument if the domain cannot be prepared
     */
    void set_domain(const Glib::ustring &domain);

    /**
     * sets the resource part of a jabberid
     *
     * @param resource the resource to set (empty string to clear resource)
     * @throws std::invalid_argument if the resource cannot be prepared
     */
    void set_resource(const Glib::ustring &resource);

    /**
     * get the node part of a jabberid
     *
     * @return the node part, empty string if no node
     */
    const Glib::ustring &get_node() { return node; };

    /**
     * returns if a jabberid has a node
     *
     * @return true if the jabberid has a node
     */
    bool has_node() { return node.length() > 0; };

    /**
     * get the domain part of a jabberid
     *
     * @return the domain part
     */
    const Glib::ustring &get_domain() { return domain; };

    /**
     * get the resource part of a jabberid
     *
     * @return the resource part, empty string if no resource
     */
    const Glib::ustring &get_resource() { return resource; };

    /**
     * returns if a jabberid has a resource
     *
     * @return true if the jabberid has a resource
     */
    bool has_resource() { return resource.length() > 0; };

    /**
     * compare jabberid instance with another instance
     *
     * @param otherjid the other jabberid to compare with
     * @return true if both jabberid instances represent the same JIDs, false
     * else
     */
    bool operator==(const jabberid &otherjid);

    /**
     * compare some parts of two jabberid instances
     *
     * @param otherjid the other jabberid to compare with
     * @param compare_resource true if the resource part should get compared
     * @param compare_node true if the node part should get compared
     * @param compare_domain true if the domain part should get compared
     * @return true if the compared parts of the jabberid instances are matching
     */
    bool compare(const jabberid &otherjid, bool compare_resource = false,
                 bool compare_node = true, bool compare_domain = true);

    /**
     * get a copy of the jid without the resource
     *
     * @return new jabberid instance representing the same jabberid but without
     * resource
     */
    jabberid get_user();

    /**
     * get the textual representation of a jabberid
     *
     * @return the textual representation
     */
    Glib::ustring full();

  private:
    /**
     * node part of the JID (the part before the @ sign)
     *
     * empty string of no node
     */
    Glib::ustring node;

    /**
     * domain part of the JID
     *
     * there must always be a domain part in a JID
     */
    Glib::ustring domain;

    /**
     * resource part of the JID
     *
     * empty strong for no resource
     */
    Glib::ustring resource;
};

/**
 * jabberid_pool is a child class of jabberid, that is used to implement
 * the compatibility layer for existing code, that expect a jid to have
 * an associated pool
 */
class jabberid_pool : public jabberid {
  public:
    /**
     * construct a jabberid_pool with an existing assigned pool
     *
     * @param jid initial jabberid
     * @param p the pool to assign
     * @throws std::invalid_argument if the JID is not valid
     */
    jabberid_pool(const Glib::ustring &jid, ::pool p);

    /**
     * get the textual representation of a jabberid (allocated in pooled memory
     *
     * @return the textual representation
     */
    char *full_pooled();

    /**
     * sets the node part of a jabberid
     *
     * @param node the node to set (empty string to clear node)
     * @throws std::invalid_argument if the node cannot be prepared
     */
    void set_node(const Glib::ustring &node);

    /**
     * sets the domain part of a jabberid
     *
     * @param domain the domain to set
     * @throws std::invalid_argument if the domain cannot be prepared
     */
    void set_domain(const Glib::ustring &domain);

    /**
     * sets the resource part of a jabberid
     *
     * @param resource the resource to set (empty string to clear resource)
     * @throws std::invalid_argument if the resource cannot be prepared
     */
    void set_resource(const Glib::ustring &resource);

    /**
     * the the pool of this jabberid_pool
     *
     * @return pool of this jabberid_pool
     */
    pool get_pool() { return p; };

    /**
     * helper pointer to construct legacy lists
     */
    jabberid_pool *next;

  private:
    /**
     * assigned pool
     *
     * this pool is not used by jabberid_pool in any way!
     */
    ::pool p;

    /**
     * cached string version of jid (allocated from the assigned pool)
     *
     * @return the textual representation
     */
    char *jid_full;
};
} // namespace xmppd

#endif // __JABBERID_HH
