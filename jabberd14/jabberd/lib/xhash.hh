/*
 * Copyrights
 *
 * Portions created by or assigned to Jabber.com, Inc. are
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2019 Matthias Wimmer
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

#ifndef __XHASH_HH
#define __XHASH_HH

namespace xmppd {

/**
 * a class implementing a hash with std::string as key and void* as value
 *
 * This is a replacement for the xht structure in older versions of jabberd14
 * and the xhash_...() functions are mapped to method calls on this object.
 *
 * @todo This dynamically maps to either a map or an unordered_map if available.
 * This depends on a test made in the configure script. But we should not depend
 * on definitions in config.h (i.e. definitions made by the configure script) in
 * files we do install. This should be fixed before this code gets released.
 */
template <class value_type>
class xhash : public std::unordered_map<std::string, value_type> {
  public:
    /**
     * get an entry from the hash but consider the key to be a domain
     *
     * This accesor function also matches if the domainkey is a 'subdomain' for
     * a domain in the map. If there are multiple matches, the most specific one
     * is returned. If no match can be found,
     * "*" is tried as a default key.
     *
     * @param domainkey the key that should be considered as a domain
     * @return iterator to the found value
     */
    typename xhash<value_type>::iterator get_by_domain(std::string domainkey);
};
} // namespace xmppd

typedef xmppd::xhash<void *> *xht;

xht xhash_new(int prime);
void xhash_put(xht h, const char *key, void *val);
void *xhash_get(xht h, const char *key);
void *xhash_get_by_domain(xht h, const char *domain);
void xhash_zap(xht h, const char *key);
void xhash_free(xht h);
typedef void (*xhash_walker)(xht h, const char *key, void *val, void *arg);
void xhash_walk(xht h, xhash_walker w, void *arg);

// TODO
// xhash_to_xml and xhash_from_xml is defined in xmlnode.hh due to
// cross dependencies => needs to get fixed!

#endif // __XHASH_HH
