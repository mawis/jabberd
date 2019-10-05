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

#ifndef __XMLNODE_HH
#define __XMLNODE_HH

#include "str.hh"
#include "xhash.hh"

#include <list>
#include <vector>

#define NTYPE_TAG 0    /**< xmlnode is an element (tag) */
#define NTYPE_ATTRIB 1 /**< xmlnode is an attribute node */
#define NTYPE_CDATA 2  /**< xmlnode is a text node (!) */

#define NTYPE_LAST 2   /**< highest possible value of xmlnode types */
#define NTYPE_UNDEF -1 /**< xmlnode has no defined type */

#define XMLNS_SEPARATOR                                                        \
    ' ' /**< character used to separate NS IRI from local name in expat        \
           callbacks */

typedef struct xmlnode_t _xmlnode, *xmlnode;

namespace xmppd {

/**
 * This class represents and manages a list of bindings from namespace prefixes
 * to namespace IRIs
 */
class ns_decl_list : private std::list<std::pair<std::string, std::string>> {
  public:
    ns_decl_list();
    ns_decl_list(const xmlnode node);
    void update(const std::string &prefix, const std::string &ns_iri);
    void delete_last(const std::string &prefix);
    char const *get_nsprefix(const std::string &iri) const;
    char const *get_nsprefix(const std::string &iri,
                             bool accept_default_prefix) const;
    char const *get_nsiri(const std::string &prefix) const;
    bool check_prefix(const std::string &prefix,
                      const std::string &ns_iri) const;

  private:
};

} // namespace xmppd

/**
 * container, that contains a vector of xmlnodes
 *
 * This has been a pointer to a special struct in former versions of jabberd14,
 * but we are now using a standard container. Declaring this type to keep the
 * syntax of the interface. So don't be confused by the name of this type, it
 * is not a single item but the complete vector.
 */
typedef std::vector<xmlnode> xmlnode_vector;

/* Node creation routines */
xmlnode xmlnode_wrap(xmlnode x, const char *wrapper);
xmlnode xmlnode_wrap_ns(xmlnode x, const char *name, const char *prefix,
                        const char *ns_iri);
xmlnode xmlnode_new_tag(const char *name);
xmlnode xmlnode_new_tag_ns(const char *name, const char *prefix,
                           const char *ns_iri);
xmlnode xmlnode_new_tag_pool(pool p, const char *name);
xmlnode xmlnode_new_tag_pool_ns(pool p, const char *name, const char *prefix,
                                const char *ns_iri);
xmlnode xmlnode_insert_tag(xmlnode parent, const char *name);
xmlnode xmlnode_insert_tag_ns(xmlnode parent, const char *name,
                              const char *prefix, const char *ns_iri);
xmlnode xmlnode_insert_cdata(xmlnode parent, const char *CDATA, ssize_t size);
xmlnode xmlnode_insert_tag_node(xmlnode parent, xmlnode node);
void xmlnode_insert_node(xmlnode parent, xmlnode node);
xmlnode xmlnode_dup(xmlnode x); /* duplicate x */
xmlnode xmlnode_dup_pool(pool p, xmlnode x);

/* Node Memory Pool */
pool xmlnode_pool(xmlnode node);

/* Node editing */
void xmlnode_hide(xmlnode child);
void xmlnode_hide_attrib(xmlnode parent, char const *name);
void xmlnode_hide_attrib_ns(xmlnode parent, char const *name,
                            char const *ns_iri);

/* Node deletion routine, also frees the node pool! */
void xmlnode_free(xmlnode node);

/* Locates a child tag by name and returns it */
xmlnode xmlnode_get_tag(xmlnode parent, char const *name);
char *xmlnode_get_tag_data(xmlnode parent, char const *name);
xmlnode_vector xmlnode_get_tags(xmlnode context_node, char const *path,
                                xht namespaces);
xmlnode xmlnode_get_list_item(const xmlnode_vector &first, unsigned int i);
char *xmlnode_get_list_item_data(const xmlnode_vector &first, unsigned int i);
xmlnode xmlnode_select_by_lang(const xmlnode_vector &nodes, const char *lang);

/* Attribute accessors */
void xmlnode_put_attrib(xmlnode owner, const char *name, const char *value);
void xmlnode_put_attrib_ns(xmlnode owner, const char *name, const char *prefix,
                           const char *ns_iri, const char *value);
char *xmlnode_get_attrib(xmlnode owner, const char *name);
char *xmlnode_get_attrib_ns(xmlnode owner, const char *name,
                            const char *ns_iri);
const char *xmlnode_get_lang(xmlnode node);

/* Node traversal routines */
xmlnode xmlnode_get_firstattrib(xmlnode parent);
xmlnode xmlnode_get_firstchild(xmlnode parent);
xmlnode xmlnode_get_lastchild(xmlnode parent);
xmlnode xmlnode_get_nextsibling(xmlnode sibling);
xmlnode xmlnode_get_prevsibling(xmlnode sibling);
xmlnode xmlnode_get_parent(xmlnode node);

/* Node information routines */
char *xmlnode_get_name(xmlnode node);
char *xmlnode_get_data(xmlnode node);
int xmlnode_get_type(xmlnode node);
const char *xmlnode_get_localname(xmlnode node);
const char *xmlnode_get_namespace(xmlnode node);
const char *xmlnode_get_nsprefix(xmlnode node);
void xmlnode_change_namespace(xmlnode node, const char *ns_iri);

int xmlnode_has_children(xmlnode node);

/* Node-to-string translation */
char *xmlnode_serialize_string(xmlnode_t const *node,
                               const xmppd::ns_decl_list &nslist,
                               int stream_type);

#define NSCHECK(x, n) (j_strcmp(xmlnode_get_namespace(x), n) == 0)

// TODO: the following actually is inside xhash.cc, but I cannot
//       move it to xhash.hh due to cross dependencies between
//       xhash.cc and xmlnode.cc => needs to get fixed!

/* conversion between xhash to xml */
xmlnode xhash_to_xml(xht h);
xht xhash_from_xml(xmlnode hash, pool p);

#endif // __XMLNODE_HH
