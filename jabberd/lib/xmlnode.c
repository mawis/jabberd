/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * --------------------------------------------------------------------------*/

/**
 * @file xmlnode.c
 * @brief handling of XML documents in a DOM like way
 */

#include <jabberdlib.h>

/* Internal routines */

/**
 * create a new xmlnode element
 *
 * @param p existing memory pool to use, if NULL a new memory pool will be created
 * @param name local name of the element to be created (ignored for NTYPE_CDATA)
 * @param prefix namespace prefix of the element (NULL for no prefix, ignored for NTYPE_CDATA)
 * @param ns_iri namespace IRI of the element (ignored for NTYPE_CDATA)
 * @param type type of the element to be created (NTYPE_CDATA, NTYPE_TAG, NTYPE_ATTRIB)
 * @return the new xmlnode, NULL on failure
 */
static xmlnode _xmlnode_new(pool p, const char* name, const char *prefix, const char *ns_iri, unsigned int type) {
    xmlnode result = NULL;
    if (type > NTYPE_LAST)
        return NULL;

    if (type != NTYPE_CDATA && name == NULL)
        return NULL;

    if (p == NULL) {
        p = pool_heap(1*1024);
    }

    /* Allocate & zero memory */
    result = (xmlnode)pmalloco(p, sizeof(_xmlnode));

    /* Initialize fields */
    if (type != NTYPE_CDATA) {
        result->name   = pstrdup(p, name);
	result->prefix = pstrdup(p, prefix);
	result->ns_iri = pstrdup(p, ns_iri);
    }
    result->type = type;
    result->p = p;
    return result;
}

/**
 * create a new xmlnode as a sibling of an existing xmlnode
 *
 * @note the sibling given as lastsibling has to be the last sibling in the list of siblings
 *
 * @param lastsibling last sibling in a list of siblings, where the new sibling should be added
 * @param name local name of the new sibling
 * @param prefix namespace prefix of the new sibling (NULL for default prefix)
 * @param ns_iri namespace IRI of the new sibling
 * @param type type of the new sibling (NTYPE_TAG, NTYPE_CDATA, NTYPE_ATTRIB)
 * @return the new xmlnode, NULL on failure
 */
static xmlnode _xmlnode_append_sibling(xmlnode lastsibling, const char* name, const char *prefix, const char *ns_iri, unsigned int type) {
    xmlnode result;

    result = _xmlnode_new(xmlnode_pool(lastsibling), name, prefix, ns_iri, type);
    if (result != NULL) {
        /* Setup sibling pointers */
        result->prev = lastsibling;
        lastsibling->next = result;
    }
    return result;
}

/**
 * create a new xmlnode as a child of an existing xmlnode
 *
 * The xmlnode may already contain child nodes, in that case the new xmlnode is added as a sibling to the existing childs.
 *
 * @param parent the xmlnode, that becomes parent of the new xmlnode
 * @param name the local name of the new sibling (ignored for NTYPE_CDATA)
 * @param prefix namespace prefix of the new sibling (NULL for default prefix)
 * @param ns_iri namespace IRI of the new sibling
 * @param type type of the new sibling (NTYPE_TAG, NTYPE_CDATA, NTYPE_ATTRIB)
 * @return the new xmlnode, NULL on failure
 */
static xmlnode _xmlnode_insert(xmlnode parent, const char* name, const char *prefix, const char *ns_iri, unsigned int type) {
    xmlnode result;

    if (parent == NULL || (type != NTYPE_CDATA && name == NULL))
	return NULL;

    /* If parent->firstchild is NULL, simply create a new node for the first child */
    if (parent->firstchild == NULL) {
        result = _xmlnode_new(parent->p, name, prefix, ns_iri, type);
        parent->firstchild = result;
    } else {
	/* Otherwise, append this to the lastchild */
        result= _xmlnode_append_sibling(parent->lastchild, name, prefix, ns_iri, type);
    }
    result->parent = parent;
    parent->lastchild = result;
    return result;
}

/**
 * Walk the sibling list, looging for a xmlnode of the specified name and type
 *
 * @param firstsibling where to start seaching in a list of siblings
 * @param name local name of the sibling to search for
 * @param ns_iri namespace IRI of the sibling to search for (NULL to ignore namespaces, or on NTYPE_ATTRIB to match prefix-less attributes)
 * @param type type of the sibling to search for
 * @return found xmlnode or NULL if no such xmlnode
 */
static xmlnode _xmlnode_search(xmlnode firstsibling, const char* name, const char *ns_iri, unsigned int type) {
    xmlnode current;

    /* iterate on the siblings */
    for (current = firstsibling; current != NULL; current = current->next) {
	if ((current->type == type)
		&& (j_strcmp(current->name, name) == 0 || (current->name == NULL && name == NULL))
		&& (j_strcmp(current->ns_iri, ns_iri) == 0 || (ns_iri == NULL && (type != NTYPE_ATTRIB  || ns_iri == current->ns_iri))))
	    return current;
    }

    /* nothing found */
    return NULL;
}

/**
 * merge multiple xmlnodes siblings of type NTYPE_CDATA to one xmlnode
 *
 * @param data first xmlnode in a list of NTYPE_CDATA siblings
 */
static void _xmlnode_merge(xmlnode data) {
    xmlnode cur;
    char *merge, *scur;
    int imerge;

    /* get total size of all merged cdata */
    imerge = 0;
    for (cur = data; cur != NULL && cur->type == NTYPE_CDATA; cur = cur->next)
        imerge += cur->data_sz;

    /* copy in current data and then spin through all of them and merge */
    scur = merge = pmalloc(data->p,imerge + 1);
    for (cur = data; cur != NULL && cur->type == NTYPE_CDATA; cur = cur->next) {
        memcpy(scur,cur->data,cur->data_sz);
        scur += cur->data_sz;
    }
    *scur = '\0';

    /* this effectively hides all of the merged-in chunks */
    data->next = cur;
    if (cur == NULL)
        data->parent->lastchild = data;
    else
        cur->prev = data;

    /* reset data */
    data->data = merge;
    data->data_sz = imerge;
}

/**
 * hide an xmlnode in a list of siblings (remove it from the list)
 *
 * @param child the xmlnode to hide
 */
static void _xmlnode_hide_sibling(xmlnode child) {
    if (child == NULL)
        return;

    if (child->prev != NULL)
        child->prev->next = child->next;
    if (child->next != NULL)
        child->next->prev = child->prev;
}

/**
 * check if a namespace prefix is already declared as we need it
 *
 * @param nslist_last pointer to the last element in the list of already printed namespace prefix declarations
 * @return 1 if the namespace prefix is already declared as we need it, 0 else
 */
static int _xmlnode_check_prefix(ns_list_item nslist_last, const char *prefix, const char *ns_iri) {
    ns_list_item cur = NULL;

    /* iterate backwards on the list */
    for (cur = nslist_last; cur != NULL; cur = cur->prev) {
	if (j_strcmp(prefix, cur->prefix) == 0 || (prefix == NULL && cur->prefix == NULL)) {
	    /* prefix is already declared, does it have the same namespace or do you have to redeclare? */
	    return j_strcmp(ns_iri, cur->ns_iri) == 0 ? 1 : 0;
	}
    }

    /* prefix not found at all */
    return 0;
}

/**
 * print an xmlnode document to a spool
 *
 * This is a recursive function.
 *
 * @param s the spool to print the xmlnode to
 * @param x the xmlnode to print
 * @param nslist_first pointer to the first element in the list of already printed namespace prefix declarations
 * @param nslist_last pointer to the last element in the list of already printed namespace prefix declarations
 * @param ns_replace 0 for no namespace IRI replacing, 1 for replacing 'jabber:server' namespace with 'jabber:client', 2 for replacing 'jabber:server' namespace with 'jabber:component:accept'
 */
static void _xmlnode_serialize(spool s, xmlnode x, ns_list_item nslist_first, ns_list_item nslist_last, int ns_replace) {
    xmlnode cur = NULL;
    xht this_level_prefixes = NULL;
    int has_childs = 0;
    ns_list_item stored_nslist_last = nslist_last;

    /* NTYPE_CDATA and NTYPE_ATTRIB are printed inside, we don't handle them as direct arguments! */
    if (x->type != NTYPE_TAG) {
	return;
    }

    /* create a hash of prefix declarations done at this level */
    this_level_prefixes = xhash_new(101);

    /* write the start tag */
    spool_add(s, "<");
    if (x->prefix != NULL) {
	spool_add(s, x->prefix);
	spool_add(s, ":");
    }
    spool_add(s, x->name);

    /* do we have to declare the namespace of this element's name? */
    if (_xmlnode_check_prefix(nslist_last, x->prefix, x->ns_iri) == 0) {
	if (x->prefix == NULL) {
	    spool_add(s, " xmlns='");
	} else {
	    spool_add(s, " xmlns:");
	    spool_add(s, x->prefix);
	    spool_add(s, "='");
	}
	if (ns_replace && j_strcmp(x->ns_iri, NS_SERVER) == 0) {
	    switch (ns_replace) {
		case 1:
		    spool_add(s, NS_CLIENT);
		    break;
		case 2:
		    spool_add(s, NS_COMPONENT_ACCEPT);
		    break;
		default:
		    spool_add(s, NS_SERVER);
	    }
	} else {
	    spool_add(s, strescape(s->p, x->ns_iri));
	}
	spool_add(s, "'");

	xhash_put(this_level_prefixes, x->prefix ? x->prefix : "", x->ns_iri);

	xmlnode_update_decl_list(s->p, &nslist_first, &nslist_last, x->prefix, x->ns_iri);
    }

    /* print attributes, that do not declare a namespace */
    for (cur = xmlnode_get_firstattrib(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	if (j_strcmp(cur->ns_iri, NS_XMLNS) == 0) {
	    /* it is a namespace prefix declaration */
	    continue;
	}

	spool_add(s, " ");

	/* does this attribute has a namespace? If yes: do you have to declare it? */
	if (cur->prefix) {
	    if (j_strcmp(cur->prefix, "xml") != 0) {
		if (_xmlnode_check_prefix(nslist_last, cur->prefix, cur->ns_iri) == 0) {
		    /* we need to declare the namespace */
		    /* XXX: do we conflict a namespace declaration in this element? We have to rename the prefix then? */

		    spool_add(s, "xmlns");
		    if (cur->prefix != NULL) {
			spool_add(s, ":");
			spool_add(s, cur->prefix);
		    }
		    spool_add(s, "='");
		    if (ns_replace && j_strcmp(x->ns_iri, NS_SERVER) == 0) {
			switch (ns_replace) {
			    case 1:
				spool_add(s, NS_CLIENT);
				break;
			    case 2:
				spool_add(s, NS_COMPONENT_ACCEPT);
				break;
			    default:
				spool_add(s, NS_SERVER);
			}
		    } else {
			spool_add(s, strescape(s->p, cur->ns_iri));
		    }
		    spool_add(s, "' ");

		    xhash_put(this_level_prefixes, cur->prefix ? cur->prefix : "", cur->ns_iri);

		    xmlnode_update_decl_list(s->p, &nslist_first, &nslist_last, cur->prefix, cur->ns_iri);
		}
	    }

	    spool_add(s, cur->prefix); /* XXX probably use renamed prefix! */
	    spool_add(s, ":");
	}

	spool_add(s, cur->name);
	spool_add(s, "='");
	spool_add(s, strescape(s->p, xmlnode_get_data(cur)));
	spool_add(s, "'");
    }

    /* print namespace declarations for namespaces, that are not yet declared */
    for (cur = xmlnode_get_firstattrib(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	if (j_strcmp(cur->ns_iri, NS_XMLNS) != 0) {
	    /* normal attribute, not a namespace declaration */
	    continue;
	}
	
	/* already declared here or at higher level? */
	if (xhash_get(this_level_prefixes, cur->prefix ? cur->name : "") != NULL || _xmlnode_check_prefix(nslist_last, cur->prefix ? cur->name : NULL, xmlnode_get_data(cur)) == 1) {
	    /* yes, no need to print */
	    continue;
	}

	/* print the declaration */
	spool_add(s, " ");
	if (cur->prefix != NULL) {
	    spool_add(s, cur->prefix);
	    spool_add(s, ":");
	}
	spool_add(s, cur->name);
	spool_add(s, "='");
	if (ns_replace && j_strcmp(xmlnode_get_data(cur), NS_SERVER) == 0) {
	    switch (ns_replace) {
		case 1:
		    spool_add(s, NS_CLIENT);
		    break;
		case 2:
		    spool_add(s, NS_COMPONENT_ACCEPT);
		    break;
		default:
		    spool_add(s, NS_SERVER);
	    }
	} else {
	    spool_add(s, strescape(s->p, xmlnode_get_data(cur)));
	}
	spool_add(s, "'");
    }

    /* we don't need the list of prefixes defined at this level anymore */
    xhash_free(this_level_prefixes);
    this_level_prefixes = NULL;
  
    /* write childs */
    for (cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur)) {
	/* close the start tag now? */
	if (has_childs == 0) {
	    spool_add(s,">");
	    has_childs = 1;
	}

	switch (cur->type) {
	    case NTYPE_TAG:
		_xmlnode_serialize(s, cur, nslist_first, nslist_last, ns_replace);
		break;
	    case NTYPE_CDATA:
		spool_add(s, strescape(s->p, xmlnode_get_data(cur)));
	}
    }

    /* write the end tag */
    if (has_childs > 0) {
	spool_add(s, "</");
	if (x->prefix != NULL) {
	    spool_add(s, x->prefix);
	    spool_add(s, ":");
	}
	spool_add(s, x->name);
	spool_add(s, ">");
    } else {
	spool_add(s, "/>");
    }

    /* update ns_list: remove what we added */
    if (stored_nslist_last != NULL) {
	stored_nslist_last->next = NULL;
    }
}

/**
 * check if an xmlnode has attributes
 *
 * @param node the xmlnode to check
 * @return 1 if the node has attributes, 0 else
 */
static int _xmlnode_has_attribs(xmlnode node) {
    if ((node != NULL) && (node->firstattrib != NULL))
	return 1;
    return 0;
}

/**
 * get the size (string length) of text contained in the element node
 *
 * @param node the element to check the length of the contained text for
 * @return length of the contained text
 */
static int _xmlnode_get_datasz(xmlnode node) {
    if (xmlnode_get_type(node) != NTYPE_CDATA)
	return 0;

    /* check for a dirty node w/ unassembled cdata chunks */
    if (xmlnode_get_type(node->next) == NTYPE_CDATA)
	_xmlnode_merge(node);
    return node->data_sz;
}

/**
 * helper function for xmlnode_get_tags()
 *
 * Appends xmlnode node, if the predicate matches. If there is a next_step, not the xmlnode is added itself,
 * but the result of an xmlnode_get_tags() recursion is added
 *
 * @param result_first pointer to the pointer to the first list element of the result (gets modified)
 * @param result_last pointer to the pointer to the first list element of the result (gets modified)
 * @param node the node, that should be appended if there is no next_step, or which should be the parent node for the next_step
 * @param predicate the predicate for this step
 * @param next_step the next step for recursion
 */
static void _xmlnode_append_if_predicate(xmlnode_list_item *result_first, xmlnode_list_item *result_last, xmlnode node, char *predicate, const char *next_step, xht namespaces) {
    xmlnode_list_item sub_result = NULL;

    /* sanity checks */
    if (result_first == NULL || result_last == NULL || node == NULL || namespaces == NULL)
	return;

    /* check the predicate */
    if (predicate != NULL) {
	char *attrib_ns_iri = NULL;
	char *attrib_name = NULL;
	char *attrib_value = NULL;
	xmlnode iter = NULL;
	int predicate_matched = 0;

	/* we only support checking for attribute existence or attribute values for now */
	if (predicate[0] != '@') {
	    /* do not add, we do not support the predicate :-( */
	    return;
	}

	/* skip the '@' */
	predicate++;

	/* make a copy of the predicate, so we can modify it */
	predicate = pstrdup(xmlnode_pool(node), predicate);

	/* is there a value we have to match? */
	attrib_value = strchr(predicate, '=');
	if (attrib_value != NULL) {
	    attrib_value[0] = 0;
	    attrib_value++;

	    /* remove quotes */
	    if (attrib_value[0] != 0) {
		attrib_value++;
		if (attrib_value[0] != 0) {
		    attrib_value[j_strlen(attrib_value)-1] = 0;
		}
	    }
	}

	/* get the namespace of the attribute */
	attrib_name = strchr(predicate, ':');
	if (attrib_name == NULL) {
	    attrib_name = predicate;
	    attrib_ns_iri = NULL;
	} else {
	    attrib_name[0] = 0;
	    attrib_name++;
	    attrib_ns_iri = xhash_get(namespaces, predicate);
	}

	/* iterate over the namespace attributes */
	for (iter = xmlnode_get_firstattrib(node); iter != NULL; iter = xmlnode_get_nextsibling(iter)) {

	    /* attribute differs in name? */
	    if (j_strcmp(attrib_name, iter->name) != 0) {
		continue;
	    }

	    /* attribute differs in namespace IRI? */
	    if (j_strcmp(attrib_ns_iri, iter->ns_iri) != 0 && !(attrib_ns_iri == NULL && iter->ns_iri == NULL)) {
		continue;
	    }

	    /* we have to check the value and it differs */
	    if (attrib_value != NULL && j_strcmp(attrib_value, xmlnode_get_data(iter)) != 0) {
		continue;
	    }

	    /* predicate matches! */
	    predicate_matched = 1;
	    break;
	    
	}

	/* return without adding anything if the predicate did not match */
	if (!predicate_matched)
	    return;
    }

    /* when we are here: no predicate, or predicate matched */

    /* if no next_step, than add the node to the list and return */
    if (next_step == NULL) {
	xmlnode_list_item result_item = pmalloco(xmlnode_pool(node), sizeof(_xmlnode_list_item));
	result_item->node = node;

	/* first item in list? */
	if (*result_first == NULL)
	    *result_first = result_item;

	/* is there already a last item */
	if (*result_last != NULL)
	    (*result_last)->next = result_item;

	/* this is now the last item */
	*result_last = result_item;

	return;
    }

    /* there is a next_step, we have to recurse */
    sub_result = xmlnode_get_tags(node, next_step, namespaces);

    /* did we get a result we have to add? */
    while (sub_result != NULL) {
	xmlnode_list_item result_item = pmalloco(xmlnode_pool(node), sizeof(_xmlnode_list_item));
	result_item->node = sub_result->node;

	/* first item in list? */
	if (*result_first == NULL)
	    *result_first = result_item;

	/* is there already a last item */
	if (*result_last != NULL)
	    (*result_last)->next = result_item;

	/* this is now the last item */
	*result_last = result_item;

	/* iterate */
	sub_result = sub_result->next;
    }
}

/* External routines */


/**
 * create a tag node
 *
 * @deprecated This function is not aware of namespaces, use xmlnode_new_tag_ns() instead
 * 
 * Automatically creates a memory pool for the node.
 * The namespace is declared to be 'jabber:server'.
 *
 * @param name name of the tag
 * @return a pointer to the new tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag(const char* name) {
    if (name == NULL)
	return NULL;

    return xmlnode_new_tag_pool(pool_heap(1*1024), name);
}

/**
 * create a tag node, including a namespace declaration
 *
 * Automatically creates a memory pool for the node.
 *
 * @param name local name of the tag
 * @param prefix the namespace prefix of the tag (NULL for the default prefix)
 * @param ns_iri the namespace IRI of the tag
 * @return a pointer to the new tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag_ns(const char* name, const char* prefix, const char* ns_iri) {
    if (name == NULL)
	return NULL;

    return xmlnode_new_tag_pool_ns(pool_heap(1*1024), name, prefix, ns_iri);
}


/**
 * create a tag node within given pool
 *
 * The namespace is declared to be 'jabber:server'.
 *
 * @deprecated This function is not aware of namespaces, use xmlnode_new_tag_pool_ns() instead
 *
 * @param p previously created memory pool
 * @param name name of the tag
 * @return a pointer to the tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag_pool(pool p, const char* name) {
    const char *local_name = NULL;
    xmlnode result = NULL;
    char *prefix = NULL;
    const char *ns_iri = NS_SERVER;

    if (name == NULL)
        return NULL;

    local_name = strchr(name, ':');
    if (local_name == NULL)
        local_name = name;
    else
        local_name++;

    if (local_name > name) {
        prefix = pmalloco(p, local_name-name);
        snprintf(prefix, local_name-name, "%s", name);

        if (j_strcmp(prefix, "db") == 0)
            ns_iri = NS_DIALBACK;
        else if (j_strcmp(prefix, "stream") == 0)
            ns_iri = NS_STREAM;
    }

    result = _xmlnode_new(p, local_name, prefix, ns_iri, NTYPE_TAG);

    return result;
}

/**
 * create a tag node within a given pool, including a namespace declaration
 *
 * @param p previously created memory pool
 * @param name local name of the tag
 * @param prefix the namespace prefix of the tag (NULL for the default prefix)
 * @param ns_iri the namespace IRI of the tag
 * @return a pointer to the new tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag_pool_ns(pool p, const char* name, const char* prefix, const char* ns_iri) {
    xmlnode result = NULL;

    /* 'jabber:client' and 'jabber:component:accept' are represented as 'jabber:server' internally */
    if (j_strcmp(ns_iri, NS_CLIENT) == 0)
	ns_iri = NS_SERVER;
    else if (j_strcmp(ns_iri, NS_COMPONENT_ACCEPT) == 0)
	ns_iri = NS_SERVER;

    result = _xmlnode_new(p, name, prefix, ns_iri, NTYPE_TAG);

    if (prefix == NULL) {
	xmlnode_put_attrib_ns(result, "xmlns", NULL, NS_XMLNS, ns_iri);
    } else {
	xmlnode_put_attrib_ns(result, prefix, "xmlns", NS_XMLNS, ns_iri);
    }

    return result;
}

/**
 * append a child tag to a tag
 *
 * @deprecated This function is not aware of namespaces, use xmlnode_insert_tag_ns() instead
 *
 * @param parent the xmlnode where the new element should be inserted
 * @param name name of the child tag
 * @return pointer to the child tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_insert_tag(xmlnode parent, const char* name) {
    const char *local_name = NULL;
    xmlnode result = NULL;

    if (name == NULL)
	return NULL;

    local_name = strchr(name, ':');
    if (local_name == NULL) {
	local_name = name;
    } else {
	local_name++;
    }

    result = _xmlnode_insert(parent, local_name, NULL, parent->ns_iri, NTYPE_TAG);
    if (result != NULL && local_name > name) {
	result->prefix = pmalloco(xmlnode_pool(result), local_name-name);
	snprintf(result->prefix, local_name-name, "%s", name);
    }
    
    return result;
}

/**
 * append a child tag to a tag, including namespace declaration
 *
 * @param parent the xmlnode where the new element should be inserted
 * @param name local name of the child tag
 * @param prefix namespace prefix of the child tag
 * @param ns_iri namespace IRI of the child tag
 * @return pointer to the child tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_insert_tag_ns(xmlnode parent, const char* name, const char* prefix, const char *ns_iri) {
    xmlnode new_node = NULL;
    
    /* 'jabber:client' and 'jabber:component:accept' are represented as 'jabber:server' internally */
    if (j_strcmp(ns_iri, NS_CLIENT) == 0)
	ns_iri = NS_SERVER;
    else if (j_strcmp(ns_iri, NS_COMPONENT_ACCEPT) == 0)
	ns_iri = NS_SERVER;
   
    new_node = _xmlnode_insert(parent, name, prefix, ns_iri, NTYPE_TAG);

    /* for compatibility with xmlnode users not aware of our namespace handling */
    if (parent != NULL && j_strcmp(parent->prefix, prefix) != 0) {
	if (prefix == NULL) {
	    xmlnode_put_attrib_ns(new_node, "xmlns", NULL, NS_XMLNS, ns_iri);
	} else {
	    xmlnode_put_attrib_ns(new_node, prefix, "xmlns", NS_XMLNS, ns_iri);
	}
    }

    return new_node;
}

/**
 * insert a text node as child to an existing xmlnode
 *
 * @param parent where to insert the new text node
 * @param CDATA content of the text node to insert
 * @param size size of the string in CDATA, or -1 for auto-detection on null-terminated strings
 * @return a pointer to the new child node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_insert_cdata(xmlnode parent, const char* CDATA, unsigned int size) {
    xmlnode result;

    if (CDATA == NULL || parent == NULL)
        return NULL;

    if (size == -1)
        size = strlen(CDATA);

    result = _xmlnode_insert(parent, NULL, NULL, NULL, NTYPE_CDATA);
    if (result != NULL) {
        result->data = (char*)pmalloc(result->p, size + 1);
        memcpy(result->data, CDATA, size);
        result->data[size] = '\0';
        result->data_sz = size;
    }

    return result;
}

/**
 * find given tag in an xmlnode tree
 *
 * @deprecated This function is not aware of namespaces, use xmlnode_get_tags(), and xmlnode_get_list_item() instead
 *
 * @param parent pointer to the parent tag
 * @param name "name" for the child tag of that name, "name/name" for a sub child (recurses), "?attrib" to match the first tag with that attrib defined, "?attrib=value" to match the first tag with that attrib and value, "=cdata" to match the text node contents of the child, or any combination: "name/name/?attrib", "name=cdata", etc
 * @return a pointer to the tag matching search criteria, or NULL if search was unsuccessfull
 */
xmlnode xmlnode_get_tag(xmlnode parent, const char* name) {
    char *str, *slash, *qmark, *equals;
    xmlnode step, ret;


    if (parent == NULL || parent->firstchild == NULL || name == NULL || name == '\0')
	return NULL;

    if (strstr(name, "/") == NULL && strstr(name,"?") == NULL && strstr(name, "=") == NULL)
        return _xmlnode_search(parent->firstchild, name, NULL, NTYPE_TAG);

    str = strdup(name);
    slash = strstr(str, "/");
    qmark = strstr(str, "?");
    equals = strstr(str, "=");

    if (equals != NULL && (slash == NULL || equals < slash) && (qmark == NULL || equals < qmark)) {
	/* of type =cdata */

        *equals = '\0';
        equals++;

        for (step = parent->firstchild; step != NULL; step = xmlnode_get_nextsibling(step)) {
            if (xmlnode_get_type(step) != NTYPE_TAG)
                continue;

            if (*str != '\0')
                if(j_strcmp(xmlnode_get_name(step),str) != 0)
                    continue;

            if (j_strcmp(xmlnode_get_data(step),equals) != 0)
                continue;

            break;
        }

        free(str);
        return step;
    }


    if (qmark != NULL && (slash == NULL || qmark < slash)) {
	/* of type ?attrib */

        *qmark = '\0';
        qmark++;
        if (equals != NULL) {
            *equals = '\0';
            equals++;
        }

        for (step = parent->firstchild; step != NULL; step = xmlnode_get_nextsibling(step)) {
            if (xmlnode_get_type(step) != NTYPE_TAG)
                continue;

            if (*str != '\0')
                if (j_strcmp(xmlnode_get_name(step),str) != 0)
                    continue;

            if (xmlnode_get_attrib(step,qmark) == NULL)
                continue;

            if (equals != NULL && j_strcmp(xmlnode_get_attrib(step,qmark),equals) != 0)
                continue;

            break;
        }

        free(str);
        return step;
    }


    *slash = '\0';
    ++slash;

    for (step = parent->firstchild; step != NULL; step = xmlnode_get_nextsibling(step)) {
        if (xmlnode_get_type(step) != NTYPE_TAG)
	    continue;

        if (j_strcmp(xmlnode_get_name(step),str) != 0)
            continue;

        ret = xmlnode_get_tag(step, slash);
        if (ret != NULL) {
            free(str);
            return ret;
        }
    }

    free(str);
    return NULL;
}

/**
 * at all xmlnodes that match a path
 *
 * The valid paths are a very small subset of xpath.
 *
 * The only predicates we support is for existence of attributes, or for attribute values,
 * we only support steps in the axis child and the axis must be ommited,
 * we support text() as a step.
 *
 * Examples:
 * - foo/bar/text()
 * - foo/bar[@baz='true']/text()
 * - foobar
 * - foobar[@attribute]
 * - *[@attribute='value']
 *
 * @param parent the xmlnode where to start the path
 * @param path the path (xpath like syntax, but only a small subset)
 * @param xht hashtable mapping namespace prefixes to namespace IRIs
 * @return first item in the list of xmlnodes, or NULL if no xmlnode matched the path
 */
xmlnode_list_item xmlnode_get_tags(xmlnode context_node, const char *path, xht namespaces) {
    char *this_step = NULL;
    const char *ns_iri = NULL;
    char *next_step = NULL;
    char *start_predicate = NULL;
    char *end_predicate = NULL;
    char *predicate = NULL;
    char *end_prefix = NULL;
    int axis = 0;	/* 0 = child, 1 = parent, 2 = attribute */
    xmlnode_list_item result_first = NULL;
    xmlnode_list_item result_last = NULL;
    xmlnode iter = NULL;

    /* sanity check */
    if (context_node == NULL || path == NULL || namespaces == NULL)
	return NULL;

    /* check if there is an axis */
    if (j_strncmp(path, "child::", 7) == 0) {
	path = path+7;
    } else if (j_strncmp(path, "parent::", 8) == 0) {
	axis = 1;
	path = path+8;
    } else if (j_strncmp(path, "attribute::", 11) == 0) {
	axis = 2;
	path = path+11;
    }

    /* separate this step from the next one, and check for a predicate in this step */
    start_predicate = strchr(path, '[');
    next_step = strchr(path, '/');
    if (start_predicate == NULL && next_step == NULL) {
	this_step = pstrdup(xmlnode_pool(context_node), path);
    } else if (start_predicate == NULL || start_predicate > next_step && next_step != NULL) {
	this_step = pmalloco(xmlnode_pool(context_node), next_step - path + 1);
	snprintf(this_step, next_step - path + 1, "%s", path);
	if (next_step != NULL)
	    next_step++;
    } else {

	end_predicate = strchr(start_predicate, ']');
	if (end_predicate == NULL) {
	    /* error in predicate syntax */
	    return NULL;
	}

	if (next_step != NULL) {
	    if (next_step < end_predicate)
		next_step = strchr(end_predicate, '/');
	    if (next_step != NULL)
		next_step++;
	}
	
	predicate = pmalloco(xmlnode_pool(context_node), end_predicate - start_predicate);
	snprintf(predicate, end_predicate - start_predicate, "%s", start_predicate+1);
	this_step = pmalloco(xmlnode_pool(context_node), start_predicate - path + 1);
	snprintf(this_step, start_predicate - path + 1, "%s", path);
    }

    /* check for the namespace IRI we have to match the node */
    end_prefix = strchr(this_step, ':');
    if (end_prefix == NULL) {
	/* default prefix (or NULL if axis is attribute::) */
	ns_iri = axis == 2 ? NULL : xhash_get(namespaces, "");
    } else {
	/* prefixed name */
	*end_prefix = 0;
	ns_iri = xhash_get(namespaces, this_step);
	this_step = end_prefix+1;
    }

    /* iterate over all child nodes, checking if this step matches them */
    for (
	    iter = axis == 0 ? xmlnode_get_firstchild(context_node) :
	    	axis == 1 ? xmlnode_get_parent(context_node) :
		axis == 2 ? xmlnode_get_firstattrib(context_node) :
		NULL;
	    iter != NULL;
	    iter = axis == 0 ? xmlnode_get_nextsibling(iter) :
	    	axis == 1 ? NULL :
		axis == 2 ? xmlnode_get_nextsibling(iter) :
		NULL) {

	if (this_step != NULL && this_step[0] == '*' && this_step[1] == 0) {
	    /* matching all nodes */

	    /* match ns_iri if prefix has been specified */
	    if (end_prefix != NULL) {
		if (iter->type == NTYPE_CDATA || j_strcmp(ns_iri, iter->ns_iri) != 0) {
		    continue;
		}
	    }

	    /* merging if it is a text node */
	    if (iter->type == NTYPE_CDATA)
		_xmlnode_merge(iter);

	    /* append to the result */
	    _xmlnode_append_if_predicate(&result_first, &result_last, iter, predicate, next_step, namespaces);

	    continue;
	}

	if (iter->type == NTYPE_CDATA && j_strcmp(this_step, "text()") == 0) {
	    /* matching text node */

	    /* merge all text nodes, that are direct siblings with this one */
	    _xmlnode_merge(iter);

	    /* append to the result */
	    _xmlnode_append_if_predicate(&result_first, &result_last, iter, predicate, next_step, namespaces);

	    continue;
	}

	if (iter->type != NTYPE_CDATA && (ns_iri == NULL && iter->ns_iri == NULL || j_strcmp(ns_iri, iter->ns_iri) == 0) && j_strcmp(this_step, iter->name) == 0) {
	    /* matching element or attribute */

	    /* append to the result */
	    _xmlnode_append_if_predicate(&result_first, &result_last, iter, predicate, next_step, namespaces);

	    continue;
	}
    }

    return result_first;
}

/**
 * return the text wrapped inside the element found by the name parameter
 *
 * this equals xmlnode_get_data(xmlnode_get_tag(parent, name))
 *
 * @deprecated This function is not aware of namespaces, use xmlnode_get_tags(), and xmlnode_get_list_item_data() instead
 *
 * @param parent the element where to search for the element defined by the name parameter
 * @param name search query for the element whichs textual content should be returned
 * @return textual content, or NULL if no textual content
 */
char *xmlnode_get_tag_data(xmlnode parent, const char *name) {
    xmlnode tag;

    tag = xmlnode_get_tag(parent, name);
    if (tag == NULL)
	return NULL;

    return xmlnode_get_data(tag);
}

/**
 * get that text wrapped by the (i+1)-th element in a list of xmlnodes
 *
 * @param first pointer to the first list item
 * @param i which item to use
 * @return textual content, or NULL if no textual content, or item not found
 */
char* xmlnode_get_list_item_data(xmlnode_list_item first, unsigned int i) {
    xmlnode tag;

    tag = xmlnode_get_list_item(first, i);
    if (tag == NULL)
	return NULL;

    return xmlnode_get_data(tag);
}

/**
 * change the namespace of a node
 *
 * @param node the node to change the namespace for
 * @param ns_iri the new namespace of the node
 */
void xmlnode_change_namespace(xmlnode node, const char *ns_iri) {
    /* santiy check */
    if (node == NULL)
	return;

    /* update the namespace */
    node->ns_iri = ns_iri ? pstrdup(xmlnode_pool(node), ns_iri) : NULL;

    /* is there an attribute declaring this namespace? */
    if (node->prefix == NULL) {
	if (xmlnode_get_attrib_ns(node, "xmlns", NS_XMLNS) != NULL)
	    xmlnode_put_attrib_ns(node, "xmlns", NULL, NS_XMLNS, ns_iri);
    } else {
	if (xmlnode_get_attrib_ns(node, node->prefix, NS_XMLNS) != NULL)
	    xmlnode_put_attrib_ns(node, node->prefix, "xmlns", NS_XMLNS, ns_iri);
    }
    
}
/**
 * add an attribute to an xmlnode element
 *
 * @deprecated This function is not aware of namespaces, use xmlnode_put_attrib_ns() instead
 *
 * @param owner element to add the attribute to
 * @param name name of the attribute
 * @param value value of the attribute
 */
void xmlnode_put_attrib(xmlnode owner, const char* name, const char* value) {
    const char *local_name = NULL;

    if (name == NULL)
	return;

    /* namespace declaration? */
    if (j_strncmp(name, "xmlns:", 6) == 0) {
	/* 'jabber:client' and 'jabber:component:accept' are represented as 'jabber:server' internally */
	if (j_strcmp(value, NS_CLIENT) == 0)
	    value = NS_SERVER;
	else if (j_strcmp(value, NS_COMPONENT_ACCEPT) == 0)
	    value = NS_SERVER;

	/* namespace prefix of the tag? */
	if (j_strcmp(name+6, owner->prefix) == 0) {
	    owner->ns_iri = pstrdup(owner->p, value);
	}
	return xmlnode_put_attrib_ns(owner, name+6, "xmlns", NS_XMLNS, value);
    }

    /* default namespace declaration? */
    if (j_strcmp(name, "xmlns") == 0) {
	/* 'jabber:client' and 'jabber:component:accept' are represented as 'jabber:server' internally */
	if (j_strcmp(value, NS_CLIENT) == 0)
	    value = NS_SERVER;
	else if (j_strcmp(value, NS_COMPONENT_ACCEPT) == 0)
	    value = NS_SERVER;

	if (owner->prefix == NULL) {
	    owner->ns_iri = pstrdup(owner->p, value);
	}
	return xmlnode_put_attrib_ns(owner, name, NULL, NS_XMLNS, value);
    }

    /* attribute in the 'xml:' namespace? */
    if (j_strncmp(name, "xml:", 4) == 0) {
	return xmlnode_put_attrib_ns(owner, name+4, "xml", NS_XML, value);
    }

    local_name = strchr(name, ':');
    if (local_name == NULL)
	local_name = name;
    else
	local_name++;

    return xmlnode_put_attrib_ns(owner, local_name, NULL, NULL, value);
}

/**
 * add an namespaced attribute to an xmlnode element
 *
 * @param owner element to add the attribute to
 * @param name local name of the attribute
 * @param prefix namespace prefix of the attribute
 * @param ns_iri namespace IRI of the attribute
 */
void xmlnode_put_attrib_ns(xmlnode owner, const char *name, const char *prefix, const char *ns_iri, const char *value) {
    xmlnode attrib;

    if (owner == NULL || name == NULL || value == NULL)
	return;

    /* 'jabber:client' and 'jabber:component:accept' are represented as 'jabber:server' internally */
    if (j_strcmp(ns_iri, NS_CLIENT) == 0)
	ns_iri = NS_SERVER;
    else if (j_strcmp(ns_iri, NS_COMPONENT_ACCEPT) == 0)
	ns_iri = NS_SERVER;

    /* If there are no existing attributs, allocate a new one to start
    the list */
    if (owner->firstattrib == NULL) {
        attrib = _xmlnode_new(owner->p, name, prefix, ns_iri, NTYPE_ATTRIB);
        owner->firstattrib = attrib;
        owner->lastattrib  = attrib;
    } else {
        attrib = _xmlnode_search(owner->firstattrib, name, ns_iri, NTYPE_ATTRIB);
        if (attrib == NULL) {
            attrib = _xmlnode_append_sibling(owner->lastattrib, name, prefix, ns_iri, NTYPE_ATTRIB);
            owner->lastattrib = attrib;
        } else {
	}
    }
    /* Update the value of the attribute */
    attrib->data_sz = strlen(value);
    attrib->data    = pstrdup(owner->p, value);
    attrib->parent  = owner;
}

/**
 * get an attribute value
 *
 * @deprecated This function is not aware of namespaces, use xmlnode_get_attrib_ns() instead
 *
 * @param owner element where to look for the attribute
 * @param name name of the attribute of which the value should be returned
 * @return value of the attribute, or NULL if no such attribute
 */
char* xmlnode_get_attrib(xmlnode owner, const char* name) {
    if (j_strncmp(name, "xmlns:", 6) == 0)
	return xmlnode_get_attrib_ns(owner, name+6, NS_XMLNS);
    if (j_strcmp(name, "xmlns") == 0)
	return xmlnode_get_attrib_ns(owner, "xmlns", NS_XMLNS);
    return xmlnode_get_attrib_ns(owner, name, NULL);
}

/**
 * get an attribute value
 *
 * @param owner element where to look for the attribute
 * @param name local name of the attribute of which the value should be returned
 * @param ns_iri namespace IRI of the attribute of which the value should be returned
 * @return value of the attribute, or NULL if no such attribute
 */
char* xmlnode_get_attrib_ns(xmlnode owner, const char* name, const char *ns_iri) {
    xmlnode attrib;

    if (owner != NULL && owner->firstattrib != NULL) {
        attrib = _xmlnode_search(owner->firstattrib, name, ns_iri, NTYPE_ATTRIB);
        if (attrib != NULL)
            return (char*)attrib->data;
    }
    return NULL;
}

/**
 * very hacky: place a pointer to arbitrary data as the value of an attribute
 *
 * @deprecated Do not use it. It's just a big hack. Probably you could use a ::xhash for the same things.
 *
 * @param owner element where to place the attribute
 * @param name name of the attribute
 * @param value the pointer, that should be stored as the value of the attribute
 */
void xmlnode_put_vattrib(xmlnode owner, const char* name, void *value) {
    xmlnode attrib;

    if (owner != NULL) {
        attrib = _xmlnode_search(owner->firstattrib, name, NULL, NTYPE_ATTRIB);
        if (attrib == NULL) {
            xmlnode_put_attrib_ns(owner, name, NULL, NULL, "");
            attrib = _xmlnode_search(owner->firstattrib, name, NULL, NTYPE_ATTRIB);
        }
        if (attrib != NULL)
            attrib->firstchild = (xmlnode)value;
    }
}

/**
 * very hacky: retrieve the pointer to arbitrary data, that has been stored as an attribute using the xmlnode_put_vattrib() function
 *
 * @deprecated Do not use it. It's just a big hack. Probably you could use a ::xhash for the same things.
 *
 * @param element where to get the attribute for
 * @param name name of the attribute
 * @return pointer to the value
 */
void* xmlnode_get_vattrib(xmlnode owner, const char* name) {
    xmlnode attrib;

    if (owner != NULL && owner->firstattrib != NULL) {
        attrib = _xmlnode_search(owner->firstattrib, name, NULL, NTYPE_ATTRIB);
        if (attrib != NULL)
            return (void*)attrib->firstchild;
    }
    return NULL;
}

/**
 * get the first attribute node of an element
 *
 * iteration on all attributes is possible by using xmlnode_get_nextsibling() using the result of this function as the start
 *
 * @param parent element for which the first attribute node should be returned
 * @return attribute node
 */
xmlnode xmlnode_get_firstattrib(xmlnode parent) {
    if (parent != NULL)
        return parent->firstattrib;
    return NULL;
}

/**
 * get the first child node of a node
 *
 * iteration on all childs is possible using xmlnode_get_nextsibling() using the result of this function as the start
 *
 * @param parent element for which the first child should be returned
 * @return child node
 */
xmlnode xmlnode_get_firstchild(xmlnode parent) {
    if (parent != NULL)
        return parent->firstchild;
    return NULL;
}

/**
 * get the last child node of a node
 *
 * (backwards) iteration on all childs is possible using xmlnode_get_prevsibling() using the result of this function as the start
 *
 * @param parent element for which the last child should be returned
 * @return last child node
 */
xmlnode xmlnode_get_lastchild(xmlnode parent) {
    if (parent != NULL)
        return parent->lastchild;
    return NULL;
}

/**
 * return the next sibling
 *
 * this can be used together with xmlnode_get_firstchild() to iterate over the childrens of a node
 *
 * @param sibling the node to get the next sibling for
 * @return next sibling
 */
xmlnode xmlnode_get_nextsibling(xmlnode sibling) {
    if (sibling != NULL)
        return sibling->next;
    return NULL;
}

/**
 * return the previous sibling
 *
 * this can be used together with xmlnode_get_lastchild() to iterate backwards over the childrens of a node
 *
 * @param sibling the node to get the previous sibling for
 * @return previous sibling
 */
xmlnode xmlnode_get_prevsibling(xmlnode sibling) {
    if (sibling != NULL)
        return sibling->prev;
    return NULL;
}

/**
 * get the parent node for a node
 *
 * @param node the node for which the parent node should be returned
 * @return parent node
 */
xmlnode xmlnode_get_parent(xmlnode node) {
    if (node != NULL)
        return node->parent;
    return NULL;
}

/**
 * get the name of a node
 *
 * @deprecated This function mimics the jabberd 1.4.x xmlnode_get_name() where the name including the prefix is returned.
 * You probably do not want to use this in a namespace aware application. You might want to use xmlnode_get_localname(),
 * and xmlnode_get_namespace() instead.
 *
 * @param node the node to get the name for
 * @return name of the node
 */
char* xmlnode_get_name(xmlnode node) {
    if (node == NULL)
	return NULL;

    if (node->prefix == NULL)
	return node->name;

    return spools(node->p, node->prefix, ":", node->name, node->p);
}

/**
 * get the local name of a node
 *
 * @param node the node to get the local name for
 * @return the local name of the node
 */
const char* xmlnode_get_localname(xmlnode node) {
    if (node == NULL)
	return NULL;

    return node->name;
}

/**
 * get the namespace IRI of a node
 *
 * @param node the node to get the namespace IRI for
 * @return namespace IRI of the node
 */
const char* xmlnode_get_namespace(xmlnode node) {
    if (node == NULL)
	return NULL;
    return node->ns_iri;
}

/**
 * get the namespace prefix of a node
 *
 * @note normally you will not need this. To compare two nodes, just compare the
 * namespace (xmlnode_get_namespace()) and the localname (xmlnode_get_localname())
 *
 * @param node the node to get the namespace prefix for
 * @return namespace prefix of the node, NULL for the default prefix
 */
const char* xmlnode_get_nsprefix(xmlnode node) {
    if (node == NULL)
	return NULL;
    return node->prefix;
}

/**
 * return the text inside the element given as node
 *
 * @param node the node to search for text nodes inside
 * @return the text contained in the node
 */
char* xmlnode_get_data(xmlnode node) {
    if (xmlnode_get_type(node) == NTYPE_TAG) /* loop till we find a CDATA in the children */
        for (node = xmlnode_get_firstchild(node); node != NULL; node = xmlnode_get_nextsibling(node))
            if (xmlnode_get_type(node) == NTYPE_CDATA)
		break;

    if (node == NULL)
	return NULL;

    /* check for a dirty node w/ unassembled cdata chunks */
    if (xmlnode_get_type(node->next) == NTYPE_CDATA)
        _xmlnode_merge(node);

    return node->data;
}

/**
 * get the type of the node
 *
 * @param node the node to get the type for
 * @return type of the node, one of ::NTYPE_TAG, ::NTYPE_ATTRIB, or ::NTYPE_CDATA
 */
int xmlnode_get_type(xmlnode node) {
    if (node != NULL)
        return node->type;
    return NTYPE_UNDEF;
}

/**
 * check if a node has child nodes
 *
 * @param node the node to check
 * @return 1 if the node has childrens, 0 else
 */
int xmlnode_has_children(xmlnode node) {
    if ((node != NULL) && (node->firstchild != NULL))
        return 1;
    return 0;
}

/**
 * get the memory pool of an xmlnode
 *
 * @param node the node to get the memory pool from
 * @return memory pool used by this node
 */
pool xmlnode_pool(xmlnode node) {
    if (node != NULL)
        return node->p;
    return (pool)NULL;
}

/**
 * hide (remove) a node from a document
 *
 * @note the root element of a document cannot be hidden with this function
 *
 * @param child the xmlnode that should be hidden
 */
void xmlnode_hide(xmlnode child) {
    xmlnode parent;

    if (child == NULL || child->parent == NULL)
        return;

    parent = child->parent;

    /* first fix up at the child level */
    _xmlnode_hide_sibling(child);

    /* next fix up at the parent level */
    if (child->type == NTYPE_ATTRIB) {
	if (parent->firstattrib == child)
	    parent->firstattrib = child->next;
	if (parent->lastattrib == child)
	    parent->lastattrib = child->prev;
    } else {
	if (parent->firstchild == child)
	    parent->firstchild = child->next;
	if (parent->lastchild == child)
	    parent->lastchild = child->prev;
    }
}

/**
 * hide (remove) an attribute of an element
 *
 * @deprecated This function is not aware of namespaces. Use xmlnode_hide_attrib_ns() instead.
 *
 * @param parent the element for which an attribute should be hidden
 * @param name name of the attribute, that should be hidden
 */
void xmlnode_hide_attrib(xmlnode parent, const char *name) {
    if (j_strncmp(name, "xmlns:", 6) == 0) {
	xmlnode_hide_attrib_ns(parent, name+6, NS_XMLNS);
	return;
    }
    xmlnode_hide_attrib_ns(parent, name, NULL);
}

/**
 * hide (remove) a namespaced attribute of an element
 *
 * @param parent the element for which an attribute should be hidden
 * @param name local name of the attribute, that should be hidden
 * @param ns_iri namespace IRI of the attribute, that should be hidden
 */
void xmlnode_hide_attrib_ns(xmlnode parent, const char *name, const char *ns_iri) {
    xmlnode attrib;

    if (parent == NULL || parent->firstattrib == NULL || name == NULL)
        return;

    attrib = _xmlnode_search(parent->firstattrib, name, ns_iri, NTYPE_ATTRIB);
    if (attrib == NULL)
        return;

    /* first fix up at the child level */
    _xmlnode_hide_sibling(attrib);

    /* next fix up at the parent level */
    if (parent->firstattrib == attrib)
        parent->firstattrib = attrib->next;
    if (parent->lastattrib == attrib)
        parent->lastattrib = attrib->prev;
}

/**
 * convert given xmlnode tree into a string
 *
 * This function guesses, that it is writing a stanza on a stream where the default prefix is declared to
 * be 'jabber:server', 'jabber:client', or 'jabber:component:accept' and the namespace prefix stream is
 * declared to be 'http://etherx.jabber.org/streams'.
 *
 * @deprecated this function is not aware of correct namespace handling. Use xmlnode_serialize_string() instead
 *
 * @param node pointer to the xmlnode tree that should be printed to the string
 * @return pointer to the created string (uses the same memory ::pool as the xmlnode), or NULL if it was unsuccessfull
 */
char *xmlnode2str(xmlnode node) {
    ns_list_item first = NULL;
    ns_list_item last = NULL;

    /* expect we are serializing a stanza on a standard stream */
    xmlnode_update_decl_list(xmlnode_pool(node), &first, &last, NULL, NS_SERVER);
    xmlnode_update_decl_list(xmlnode_pool(node), &first, &last, "stream", NS_STREAM);
    
    spool s = spool_new(xmlnode_pool(node));
    _xmlnode_serialize(s, node, first, last, 0);
    return spool_print(s);
}

/**
 * serialize a given xmlnode to a string
 *
 * This function can be used to serialize a stanza. As a stanza is typically written to an XML stream, there might be
 * namespaces, that are already declared by the stream root element. These namespaces do not need to be declared again,
 * when the stanza is serialized. This is what nslist_first and nslist_last is for. These two pointers point to the
 * begin and end of a list of already declared namespace prefixes. If all namespaces should be declared, than you
 * can just pass NULL as these two arguments.
 *
 * Do not pass the 'jabber:client', or 'jabber:component:accept' namespace in the list of already declared namespaces,
 * but pass always the namespace 'jabber:server' instead. This is because xmlnode represents all these namespaces as
 * 'jabber:server'.
 * 
 * @note while xmlnode_serialize_string() is running, the list passed by the arguments nslist_first and nslist_last gets
 * expanded, but when returning, the list is restored. Keep this in mind in a multithreading environment.
 *
 * @note Internally xmlnode converts the namespaces 'jabber:client' and 'jabber:component:accept' to the namespace
 * 'jabber:server'. This is done to be able to easily serialize the same stanza on client streams, server streams,
 * as well as streams where components are connected. When serializing the xmlnode, the namespace 'jabber:server' is
 * serialized as the right namespace. This is controled by the stream_type argument.
 *
 * @param node the base xmlnode of the tree, that should be serialized
 * @param nslist_first pointer to the first element of already declared namespaces
 * @param nslist_last pointer to the last element of already declared namespaces
 * @param stream_type 0 for a 'jabber:server' stream, 1 for a 'jabber:client' stream, 2 for a 'jabber:component:accept' stream
 * @return serialized XML tree
 */
char *xmlnode_serialize_string(xmlnode node, ns_list_item nslist_first, ns_list_item nslist_last, int stream_type) {
    /* sanity check */
    if (node == NULL)
	return NULL;

    spool s = spool_new(xmlnode_pool(node));
    _xmlnode_serialize(s, node, nslist_first, nslist_last, stream_type);
    return spool_print(s);
}

/**
 * copy an element node as a child to an other node
 *
 * @param parent where to insert the xmlnode
 * @param node node to insert
 * @return pointer to the copied xmlnode
 */
xmlnode xmlnode_insert_tag_node(xmlnode parent, xmlnode node) {
    xmlnode child;

    if (parent == NULL || node == NULL)
	return NULL;

    child = xmlnode_insert_tag_ns(parent, node->name, node->prefix, node->ns_iri);
    if (_xmlnode_has_attribs(node))
        xmlnode_insert_node(child, xmlnode_get_firstattrib(node));
    if (xmlnode_has_children(node))
        xmlnode_insert_node(child, xmlnode_get_firstchild(node));

    return child;
}

/**
 * places copy of node and node's siblings in parent
 *
 * @param parent where to place the copy to
 * @param node what to copy
 */
void xmlnode_insert_node(xmlnode parent, xmlnode node) {
    if (node == NULL || parent == NULL)
        return;

    while (node != NULL) {
        switch (xmlnode_get_type(node)) {
	    case NTYPE_ATTRIB:
		xmlnode_put_attrib_ns(parent, node->name, node->prefix, node->ns_iri, xmlnode_get_data(node));
		break;
	    case NTYPE_TAG:
		xmlnode_insert_tag_node(parent, node);
		break;
	    case NTYPE_CDATA:
		xmlnode_insert_cdata(parent, xmlnode_get_data(node), _xmlnode_get_datasz(node));
        }
        node = xmlnode_get_nextsibling(node);
    }
}


/**
 * produce full duplicate of x with a new pool
 *
 * @note x must be a tag!
 *
 * @param x xmlnode (tag) that should be duplicated using a new memory pool
 * @return pointer to the duplicated tree, or NULL on error
 */
xmlnode xmlnode_dup(xmlnode x) {
    xmlnode x2;

    if (x == NULL)
        return NULL;

    x2 = xmlnode_new_tag_ns(x->name, x->prefix, x->ns_iri);

    if (_xmlnode_has_attribs(x))
        xmlnode_insert_node(x2, xmlnode_get_firstattrib(x));
    if (xmlnode_has_children(x))
        xmlnode_insert_node(x2, xmlnode_get_firstchild(x));

    return x2;
}

/**
 * produce a full duplicate of a x using the specified memory pool
 *
 * @note this is nearly the same as xmlnode_dup(), with the difference, that you can specify which memory pool to use
 *
 * @param p memory pool to use
 * @param x xmlnode (tag) that should be duplicated
 * @return pointer to the duplicated tree, or NULL on error
 */
xmlnode xmlnode_dup_pool(pool p, xmlnode x) {
    xmlnode x2;

    if(x == NULL)
        return NULL;

    x2 = xmlnode_new_tag_pool_ns(p, x->name, x->prefix, x->ns_iri);

    if (_xmlnode_has_attribs(x))
        xmlnode_insert_node(x2, xmlnode_get_firstattrib(x));
    if (xmlnode_has_children(x))
        xmlnode_insert_node(x2, xmlnode_get_firstchild(x));

    return x2;
}

/**
 * wrap a xmlnode in a new element
 *
 * this function creates a new element with the name specified as the wrapper parameter,
 * the xmlnode x becomes a child of this new element
 *
 * @deprecated This function is not aware of namespaces. Use xmlnode_wrap_ns() instead.
 *
 * @param x the xmlnode that gets wrapped
 * @param wrapper name of the wrapping element (that is to be created)
 * @return the new element, that is wrapping x
 */
xmlnode xmlnode_wrap(xmlnode x, const char *wrapper) {
    const char *local_name = NULL;
    xmlnode result = NULL;

    if (x == NULL || wrapper == NULL)
	return NULL;

    local_name = strchr(wrapper, ':');
    if (local_name == NULL)
	local_name = wrapper;
    else
	local_name++;

    result = xmlnode_wrap_ns(x, local_name, NULL, NS_SERVER);

    if (local_name > wrapper) {
	result->prefix = pmalloco(result->p, local_name-wrapper);
	snprintf(result->prefix, local_name-wrapper, "%s", wrapper);
    }

    return result;
}

/**
 * wrap an xmlnode in a new namespaced element
 *
 * this function creates a new element with the specified namespace and name,
 * the xmlnode x becomes a child of this new element
 *
 * @param x the xmlnode that gets wrapped
 * @param name the local name of the wrapper element (that is to be created)
 * @param prefix the namespace prefix of the wrapper element
 * @param ns_iri the namespace IRI of the wrapper element
 * @return the new element, that is wrapping x
 */
xmlnode xmlnode_wrap_ns(xmlnode x, const char *name, const char *prefix, const char *ns_iri) {
    xmlnode wrap = NULL;
    const char* wrapped_lang = NULL;

    if (x == NULL || name == NULL)
	return NULL;

    wrap = xmlnode_new_tag_pool_ns(x->p, name, prefix, ns_iri);
    if (wrap == NULL)
	return NULL;
    wrap->firstchild=x;
    wrap->lastchild=x;
    x->parent=wrap;

    wrapped_lang = xmlnode_get_lang(x);
    if (wrapped_lang != NULL) {
	xmlnode_put_attrib_ns(wrap, "lang", "xml", NS_XML, wrapped_lang);
    }

    return wrap;
}

/**
 * free the memory allocated by an xmlnode tree
 *
 * No nodes inside the xmlnode tree can be used afterwards, as they are all freed by this function
 *
 * @param node one of the elements inside a tree of xmlnodes that should be freed
 */
void xmlnode_free(xmlnode node) {
    if(node == NULL)
        return;

    pool_free(node->p);
}

/**
 * add a declared prefix to the list of namespace prefix declarations
 *
 * @param p memory pool to allocate memory for the items
 * @param first_item_ptr pointer to the pointer to the first list element
 * @param last_item_ptr pointer to the pointer to the last list element
 * @param prefix namespace prefix to add
 * @param ns_iri namespace IRI to add
 */
void xmlnode_update_decl_list(pool p, ns_list_item *first_item_ptr, ns_list_item *last_item_ptr, const char *prefix, const char *ns_iri) {
    ns_list_item new_item = NULL;

    /* sanity check */
    if (p == NULL || first_item_ptr == NULL || last_item_ptr == NULL)
	return;

    /* 'jabber:client' and 'jabber:component:accept' are represented as 'jabber:server' internally */
    if (j_strcmp(ns_iri, NS_CLIENT) == 0)
	ns_iri = NS_SERVER;
    else if (j_strcmp(ns_iri, NS_COMPONENT_ACCEPT) == 0)
	ns_iri = NS_SERVER;

    /* create the new item */
    new_item = pmalloco(p, sizeof(_ns_list_item));
    new_item->prefix = pstrdup(p, prefix);
    new_item->ns_iri = pstrdup(p, ns_iri);

    /* first item in list? */
    if (*first_item_ptr == NULL || *last_item_ptr == NULL) {
	*first_item_ptr = new_item;
	*last_item_ptr = new_item;
	return;
    }

    /* append to the end of the list */
    (*last_item_ptr)->next = new_item;
    new_item->prev = (*last_item_ptr);
    *last_item_ptr = new_item;
}

/**
 * copy a list of declared namespaces
 *
 * @param p Memory pool used to allocate memory for the copy of the list
 * @param first where to start copying
 * @param copy_first pointer to a ::ns_list_item variable, where the pointer to the first element of the copy will be stored
 * @param copy_last pointer to a ::ns_list_item variable, where the pointer to the last element of the copy will be stored
 */
void xmlnode_copy_decl_list(pool p, ns_list_item first, ns_list_item *copy_first, ns_list_item *copy_last) {
    ns_list_item iter = NULL;

    /* at the beginning there was nothing */
    *copy_first = NULL;
    *copy_last = NULL;

    /* copy the items */
    for (iter = first; iter != NULL; iter = iter->next) {
    	xmlnode_update_decl_list(p, copy_first, copy_last, iter->prefix, iter->ns_iri);
    }
}

/**
 * get the list of declared namespaces from an xmlnode
 *
 * @param p memory pool used to allocate memory for the list
 * @param node xmlnode to get the declared namespaces from
 * @param first_ns pointer to where a pointer to the first entry should be stored
 * @param last_ns pointer to where a pointer to the last entry should be stored
 */
void xmlnode_get_decl_list(pool p, xmlnode node, ns_list_item *first_ns, ns_list_item *last_ns) {
    xmlnode iter = NULL;

    /* sanity checks */
    if (p == NULL || node == NULL || first_ns == NULL || last_ns == NULL) {
	return;
    }

    /* start with an empty list */
    *first_ns = NULL;
    *last_ns = NULL;

    /* iterate on attributes to get namespaces */
    for (iter = xmlnode_get_firstattrib(node); iter != NULL; iter = xmlnode_get_nextsibling(iter)) {
	if (j_strcmp(xmlnode_get_namespace(iter), NS_XMLNS) != 0) {
	    /* not a namespace declaration */
	    continue;
	}

	/* declaring default namespace? */
	if (iter->prefix == NULL)
	    xmlnode_update_decl_list(p, first_ns, last_ns, NULL, xmlnode_get_data(iter));
	else
	    xmlnode_update_decl_list(p, first_ns, last_ns, xmlnode_get_localname(iter), xmlnode_get_data(iter));
    }
}

/**
 * get the declared language of a node
 *
 * @param node the node to get the language for
 * @return the declared language of the node, or NULL for no declared language
 */
const char* xmlnode_get_lang(xmlnode node) {
    char *localresult = NULL;
    
    /* end of recursion */
    if (node == NULL)
	return NULL;

    /* only elements may have their own language */
    if (node->type == NTYPE_TAG) {
	/* is there an xml:lang attribute? */
	localresult = xmlnode_get_attrib_ns(node, "lang", NS_XML);
	if (localresult != NULL)
	    return localresult;
    }

    /* it's the language of the parent, that we have as well */
    return xmlnode_get_lang(node->parent);
}

/**
 * delete the last occurence for a prefix declaration in a list of namespace declarations
 *
 * @param first_ns pointer to the pointer of the first list element (might get updated)
 * @param last_ns pointer to the pointer of the last list element (might get updated)
 * @param prefix the prefix, that should be deleted
 */
void xmlnode_delete_last_decl(ns_list_item *first_ns, ns_list_item *last_ns, const char *prefix) {
    ns_list_item iter = NULL;
    
    /* sanity check */
    if (first_ns == NULL || last_ns == NULL) {
	return;
    }

    /* nothing to do if there is no list */
    if (*first_ns == NULL || *last_ns == NULL) {
	return;
    }

    /* find last declaration */
    for (iter = *last_ns; iter != NULL; iter = iter->prev) {
	/* is it the prefix we are searching for? */
	if (j_strcmp(iter->prefix, prefix) == 0)
	    break;
    }

    /* prefix found? */
    if (iter == NULL)
	return; /* no */

    /* delete the prefix */
    if (iter->prev != NULL) {
	/* if it isn't the first list item, we have to update the item before this one */
	iter->prev->next = iter->next;
    } else {
	/* if it is the first item, we have up update the start of the list */
	*first_ns = iter->next;
    }
    if (iter->next != NULL) {
	/* if it isn't the last list item, we have to update the item after this one */
	iter->next->prev = iter->prev;
    } else {
	/* if it is the last item, we have to update the end of the list */
	*last_ns = iter->prev;
    }
}

/**
 * get a prefix for the namespace IRI in the list of declared namespaces
 *
 * @param last_ns pointer to the last list item
 * @param iri namespace IRI to search for
 * @return prefix found for this namespace, NULL if not found, "" if default prefix
 */
const char *xmlnode_list_get_nsprefix(ns_list_item last_ns, const char *iri) {
    ns_list_item iter = NULL;

    /* this prefix is aways defined */
    if (j_strcmp(iri, NS_XML) == 0) {
	return "xml";
    }

    /* iterate the list backwards */
    for (iter = last_ns; iter != NULL; iter = iter->prev) {
	/* does this item declare the right namespace? */
	if (j_strcmp(iter->ns_iri, iri) == 0) {
	    return iter->prefix == NULL ? "" : iter->prefix;
	}
    }

    /* nothing found */
    return NULL;
}

/**
 * get the namespace IRI for a prefix
 *
 * @param last_ns pointer to the last list item
 * @param prefix the prefix to search the IRI for
 * @return namespace IRI assigned to the prefix, NULL if no such prefix
 */
const char *xmlnode_list_get_nsiri(ns_list_item last_ns, const char *prefix) {
    ns_list_item iter = NULL;

    /* iterate the list backwards */
    for (iter = last_ns; iter != NULL; iter = iter->prev) {
	/* does this item define the right prefix? */
	if ((prefix == NULL && iter->prefix == NULL) || j_strcmp(iter->prefix, prefix) == 0) {
	    return iter->ns_iri;
	}
    }

    /* nothing found */
    return NULL;
}

/**
 * get the (i+1)-th element in a list of xmlnodes
 *
 * @param first first list item
 * @param i which item to get (we start counting at zero)
 * @return the node of the list item, NULL if no such item
 */
xmlnode xmlnode_get_list_item(xmlnode_list_item first, unsigned int i) {
    /* find the item */
    while (first != NULL && i > 0) {
	first = first->next;
	i--;
    }

    /* found? */
    if (first != NULL)
	return first->node;

    /* not found */
    return NULL;
}

/**
 * select one note from a list of notes by language
 *
 * This picks the first node in the list with the specified language,
 * if no such node exists, the first node without a language is
 * selected, if no nodes without a language are in the list, the
 * first list item is returned.
 *
 * @param nodes pointer to the first entry in the list of nodes
 * @param lang language to prefere (if NULL, the first node without language is prefered)
 * @param the selected nodes, NULL if no nodes have been passed
 */
xmlnode xmlnode_select_by_lang(xmlnode_list_item nodes, const char* lang) {
    xmlnode_list_item iter = NULL;
    xmlnode first_without_lang = NULL;

    /* santiy check */
    if (nodes == NULL) {
	return NULL;
    }

    /* iterate the nodes */
    for (iter = nodes; iter != NULL; iter = iter->next) {
	/* get the language of the node */
	const char* this_nodes_lang = xmlnode_get_lang(iter->node);

	/* match by language? */
	if (lang != NULL) {
	    if (j_strcmp(this_nodes_lang, lang) == 0) {
		return iter->node;
	    }
	}

	/* check for nodes without a language */
	if (first_without_lang == NULL && this_nodes_lang == NULL) {
	    if (lang == NULL)
		return iter->node;
	    first_without_lang = iter->node;
	}
    }

    /* no match by language, either return node without language (prefered), or first node */
    return first_without_lang != NULL ? first_without_lang : nodes->node;
}
