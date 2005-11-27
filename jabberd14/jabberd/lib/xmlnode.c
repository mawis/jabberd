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
		spool_add(s, xmlnode_get_data(cur));
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

    /* 'jabber:client' and 'jabber:component:accept' are represented as 'jabber:server' internally */
    if (j_strcmp(ns_iri, NS_CLIENT) == 0)
	ns_iri = NS_SERVER;
    else if (j_strcmp(ns_iri, NS_COMPONENT_ACCEPT) == 0)
	ns_iri = NS_SERVER;

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

    if (name == NULL)
	return NULL;

    local_name = strchr(name, ':');
    if (local_name == NULL)
	local_name = name;
    else
	local_name++;

    result = _xmlnode_new(p, local_name, NULL, NS_SERVER, NTYPE_TAG);
    if (result != NULL && local_name > name) {
	result->prefix = pmalloco(xmlnode_pool(result), local_name-name);
	snprintf(result->prefix, local_name-name, "%s", name);
    }
    
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
    return _xmlnode_insert(parent, name, prefix, ns_iri, NTYPE_TAG);
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
 * @todo implement a function that does the same but honors namespaces
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
 * return the text of the inside wrapped by the element found by the name parameter
 *
 * this equals xmlnode_get_data(xmlnode_get_tag(parent, name))
 *
 * @todo implement a function that does the same but honors namespaces
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
        }
    }
    /* Update the value of the attribute */
    attrib->data_sz = strlen(value);
    attrib->data    = pstrdup(owner->p, value);
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
    if (parent->firstchild == child)
        parent->firstchild = child->next;
    if (parent->lastchild == child)
        parent->lastchild = child->prev;
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
    xmlnode wrap;

    if (x == NULL || name == NULL)
	return NULL;

    wrap = xmlnode_new_tag_pool_ns(x->p, name, prefix, ns_iri);
    if (wrap == NULL)
	return NULL;
    wrap->firstchild=x;
    wrap->lastchild=x;
    x->parent=wrap;
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
    new_item->prefix = prefix;
    new_item->ns_iri = ns_iri;

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
void	 xmlnode_copy_decl_list(pool p, ns_list_item first, ns_list_item *copy_first, ns_list_item *copy_last) {
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
	    xmlnode_update_decl_list(p, first_ns, last_ns, NULL, pstrdup(p, xmlnode_get_data(iter)));
	else
	    xmlnode_update_decl_list(p, first_ns, last_ns, pstrdup(p, xmlnode_get_localname(iter)), pstrdup(p, xmlnode_get_data(iter)));
    }
}
