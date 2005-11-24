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
 * @param name name of the element to be created (ignored for NTYPE_CDATA)
 * @param type type of the element to be created (NTYPE_CDATA, NTYPE_TAG, NTYPE_ATTRIB)
 * @return the new xmlnode, NULL on failure
 */
static xmlnode _xmlnode_new(pool p, const char* name, unsigned int type) {
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
    if (type != NTYPE_CDATA)
        result->name = pstrdup(p,name);
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
 * @param name name of the new sibling
 * @param type type of the new sibling (NTYPE_TAG, NTYPE_CDATA, NTYPE_ATTRIB)
 * @return the new xmlnode, NULL on failure
 */
static xmlnode _xmlnode_append_sibling(xmlnode lastsibling, const char* name, unsigned int type) {
    xmlnode result;

    result = _xmlnode_new(xmlnode_pool(lastsibling), name, type);
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
 * @param name the name of the new sibling (ignored for NTYPE_CDATA)
 * @param type type of the new sibling (NTYPE_TAG, NTYPE_CDATA, NTYPE_ATTRIB)
 * @return the new xmlnode, NULL on failure
 */
static xmlnode _xmlnode_insert(xmlnode parent, const char* name, unsigned int type) {
    xmlnode result;

    if(parent == NULL || (type != NTYPE_CDATA && name == NULL)) return NULL;

    /* If parent->firstchild is NULL, simply create a new node for the first child */
    if (parent->firstchild == NULL) {
        result = _xmlnode_new(parent->p, name, type);
        parent->firstchild = result;
    } else {
	/* Otherwise, append this to the lastchild */
        result= _xmlnode_append_sibling(parent->lastchild, name, type);
    }
    result->parent = parent;
    parent->lastchild = result;
    return result;
}

/**
 * Walk the sibling list, looging for a xmlnode of the specified name and type
 *
 * @param firstsibling where to start seaching in a list of siblings
 * @param name name of the sibling to search for
 * @param type type of the sibling to search for
 * @return found xmlnode or NULL if no such xmlnode
 */
static xmlnode _xmlnode_search(xmlnode firstsibling, const char* name, unsigned int type) {
    xmlnode current;

    /* iterate on the siblings */
    for (current = firstsibling; current != NULL; current = current->next) {
	if ((current->type == type) && (j_strcmp(current->name, name) == 0 || (current->name == NULL && name == NULL)))
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
 * Write a tag (including attributes) to a spool
 *
 * @param s spool to write the tag to
 * @param node xmlnode for which a tag should be written
 * @param flag 0 = write a empty-element tag, 1 = write a start-tag, 2 = write a end-tag
 */
static void _xmlnode_tag2str(spool s, xmlnode node, int flag) {
    xmlnode tmp;

    if(flag==0 || flag==1) {
	/* tag that includes attributes */
	spooler(s, "<", xmlnode_get_name(node), s);
	
	/* iterate on attributes and write them */
	for (tmp = xmlnode_get_firstattrib(node); tmp != NULL; tmp = xmlnode_get_nextsibling(tmp)) {
	    spooler(s, " ", xmlnode_get_name(tmp), "='", strescape(xmlnode_pool(node), xmlnode_get_data(tmp)), "'", s);
	}

	if(flag==0)
	    spool_add(s,"/>");
	else
	    spool_add(s,">");
    } else {
	/* end tag does not include attributes */
	spooler(s,"</",xmlnode_get_name(node),">",s);
    }
}

/**
 * Print an xmlnode including child nodes to a (new) spool
 *
 * @note the xmlnode has to be of type NTYPE_TAG
 *
 * @param node the xmlnode to write
 * @return spool where the xmlnode has been printed to
 */
static spool _xmlnode2spool(xmlnode node) {
    spool s;
    int level=0;
    int dir=0;	/* 0 = descending (writing start tags), ascending in the xmlnode tree */
    xmlnode tmp;

    /* we don't print attributes or CDATA nodes as base nodes */
    if (!node || xmlnode_get_type(node)!=NTYPE_TAG)
        return NULL;

    s = spool_new(xmlnode_pool(node));
    if (!s)
	return NULL;

    while (1) {
        if (dir==0) {
	    /* we are descending in the tree, write start-tags */
    	    if(xmlnode_get_type(node) == NTYPE_TAG) {
		/* NTYPE_TAG nodes */
                if(xmlnode_has_children(node)) {
		    /* node has children, write start-tag and childrens */
                    _xmlnode_tag2str(s,node,1);
                    node = xmlnode_get_firstchild(node);
                    level++;
                    continue;
                } else {
		    /* node has no children, write empty tag */
                    _xmlnode_tag2str(s,node,0);
                }
            } else {
		/* NTYPE_CDATA nodes */
                spool_add(s,strescape(xmlnode_pool(node),xmlnode_get_data(node)));
            }
        }

	/* check if there is another sibling we have to print */
    	tmp = xmlnode_get_nextsibling(node);
        if(!tmp) {
	    /* all siblings processed, write end-tag of the parent */
            node = xmlnode_get_parent(node);
            level--;
            if(level>=0)
		_xmlnode_tag2str(s,node,2);
	    /* complete xmlnode including children printed? */
            if(level<1)
		break;

	    /* nothing to descend into ... we are ascending */
            dir = 1;
        } else {
	    /* sibling found where we descend again to */
            node = tmp;
            dir = 0;
        }
    }

    return s;
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
 * Automatically creates a memory pool for the node.
 *
 * @param name name of the tag
 * @return a pointer to the new tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag(const char* name) {
    return _xmlnode_new(NULL, name, NTYPE_TAG);
}


/**
 * create a tag node within given pool
 *
 * @param p previously created memory pool
 * @param name name of the tag
 * @return a pointer to the tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag_pool(pool p, const char* name) {
    return _xmlnode_new(p, name, NTYPE_TAG);
}


/**
 * append a child tag to a tag
 *
 * @param parent the xmlnode where the new element should be inserted
 * @param name name of the child tag
 * @return pointer to the child tag node, or NULL if it was unsuccessfull
 */
xmlnode xmlnode_insert_tag(xmlnode parent, const char* name) {
    return _xmlnode_insert(parent, name, NTYPE_TAG);
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

    result = _xmlnode_insert(parent, NULL, NTYPE_CDATA);
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
        return _xmlnode_search(parent->firstchild, name, NTYPE_TAG);

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
 * @param owner element to add the attribute to
 * @param name name of the attribute
 * @param value value of the attribute
 */
void xmlnode_put_attrib(xmlnode owner, const char* name, const char* value) {
    xmlnode attrib;

    if (owner == NULL || name == NULL || value == NULL)
	return;

    /* If there are no existing attributs, allocate a new one to start
    the list */
    if (owner->firstattrib == NULL) {
        attrib = _xmlnode_new(owner->p, name, NTYPE_ATTRIB);
        owner->firstattrib = attrib;
        owner->lastattrib  = attrib;
    } else {
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
        if (attrib == NULL) {
            attrib = _xmlnode_append_sibling(owner->lastattrib, name, NTYPE_ATTRIB);
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
 * @param owner element where to look for the attribute
 * @param name name of the attribute of which the value should be returned
 * @return value of the attribute, or NULL if no such attribute
 */
char* xmlnode_get_attrib(xmlnode owner, const char* name) {
    xmlnode attrib;

    if (owner != NULL && owner->firstattrib != NULL) {
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
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
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
        if (attrib == NULL) {
            xmlnode_put_attrib(owner, name, "");
            attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
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
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
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
 * @param node the node to get the name for
 * @return name of the node
 */
char* xmlnode_get_name(xmlnode node) {
    if (node != NULL)
        return node->name;
    return NULL;
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
 * @param parent the element for which an attribute should be hidden
 * @param name name of the attribute, that should be hidden
 */
void xmlnode_hide_attrib(xmlnode parent, const char *name) {
    xmlnode attrib;

    if (parent == NULL || parent->firstattrib == NULL || name == NULL)
        return;

    attrib = _xmlnode_search(parent->firstattrib, name, NTYPE_ATTRIB);
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
 * @param node pointer to the xmlnode tree that should be printed to the string
 * @return pointer to the created string (uses the same memory ::pool as the xmlnode), or NULL if it was unsuccessfull
 */
char *xmlnode2str(xmlnode node) {
    return spool_print(_xmlnode2spool(node));
}

/**
 * convert given xmlnode tree into a newline terminated string
 *
 * @note same as xmlnode2str() with the difference, that the result is terminated by a newline character (U+000D)
 *
 * @param node pointer to the xmlnode tree that should be printed to the string
 * @return pointer to the created string (uses the same memory ::pool as the xmlnode), or NULL if it was unsuccessfull
 */
char* xmlnode2tstr(xmlnode node) {
    spool s = _xmlnode2spool(node);
    if (s != NULL)
	spool_add(s, "\n");
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

    child = xmlnode_insert_tag(parent, xmlnode_get_name(node));
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
		xmlnode_put_attrib(parent, xmlnode_get_name(node), xmlnode_get_data(node));
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

    x2 = xmlnode_new_tag(xmlnode_get_name(x));

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

    x2 = xmlnode_new_tag_pool(p, xmlnode_get_name(x));

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
 * @param x the xmlnode that gets wrapped
 * @param wrapper name of the wrapping element (that is to be created)
 * @return the new element, that is wrapping x
 */
xmlnode xmlnode_wrap(xmlnode x,const char *wrapper) {
    xmlnode wrap;
    if(x==NULL||wrapper==NULL) return NULL;
    wrap=xmlnode_new_tag_pool(xmlnode_pool(x),wrapper);
    if(wrap==NULL) return NULL;
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
