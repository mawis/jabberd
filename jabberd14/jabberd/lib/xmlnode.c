/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/

#include "lib.h"

/* Internal routines */
typedef struct xml_parse_st
{
    xmlnode current;
    int cur_depth;
    int max_depth;
} _xmlnode_parse, *xmlnode_parse;

void __parse_defaultHandler(void *parser, const XML_Char *s, int len)
{
    xmlnode_parse x = (xmlnode_parse)XML_GetUserData(parser);

    if(x->cur_depth < x->max_depth)
        return; /* don't bother building the full text here either, haven't reached desired parse depth */

    if(x->current->full == NULL)
    {
        x->current->full = (char*)malloc(len + 1);
        memcpy(x->current->full, s, len);
        memcpy(x->current->full + len, "\0", 1);
    }
    else
    {
        int old_len = strlen(x->current->full);
        x->current->full = (char*)realloc(x->current->full,old_len + len + 1);
        memcpy(x->current->full + old_len, s, len);
        memcpy(x->current->full + old_len + 1, "\0", 1);
    }
}

void __parse_startElement(void *parser, const char *name, const char **atts)
{
    xmlnode_parse x = (xmlnode_parse)XML_GetUserData(parser);

    if(x->cur_depth == 0)
    {
        x->cur_depth++;
        return;
    }

    /* if we are too deep to parse, just build the ->full */
    if(x->cur_depth >= x->max_depth && x->max_depth != -1)
    {
        if(x->cur_depth == x->max_depth)
        {
            x->current = xmlnode_insert_tag(x->current, name);
            xmlnode_put_expat_attribs(x->current, atts);
        }
        XML_DefaultCurrent(parser);
        x->current->complete = 0;
        x->cur_depth++;
        return;
    }

    x->current = xmlnode_insert_tag(x->current, name);
    xmlnode_put_expat_attribs(x->current, atts);

    x->cur_depth++;
}

void __parse_endElement(void *parser, const char *name)
{
    xmlnode_parse x = (xmlnode_parse)XML_GetUserData(parser);

    if(--x->cur_depth > x->max_depth && x->max_depth != -1)
    {
        XML_DefaultCurrent(parser);
        x->current->complete = 0;
        return;
    }

    x->current = xmlnode_get_parent(x->current);
}

void __parse_cdataHandler(void *parser, const char *s, int len)
{
    xmlnode_parse x = (xmlnode_parse)XML_GetUserData(parser);

    if(x->cur_depth > x->max_depth && x->max_depth != -1)
    {
        XML_DefaultCurrent(parser);
        x->current->complete = 0;
        return;
    }

    xmlnode_insert_cdata(x->current, s, len);
}

void __parse_commentHandler(void *parser, const XML_Char *data) { }

void _parse_xmlnode(xmlnode current, int parse_depth)
{
    XML_Parser p;
    xmlnode_parse x;

    /* do not need to parse for any of these conditions */
    if(current == NULL || parse_depth == 0 || current->full == NULL || current->complete == 1)
        return;

    x = (xmlnode_parse)malloc(sizeof(_xmlnode_parse));
    memset(x, 0, sizeof(_xmlnode_parse));
    x->current = current;
    x->max_depth = parse_depth;
    
    /* create a expat parser, and parse the xmlnode */
    p = XML_ParserCreate(NULL);
    current->complete = parse_depth; /* flag for how far to traverse the nodes */
    XML_SetUserData(p, (void*)x);
    XML_UseParserAsHandlerArg(p);
    XML_SetElementHandler(p, (void*)__parse_startElement, (void*)__parse_endElement);
    XML_SetDefaultHandler(p, (void*)__parse_defaultHandler);
    XML_SetCharacterDataHandler(p, (void*)__parse_cdataHandler);
    XML_SetCommentHandler(p, (void*)__parse_commentHandler);

    /* perform the parsing */
    if(!XML_Parse(p, current->full, strlen(current->full), 1))
    {
        /* XXX hrmm.. parsing error.. this should never happen,
         * since expat already has parsed this text, and was error free */
    }

    /* free the parser and text, flag this xmlnode as complete */
    XML_ParserFree(p);
    current->complete = 1;
    free(current->full);
    free(x);
    current->full = NULL;
}

xmlnode _xmlnode_new(pool p, const char* name, unsigned int type)
{
    xmlnode result = NULL;
    if (type > NTYPE_LAST)
        return NULL;

    if (type != NTYPE_CDATA && name == NULL)
        return NULL;

    if (p == NULL)
    {
        p = pool_heap(1*1024);
    }

    /* Allocate & zero memory */
    result = (xmlnode)pmalloco(p, sizeof(_xmlnode));

    /* Initialize fields */
    if (type != NTYPE_CDATA)
        result->name = pstrdup(p,name);
    result->type = type;
    result->p = p;
    result->complete = 1;
    return result;
}

static xmlnode _xmlnode_append_sibling(xmlnode lastsibling, const char* name, unsigned int type)
{
    xmlnode result;

    result = _xmlnode_new(xmlnode_pool(lastsibling), name, type);
    if (result != NULL)
    {
        /* Setup sibling pointers */
        result->prev = lastsibling;
        lastsibling->next = result;
    }
    return result;
}

static xmlnode _xmlnode_insert(xmlnode parent, const char* name, unsigned int type)
{
    xmlnode result;

    if(parent == NULL || (type != NTYPE_CDATA && name == NULL)) return NULL;

    if(!parent->complete)
        _parse_xmlnode(parent, 1);

    /* If parent->firstchild is NULL, simply create a new node for the first child */
    if (parent->firstchild == NULL)
    {
        result = _xmlnode_new(parent->p, name, type);
        parent->firstchild = result;
    }
    /* Otherwise, append this to the lastchild */
    else
    {
        result= _xmlnode_append_sibling(parent->lastchild, name, type);
    }
    result->parent = parent;
    parent->lastchild = result;
    return result;

}

static xmlnode _xmlnode_search(xmlnode firstsibling, const char* name, unsigned int type)
{
    xmlnode current;

    if(firstsibling != NULL && type != NTYPE_ATTRIB && firstsibling->parent != NULL && firstsibling->parent->complete == 0)
        _parse_xmlnode(firstsibling->parent, 1);

    /* Walk the sibling list, looking for the given type of xmlnode with
    the specified name */
    current = firstsibling;
    while (current != NULL)
    {
        if ((current->type == type) && (j_strcmp(current->name, name) == 0))
            return current;
        else
            current = current->next;
    }
    return NULL;
}

void _xmlnode_merge(xmlnode data)
{
    xmlnode cur;
    char *merge, *scur;
    int imerge;

    if(data != NULL && data->parent != NULL && data->parent->complete == 0)
        _parse_xmlnode(data->parent, 1);

    /* get total size of all merged cdata */
    imerge = 0;
    for(cur = data; cur != NULL && cur->type == NTYPE_CDATA; cur = cur->next)
        imerge += cur->data_sz;

    /* copy in current data and then spin through all of them and merge */
    scur = merge = pmalloc(data->p,imerge + 1);
    for(cur = data; cur != NULL && cur->type == NTYPE_CDATA; cur = cur->next)
    {
        memcpy(scur,cur->data,cur->data_sz);
        scur += cur->data_sz;
    }
    *scur = '\0';

    /* this effectively hides all of the merged-in chunks */
    data->next = cur;
    if(cur == NULL)
        data->parent->lastchild = data;
    else
        cur->prev = data;

    /* reset data */
    data->data = merge;
    data->data_sz = imerge;
    
}

static void _xmlnode_hide_sibling(xmlnode child)
{
    if(child == NULL)
        return;

    if(child->parent != NULL && child->parent->complete == 0)
        _parse_xmlnode(child->parent, 1);

    if(child->prev != NULL)
        child->prev->next = child->next;
    if(child->next != NULL)
        child->next->prev = child->prev;
}

void _xmlnode_tag2str(spool s, xmlnode node, int flag)
{
    xmlnode tmp;

    if(node == NULL)
        return;

    if(node->complete == 0)
        _parse_xmlnode(node, -1);

    if(flag==0 || flag==1)
    {
	    spooler(s,"<",xmlnode_get_name(node),s);
	    tmp = xmlnode_get_firstattrib(node);
	    while(tmp) {
	        spooler(s," ",xmlnode_get_name(tmp),"='",strescape(xmlnode_pool(node),xmlnode_get_data(tmp)),"'",s);
	        tmp = xmlnode_get_nextsibling(tmp);
	    }
	    if(flag==0)
	        spool_add(s,"/>");
	    else
	        spool_add(s,">");
    }
    else
    {
	    spooler(s,"</",xmlnode_get_name(node),">",s);
    }
}

spool _xmlnode2spool(xmlnode node)
{
    spool s;
    int level=0,dir=0;
    xmlnode tmp;

    if(!node || xmlnode_get_type(node)!=NTYPE_TAG)
        return NULL;

    s = spool_new(xmlnode_pool(node));
    if(!s) return(NULL);

    if(node->complete == 0)
        _parse_xmlnode(node, -1);

    while(1)
    {
        if(dir==0)
        {
    	    if(xmlnode_get_type(node) == NTYPE_TAG)
            {
                if(xmlnode_has_children(node))
                {
                    _xmlnode_tag2str(s,node,1);
                    node = xmlnode_get_firstchild(node);
                    level++;
                    continue;
                }else{
                    _xmlnode_tag2str(s,node,0);
                }
            }else{
                spool_add(s,strescape(xmlnode_pool(node),xmlnode_get_data(node)));
            }
        }

    	tmp = xmlnode_get_nextsibling(node);
        if(!tmp)
        {
            node = xmlnode_get_parent(node);
            level--;
            if(level>=0) _xmlnode_tag2str(s,node,2);
            if(level<1) break;
            dir = 1;
        }else{
            node = tmp;
            dir = 0;
        }
    }

    return s;
}


/* External routines */


/*
 *  xmlnode_new_tag -- create a tag node
 *  Automatically creates a memory pool for the node.
 *
 *  parameters
 *      name -- name of the tag
 *
 *  returns
 *      a pointer to the tag node
 *      or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag(const char* name)
{
    return _xmlnode_new(NULL, name, NTYPE_TAG);
}


/*
 *  xmlnode_new_tag_pool -- create a tag node within given pool
 *
 *  parameters
 *      p -- previously created memory pool
 *      name -- name of the tag
 *
 *  returns
 *      a pointer to the tag node
 *      or NULL if it was unsuccessfull
 */
xmlnode xmlnode_new_tag_pool(pool p, const char* name)
{
    return _xmlnode_new(p, name, NTYPE_TAG);
}


/*
 *  xmlnode_insert_tag -- append a child tag to a tag
 *
 *  parameters
 *      parent -- pointer to the parent tag
 *      name -- name of the child tag
 *
 *  returns
 *      a pointer to the child tag node
 *      or NULL if it was unsuccessfull
 */
xmlnode xmlnode_insert_tag(xmlnode parent, const char* name)
{
    return _xmlnode_insert(parent, name, NTYPE_TAG);
}


/*
 *  xmlnode_insert_cdata -- append character data to a tag
 *
 *  parameters
 *      parent -- parent tag
 *      CDATA -- character data
 *      size -- size of CDATA
 *              or -1 for null-terminated CDATA strings
 *
 *  returns
 *      a pointer to the child CDATA node
 *      or NULL if it was unsuccessfull
 */
xmlnode xmlnode_insert_cdata(xmlnode parent, const char* CDATA, unsigned int size)
{
    xmlnode result;

    if(CDATA == NULL || parent == NULL)
        return NULL;

    if(size == -1)
        size = strlen(CDATA);

    result = _xmlnode_insert(parent, NULL, NTYPE_CDATA);
    if (result != NULL)
    {
        result->data = (char*)pmalloc(result->p, size + 1);
        memcpy(result->data, CDATA, size);
        result->data[size] = '\0';
        result->data_sz = size;
    }

    return result;
}


/*
 *  xmlnode_get_tag -- find given tag in an xmlnode tree
 *
 *  parameters
 *      parent -- pointer to the parent tag
 *      name -- "name" for the child tag of that name
 *              "name/name" for a sub child (recurses)
 *              "?attrib" to match the first tag with that attrib defined
 *              "?attrib=value" to match the first tag with that attrib and value
 *              "=cdata" to match the cdata contents of the child
 *              or any combination: "name/name/?attrib", "name=cdata", etc
 *
 *  results
 *      a pointer to the tag matching search criteria
 *      or NULL if search was unsuccessfull
 */
xmlnode xmlnode_get_tag(xmlnode parent, const char* name)
{
    char *str, *slash, *qmark, *equals;
    xmlnode step, ret;

    if(parent == NULL || parent->firstchild == NULL || name == NULL || name == '\0') return NULL;

    if(strstr(name, "/") == NULL && strstr(name,"?") == NULL && strstr(name, "=") == NULL)
        return _xmlnode_search(parent->firstchild, name, NTYPE_TAG);

    if(parent->complete == 0)
        _parse_xmlnode(parent, 1);

    str = strdup(name);
    slash = strstr(str, "/");
    qmark = strstr(str, "?");
    equals = strstr(str, "=");

    if(equals != NULL && (slash == NULL || equals < slash) && (qmark == NULL || equals < qmark))
    { /* of type =cdata */

        *equals = '\0';
        equals++;

        for(step = parent->firstchild; step != NULL; step = xmlnode_get_nextsibling(step))
        {
            if(xmlnode_get_type(step) != NTYPE_TAG)
                continue;

            if(*str != '\0')
                if(j_strcmp(xmlnode_get_name(step),str) != 0)
                    continue;

            if(j_strcmp(xmlnode_get_data(step),equals) != 0)
                continue;

            break;
        }

        free(str);
        return step;
    }


    if(qmark != NULL && (slash == NULL || qmark < slash))
    { /* of type ?attrib */

        *qmark = '\0';
        qmark++;
        if(equals != NULL)
        {
            *equals = '\0';
            equals++;
        }

        for(step = parent->firstchild; step != NULL; step = xmlnode_get_nextsibling(step))
        {
            if(xmlnode_get_type(step) != NTYPE_TAG)
                continue;

            if(*str != '\0')
                if(j_strcmp(xmlnode_get_name(step),str) != 0)
                    continue;

            if(xmlnode_get_attrib(step,qmark) == NULL)
                continue;

            if(equals != NULL && j_strcmp(xmlnode_get_attrib(step,qmark),equals) != 0)
                continue;

            break;
        }

        free(str);
        return step;
    }


    *slash = '\0';
    ++slash;

    for(step = parent->firstchild; step != NULL; step = xmlnode_get_nextsibling(step))
    {
        if(xmlnode_get_type(step) != NTYPE_TAG) continue;

        if(j_strcmp(xmlnode_get_name(step),str) != 0)
            continue;

        ret = xmlnode_get_tag(step, slash);
        if(ret != NULL)
        {
            free(str);
            return ret;
        }
    }

    free(str);
    return NULL;
}


/* return the cdata from any tag */
char *xmlnode_get_tag_data(xmlnode parent, const char *name)
{
    xmlnode tag;

    tag = xmlnode_get_tag(parent, name);
    if(tag == NULL) return NULL;

    return xmlnode_get_data(tag);
}


void xmlnode_put_attrib(xmlnode owner, const char* name, const char* value)
{
    xmlnode attrib;

    if(owner == NULL || name == NULL || value == NULL) return;
    
    /* If there are no existing attributs, allocate a new one to start
    the list */
    if (owner->firstattrib == NULL)
    {
        attrib = _xmlnode_new(owner->p, name, NTYPE_ATTRIB);
        owner->firstattrib = attrib;
        owner->lastattrib  = attrib;
    }
    else
    {
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
        if(attrib == NULL)
        {
            attrib = _xmlnode_append_sibling(owner->lastattrib, name, NTYPE_ATTRIB);
            owner->lastattrib = attrib;
        }
    }
    /* Update the value of the attribute */
    attrib->data_sz = strlen(value);
    attrib->data    = pstrdup(owner->p, value);

}

char* xmlnode_get_attrib(xmlnode owner, const char* name)
{
    xmlnode attrib;

    if (owner != NULL && owner->firstattrib != NULL)
    {
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
        if (attrib != NULL)
            return (char*)attrib->data;
    }
    return NULL;
}

void xmlnode_put_vattrib(xmlnode owner, const char* name, void *value)
{
    xmlnode attrib;

    if (owner != NULL)
    {
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
        if (attrib == NULL)
        {
            xmlnode_put_attrib(owner, name, "");
            attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
        }
        if (attrib != NULL)
            attrib->firstchild = (xmlnode)value;
    }
}

void* xmlnode_get_vattrib(xmlnode owner, const char* name)
{
    xmlnode attrib;

    if (owner != NULL && owner->firstattrib != NULL)
    {
        attrib = _xmlnode_search(owner->firstattrib, name, NTYPE_ATTRIB);
        if (attrib != NULL)
            return (void*)attrib->firstchild;
    }
    return NULL;
}

xmlnode xmlnode_get_firstattrib(xmlnode parent)
{
    if(parent != NULL && parent->complete == 0)
        _parse_xmlnode(parent, 1);

    if (parent != NULL)
        return parent->firstattrib;
    return NULL;
}

xmlnode xmlnode_get_firstchild(xmlnode parent)
{
    if(parent != NULL && parent->complete == 0)
        _parse_xmlnode(parent, 1);

    if (parent != NULL)
        return parent->firstchild;
    return NULL;
}

xmlnode xmlnode_get_lastchild(xmlnode parent)
{
    if(parent != NULL && parent->complete == 0)
        _parse_xmlnode(parent, 1);

    if (parent != NULL)
        return parent->lastchild;
    return NULL;
}

xmlnode xmlnode_get_nextsibling(xmlnode sibling)
{
    if(sibling != NULL && sibling->parent != NULL && sibling->parent->complete == 0)
        _parse_xmlnode(sibling->parent, 1);

    if (sibling != NULL)
        return sibling->next;
    return NULL;
}

xmlnode xmlnode_get_prevsibling(xmlnode sibling)
{
    if(sibling != NULL && sibling->parent != NULL && sibling->parent->complete == 0)
        _parse_xmlnode(sibling->parent, 1);

    if (sibling != NULL)
        return sibling->prev;
    return NULL;
}

xmlnode xmlnode_get_parent(xmlnode node)
{
    if (node != NULL)
        return node->parent;
    return NULL;
}

char* xmlnode_get_name(xmlnode node)
{
    if (node != NULL)
        return node->name;
    return NULL;
}

char* xmlnode_get_data(xmlnode node)
{
    xmlnode cur;

    if(node == NULL) return NULL;

    if(node->complete == 0)
        _parse_xmlnode(node, 1);

    if(xmlnode_get_type(node) == NTYPE_TAG) /* loop till we find a CDATA */
    {
        for(cur = xmlnode_get_firstchild(node); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        {
            if(xmlnode_get_type(cur) != NTYPE_CDATA) continue;

            /* check for a dirty node w/ unassembled cdata chunks */
            if(xmlnode_get_type(cur->next) == NTYPE_CDATA)
                _xmlnode_merge(cur);

            return cur->data;
        }
    }else{
        return node->data;
    }
    return NULL;
}

int xmlnode_get_datasz(xmlnode node)
{
    if (node != NULL)
    {
        if(node->complete == 0)
            _parse_xmlnode(node, 1);

        /* check for a dirty node w/ unassembled cdata chunks */
        if(xmlnode_get_type(node->next) == NTYPE_CDATA)
            _xmlnode_merge(node);
        return node->data_sz;
    }
    return 0;
}

int xmlnode_get_type(xmlnode node)
{
    if (node != NULL)
        return node->type;
    return NTYPE_UNDEF;
}

int xmlnode_has_children(xmlnode node)
{
    if(node != NULL && node->complete == 0)
        _parse_xmlnode(node, 1);

    if ((node != NULL) && (node->firstchild != NULL))
        return 1;
    return 0;
}

int xmlnode_has_attribs(xmlnode node)
{
    if ((node != NULL) && (node->firstattrib != NULL))
        return 1;
    return 0;
}

pool xmlnode_pool(xmlnode node)
{
    if (node != NULL)
        return node->p;
    return (pool)NULL;
}

void xmlnode_hide(xmlnode child)
{
    xmlnode parent;

    if(child == NULL || child->parent == NULL)
        return;

    parent = child->parent;

    if(parent->complete == 0)
        _parse_xmlnode(parent, 1);

    /* first fix up at the child level */
    _xmlnode_hide_sibling(child);

    /* next fix up at the parent level */
    if(parent->firstchild == child)
        parent->firstchild = child->next;
    if(parent->lastchild == child)
        parent->lastchild = child->prev;
}

void xmlnode_hide_attrib(xmlnode parent, const char *name)
{
    xmlnode attrib;

    if(parent == NULL || parent->firstattrib == NULL || name == NULL)
        return;

    attrib = _xmlnode_search(parent->firstattrib, name, NTYPE_ATTRIB);
    if(attrib == NULL)
        return;

    /* first fix up at the child level */
    _xmlnode_hide_sibling(attrib);

    /* next fix up at the parent level */
    if(parent->firstattrib == attrib)
        parent->firstattrib = attrib->next;
    if(parent->lastattrib == attrib)
        parent->lastattrib = attrib->prev;
}



/*
 *  xmlnode2str -- convert given xmlnode tree into a string
 *
 *  parameters
 *      node -- pointer to the xmlnode structure
 *
 *  results
 *      a pointer to the created string
 *      or NULL if it was unsuccessfull
 */
char *xmlnode2str(xmlnode node)
{
     return spool_print(_xmlnode2spool(node));
}

/*
 *  xmlnode2tstr -- convert given xmlnode tree into a newline terminated string
 *
 *  parameters
 *      node -- pointer to the xmlnode structure
 *
 *  results
 *      a pointer to the created string
 *      or NULL if it was unsuccessfull
 */
char*    xmlnode2tstr(xmlnode node)
{
     spool s = _xmlnode2spool(node);
     if (s != NULL)
	  spool_add(s, "\n");
    return spool_print(s);
}


/* loop through both a and b comparing everything, attribs, cdata, children, etc */
int xmlnode_cmp(xmlnode a, xmlnode b)
{
    int ret = 0;

    while(1)
    {
        if(a == NULL && b == NULL)
            return 0;

        if(a == NULL || b == NULL)
            return -1;

        if(xmlnode_get_type(a) != xmlnode_get_type(b))
            return -1;

        switch(xmlnode_get_type(a))
        {
        case NTYPE_ATTRIB:
            ret = j_strcmp(xmlnode_get_name(a), xmlnode_get_name(b));
            if(ret != 0)
                return -1;
            ret = j_strcmp(xmlnode_get_data(a), xmlnode_get_data(b));
            if(ret != 0)
                return -1;
            break;
        case NTYPE_TAG:
            ret = j_strcmp(xmlnode_get_name(a), xmlnode_get_name(b));
            if(ret != 0)
                return -1;
            ret = xmlnode_cmp(xmlnode_get_firstattrib(a), xmlnode_get_firstattrib(b));
            if(ret != 0)
                return -1;
            ret = xmlnode_cmp(xmlnode_get_firstchild(a), xmlnode_get_firstchild(b));
            if(ret != 0)
                return -1;
            break;
        case NTYPE_CDATA:
            ret = j_strcmp(xmlnode_get_data(a), xmlnode_get_data(b));
            if(ret != 0)
                return -1;
        }
        a = xmlnode_get_nextsibling(a);
        b = xmlnode_get_nextsibling(b);
    }
}


xmlnode xmlnode_insert_tag_node(xmlnode parent, xmlnode node)
{
    xmlnode child;

    child = xmlnode_insert_tag(parent, xmlnode_get_name(node));
    if (xmlnode_has_attribs(node))
        xmlnode_insert_node(child, xmlnode_get_firstattrib(node));
    if (xmlnode_has_children(node))
        xmlnode_insert_node(child, xmlnode_get_firstchild(node));

    return child;
}

/* places copy of node and node's siblings in parent */
void xmlnode_insert_node(xmlnode parent, xmlnode node)
{
    if(node == NULL || parent == NULL)
        return;

    while(node != NULL)
    {
        switch(xmlnode_get_type(node))
        {
        case NTYPE_ATTRIB:
            xmlnode_put_attrib(parent, xmlnode_get_name(node), xmlnode_get_data(node));
            break;
        case NTYPE_TAG:
            xmlnode_insert_tag_node(parent, node);
            break;
        case NTYPE_CDATA:
            xmlnode_insert_cdata(parent, xmlnode_get_data(node), xmlnode_get_datasz(node));
        }
        node = xmlnode_get_nextsibling(node);
    }
}


/* produce full duplicate of x with a new pool, x must be a tag! */
xmlnode xmlnode_dup(xmlnode x)
{
    xmlnode x2;

    if(x == NULL)
        return NULL;

    x2 = xmlnode_new_tag(xmlnode_get_name(x));

    if (xmlnode_has_attribs(x))
        xmlnode_insert_node(x2, xmlnode_get_firstattrib(x));
    if (xmlnode_has_children(x))
        xmlnode_insert_node(x2, xmlnode_get_firstchild(x));

    return x2;
}

xmlnode xmlnode_dup_pool(pool p, xmlnode x)
{
    xmlnode x2;

    if(x == NULL)
        return NULL;

    x2 = xmlnode_new_tag_pool(p, xmlnode_get_name(x));

    if (xmlnode_has_attribs(x))
        xmlnode_insert_node(x2, xmlnode_get_firstattrib(x));
    if (xmlnode_has_children(x))
        xmlnode_insert_node(x2, xmlnode_get_firstchild(x));

    return x2;
}

xmlnode xmlnode_wrap(xmlnode x,const char *wrapper)
{
    xmlnode wrap;
    if(x==NULL||wrapper==NULL) return NULL;
    wrap=xmlnode_new_tag_pool(xmlnode_pool(x),wrapper);
    if(wrap==NULL) return NULL;
    wrap->firstchild=x;
    wrap->lastchild=x;
    x->parent=wrap;
    return wrap;
}

void xmlnode_free(xmlnode node)
{
    if(node == NULL)
        return;

    pool_free(node->p);
}
