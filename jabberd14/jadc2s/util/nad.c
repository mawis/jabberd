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
 * --------------------------------------------------------------------------*/

#include "util.h"

#define BLOCKSIZE 1024

/* internal: do and return the math and ensure it gets realloc'd */
int _nad_realloc(void **oblocks, int len)
{
    void *nblocks;
    int nlen;

    /* round up to standard block sizes */
    nlen = (((len-1)/BLOCKSIZE)+1)*BLOCKSIZE;

    /* keep trying till we get it */
    while((nblocks = realloc(*oblocks, nlen)) == NULL) sleep(1);
    *oblocks = nblocks;
    return nlen;
}

/* this is the safety check used to make sure there's always enough mem */
#define NAD_SAFE(blocks, size, len) if((size) > len) len = _nad_realloc((void**)&(blocks),(size));

/* internal: append some cdata and return the index to it */
int _nad_cdata(nad_t nad, char *cdata, int len)
{
    NAD_SAFE(nad->cdata, nad->ccur + len, nad->clen);

    memcpy(nad->cdata + nad->ccur, cdata, len);
    nad->ccur += len;
    return nad->ccur - len;
}

/* internal: create a new attr on any given elem */
int _nad_attr(nad_t nad, int elem, char *name, char *val)
{
    int attr;

    /* make sure there's mem for us */
    NAD_SAFE(nad->attrs, (nad->acur + 1) * sizeof(struct nad_attr_st), nad->alen);

    attr = nad->acur;
    nad->acur++;
    nad->attrs[attr].next = nad->elems[elem].attr;
    nad->elems[elem].attr = attr;
    nad->attrs[attr].lname = strlen(name);
    nad->attrs[attr].iname = _nad_cdata(nad,name,nad->attrs[attr].lname);
    nad->attrs[attr].lval = strlen(val);
    nad->attrs[attr].ival = _nad_cdata(nad,val,nad->attrs[attr].lval);    

    return attr;
}

/* create a new cache, simple pointer to a list of nads */
nad_cache_t nad_cache_new(void)
{
    nad_cache_t cache;
    while((cache = malloc(sizeof(nad_cache_t))) == NULL) sleep(1);
    *cache = NULL;
    return cache;
}


/* free the cache and any nads in it */
void nad_cache_free(nad_cache_t cache)
{
    nad_t cur;
    while((cur = *cache) != NULL)
    {
        *cache = cur->next;
        free(cur->elems);
        free(cur->attrs);
        free(cur->cdata);
        free(cur->depths);
        free(cur);
    }
    free(cache);
}

/* get the next nad from the cache, or create some */
nad_t nad_new(nad_cache_t cache)
{
    nad_t nad;

    if(*cache != NULL)
    {
        nad = *cache;
        *cache = nad->next;
        nad->ccur = nad->ecur = nad->acur = 0;
        return nad;
    }

    while((nad = malloc(sizeof(struct nad_st))) == NULL) sleep(1);
    memset(nad,0,sizeof(struct nad_st));
    return nad;
}

nad_t nad_copy(nad_cache_t cache, nad_t nad)
{
    nad_t copy;

    if(nad == NULL) return NULL;

    /* get one from the cache */
    copy = nad_new(cache);

    /* if it's not large enough, make bigger */
    NAD_SAFE(copy->elems, nad->elen, copy->elen);
    NAD_SAFE(copy->attrs, nad->alen, copy->alen);
    NAD_SAFE(copy->cdata, nad->clen, copy->clen);

    /* copy all data */
    memcpy(copy->elems, nad->elems, nad->elen);
    memcpy(copy->attrs, nad->attrs, nad->alen);
    memcpy(copy->cdata, nad->cdata, nad->clen);

    /* sync data */
    copy->ecur = nad->ecur;
    copy->acur = nad->acur;
    copy->ccur = nad->ccur;

    return copy;
}

/* plug a nad back in the cache */
void nad_free(nad_cache_t cache, nad_t nad)
{
    if(nad == NULL) return;

    nad->next = *cache;
    *cache = nad;
}

/* locate the next elem at a given depth with an optional matching name */
int nad_find_elem(nad_t nad, int elem, char *name, int depth)
{
    int lname = 0;

    /* make sure there are valid args */
    if(elem >= nad->ecur || name == NULL) return -1;

    /* set up args for searching */
    depth = nad->elems[elem].depth + depth;
    if(name != NULL) lname = strlen(name);

    /* search */
    for(elem++;elem < nad->ecur;elem++)
        if(nad->elems[elem].depth == depth && (lname <= 0 || (lname == nad->elems[elem].lname && strncmp(name,nad->cdata + nad->elems[elem].iname, lname) == 0)))
            return elem;

    return -1;
}

/* get a matching attr on this elem, both name and optional val */
int nad_find_attr(nad_t nad, int elem, char *name, char *val)
{
    int attr;
    int lname, lval;

    /* make sure there are valid args */
    if(elem >= nad->ecur || name == NULL) return -1;

    attr = nad->elems[elem].attr;
    lname = strlen(name);
    if(val != NULL)
        lval = strlen(val);
    else
        lval = 0;

    while(attr >= 0)
    {
        /* hefty, match name and if a val, also match that */
        if(lname == nad->attrs[attr].lname && strncmp(name,nad->cdata + nad->attrs[attr].iname, lname) == 0 && 
          (lval <= 0 || (lval == nad->attrs[attr].lval && strncmp(val,nad->cdata + nad->attrs[attr].ival, lval) == 0)))
            return attr;
        attr = nad->attrs[attr].next;
    }
    return -1;
}

/* create, update, or zap any matching attr on this elem */
void nad_set_attr(nad_t nad, int elem, char *name, char *val)
{
    int attr;

    /* find one to replace first */
    if((attr = nad_find_attr(nad, elem, name, NULL)) < 0)
    {
        /* only create new if there's a value to store */
        if(val != NULL)
            _nad_attr(nad, elem, name, val);
        return;
    }

    /* got matching, update value or zap */
    if(val == NULL)
    {
        nad->attrs[attr].lval = nad->attrs[attr].lname = 0;
    }else{
        nad->attrs[attr].lval = strlen(val);
        nad->attrs[attr].ival = _nad_cdata(nad,val,nad->attrs[attr].lval);
    }

}

/* shove in a new child elem after the given one */
int nad_insert_elem(nad_t nad, int parent, char *name, char *cdata)
{
    int elem = parent + 1;

    NAD_SAFE(nad->elems, (nad->ecur + 1) * sizeof(struct nad_elem_st), nad->elen);

    /* relocate all the rest of the elems (unless we're at the end already) */
    if(nad->ecur != elem)
        memmove(&nad->elems[elem + 1], &nad->elems[elem], (nad->ecur - elem) * sizeof(struct nad_elem_st));
    nad->ecur++;

    /* set up req'd parts of new elem */
    nad->elems[elem].lname = strlen(name);
    nad->elems[elem].iname = _nad_cdata(nad,name,nad->elems[elem].lname);
    nad->elems[elem].attr = -1;
    nad->elems[elem].itail = nad->elems[elem].ltail = 0;

    /* add cdata if given */
    if(cdata != NULL)
    {
        nad->elems[elem].lcdata = strlen(cdata);
        nad->elems[elem].icdata = _nad_cdata(nad,cdata,nad->elems[elem].lcdata);
    }else{
        nad->elems[elem].icdata = nad->elems[elem].lcdata = 0;
    }

    /* parent/child */
    nad->elems[elem].depth = nad->elems[parent].depth + 1;

    return elem;
}

/* wrap an element with another element */
void nad_wrap_elem(nad_t nad, int elem, char *name)
{
    int cur;

    /* !!! it is your fault if you call this with a bad elem */
    if(elem >= nad->ecur) return;

    NAD_SAFE(nad->elems, (nad->ecur + 1) * sizeof(struct nad_elem_st), nad->elen);

    /* relocate all the rest of the elems after us */
    memmove(&nad->elems[elem + 1], &nad->elems[elem], (nad->ecur - elem) * sizeof(struct nad_elem_st));
    nad->ecur++;

    /* set up req'd parts of new elem */
    nad->elems[elem].lname = strlen(name);
    nad->elems[elem].iname = _nad_cdata(nad,name,nad->elems[elem].lname);
    nad->elems[elem].attr = -1;
    nad->elems[elem].itail = nad->elems[elem].ltail = 0;
    nad->elems[elem].icdata = nad->elems[elem].lcdata = 0;

    /* raise the bar on all the children */
    nad->elems[elem+1].depth++;
    for(cur = elem + 2; cur < nad->ecur && nad->elems[cur].depth > nad->elems[elem].depth; cur++) nad->elems[cur].depth++;
}

/* create a new elem on the list */
int nad_append_elem(nad_t nad, char *name, int depth)
{
    int elem;

    /* make sure there's mem for us */
    NAD_SAFE(nad->elems, (nad->ecur + 1) * sizeof(struct nad_elem_st), nad->elen);

    elem = nad->ecur;
    nad->ecur++;
    nad->elems[elem].lname = strlen(name);
    nad->elems[elem].iname = _nad_cdata(nad,name,nad->elems[elem].lname);
    nad->elems[elem].icdata = nad->elems[elem].lcdata = 0;
    nad->elems[elem].itail = nad->elems[elem].ltail = 0;
    nad->elems[elem].attr = -1;
    nad->elems[elem].depth = depth;

    /* make sure there's mem in the depth array, then track us */
    NAD_SAFE(nad->depths, (depth + 1) * sizeof(int), nad->dlen);
    nad->depths[depth] = elem;

    return elem;
}

/* attach new attr to the last elem */
int nad_append_attr(nad_t nad, char *name, char *val)
{
    return _nad_attr(nad, nad->ecur - 1, name, val);
}

/* append new cdata to the last elem */
void nad_append_cdata(nad_t nad, char *cdata, int len, int depth)
{
    int elem = nad->ecur - 1;

    /* make sure this cdata is the child of the last elem to append */
    if(nad->elems[elem].depth == depth - 1)
    {
        if(nad->elems[elem].icdata == 0)
            nad->elems[elem].icdata = nad->ccur;
        _nad_cdata(nad,cdata,len);
        nad->elems[elem].lcdata += len;
        return;
    }

    /* otherwise, pin the cdata on the tail of the last element at this depth */
    elem = nad->depths[depth];
    if(nad->elems[elem].itail == 0)
        nad->elems[elem].itail = nad->ccur;
    _nad_cdata(nad,cdata,len);
    nad->elems[elem].ltail += len;
}

void _nad_escape(nad_t nad, int data, int len, int flag)
{
    char *c;
    int ic;

    if(len <= 0) return;

    /* first, if told, find and escape ' */
    while(flag >= 2 && (c = memchr(nad->cdata + data,'\'',len)) != NULL)
    {
        /* get offset */
        ic = c - nad->cdata;

        /* cute, eh?  handle other data before this normally */
        _nad_escape(nad, data, ic - data, 1);

        /* ensure enough space, and add our escaped &apos; */
        NAD_SAFE(nad->cdata, nad->ccur + 6, nad->clen);
        memcpy(nad->cdata + nad->ccur, "&apos;", 6);
        nad->ccur += 6;

        /* just update and loop for more */
        len -= (ic+1) - data;
        data = ic+1;
    }

    /* next look for < */
    while(flag >= 1 && (c = memchr(nad->cdata + data,'<',len)) != NULL)
    {
        ic = c - nad->cdata;
        _nad_escape(nad, data, ic - data, 0);

        /* ensure enough space, and add our escaped &apos; */
        NAD_SAFE(nad->cdata, nad->ccur + 4, nad->clen);
        memcpy(nad->cdata + nad->ccur, "&lt;", 4);
        nad->ccur += 4;

        /* just update and loop for more */
        len -= (ic+1) - data;
        data = ic+1;
    }

    /* if & is found, escape it */
    while((c = memchr(nad->cdata + data,'&',len)) != NULL)
    {
        ic = c - nad->cdata;

        /* ensure enough space */
        NAD_SAFE(nad->cdata, nad->ccur + 5 + (ic - data), nad->clen);

        /* handle normal data */
        memcpy(nad->cdata + nad->ccur, nad->cdata + data, (ic - data));
        nad->ccur += (ic - data);

        /* append escaped &lt; */
        memcpy(nad->cdata + nad->ccur, "&amp;", 5);
        nad->ccur += 5;

        /* just update and loop for more */
        len -= (ic+1) - data;
        data = ic+1;
    }

    /* nothing exciting, just append normal cdata */
    NAD_SAFE(nad->cdata, nad->ccur + len, nad->clen);
    memcpy(nad->cdata + nad->ccur, nad->cdata + data, len);
    nad->ccur += len;
}

/* internal recursive printing function */
int _nad_lp0(nad_t nad, int elem)
{
    int attr;
    int ndepth;

    /* there's a lot of code in here, but don't let that scare you, it's just duplication in order to be a bit more efficient cpu-wise */

    /* this whole thing is in a big loop for processing siblings */
    while(elem != nad->ecur)
    {

    /* make enough space for the opening element */
    NAD_SAFE(nad->cdata, nad->ccur + nad->elems[elem].lname + 1, nad->clen);

    /* copy in the name parts */
    *(nad->cdata + nad->ccur++) = '<';
    memcpy(nad->cdata + nad->ccur, nad->cdata + nad->elems[elem].iname, nad->elems[elem].lname);
    nad->ccur += nad->elems[elem].lname;

    for(attr = nad->elems[elem].attr; attr >= 0; attr = nad->attrs[attr].next)
    {
        if(nad->attrs[attr].lname <= 0) continue;

        /* make enough space for the wrapper part */
        NAD_SAFE(nad->cdata, nad->ccur + nad->attrs[attr].lname + 3, nad->clen);

        /* copy in the name parts */
        *(nad->cdata + nad->ccur++) = ' ';
        memcpy(nad->cdata + nad->ccur, nad->cdata + nad->attrs[attr].iname, nad->attrs[attr].lname);
        nad->ccur += nad->attrs[attr].lname;
        *(nad->cdata + nad->ccur++) = '=';
        *(nad->cdata + nad->ccur++) = '\'';

        /* copy in the escaped value */
        _nad_escape(nad, nad->attrs[attr].ival, nad->attrs[attr].lval, 2);

        /* make enough space for the closing quote and add it */
        NAD_SAFE(nad->cdata, nad->ccur + 1, nad->clen);
        *(nad->cdata + nad->ccur++) = '\'';
    }

    /* figure out what's next */
    if(elem+1 == nad->ecur)
        ndepth = -1;
    else
        ndepth = nad->elems[elem+1].depth;

    /* handle based on if there are children, update nelem after done */
    if(ndepth <= nad->elems[elem].depth)
    {
        /* make sure there's enough for what we could need */
        NAD_SAFE(nad->cdata, nad->ccur + 2, nad->clen);
        if(nad->elems[elem].lcdata == 0)
        {
            memcpy(nad->cdata + nad->ccur, "/>", 2);
            nad->ccur += 2;
        }else{
            *(nad->cdata + nad->ccur++) = '>';

            /* copy in escaped cdata */
            _nad_escape(nad, nad->elems[elem].icdata, nad->elems[elem].lcdata,1);

            /* close tag */
            NAD_SAFE(nad->cdata, nad->ccur + 3 + nad->elems[elem].lname, nad->clen);
            memcpy(nad->cdata + nad->ccur, "</", 2);
            nad->ccur += 2;
            memcpy(nad->cdata + nad->ccur, nad->cdata + nad->elems[elem].iname, nad->elems[elem].lname);
            nad->ccur += nad->elems[elem].lname;
            *(nad->cdata + nad->ccur++) = '>';
        }

        /* always try to append the tail */
        _nad_escape(nad, nad->elems[elem].itail, nad->elems[elem].ltail,1);

        /* if no siblings either, bail */
        if(ndepth < nad->elems[elem].depth)
            return elem+1;

        /* next sibling */
        elem++;
    }else{
        int nelem;
        /* process any children */

        /* close ourself and append any cdata first */
        NAD_SAFE(nad->cdata, nad->ccur + 1, nad->clen);
        *(nad->cdata + nad->ccur++) = '>';
        _nad_escape(nad, nad->elems[elem].icdata, nad->elems[elem].lcdata,1);

        /* process children */
        nelem = _nad_lp0(nad,elem+1);

        /* close and tail up */
        NAD_SAFE(nad->cdata, nad->ccur + 3 + nad->elems[elem].lname, nad->clen);
        memcpy(nad->cdata + nad->ccur, "</", 2);
        nad->ccur += 2;
        memcpy(nad->cdata + nad->ccur, nad->cdata + nad->elems[elem].iname, nad->elems[elem].lname);
        nad->ccur += nad->elems[elem].lname;
        *(nad->cdata + nad->ccur++) = '>';
        _nad_escape(nad, nad->elems[elem].itail, nad->elems[elem].ltail,1);

        /* for next sibling in while loop */
        elem = nelem;
    }

    /* here's the end of that big while loop */
    }

    return elem;
}

void nad_print(nad_t nad, int elem, char **xml, int *len)
{
    int ixml = nad->ccur;

    _nad_lp0(nad,elem);
    *len = nad->ccur - ixml;
    *xml = nad->cdata + ixml;
}

/*
 * nads serialize to a buffer of this form:
 *
 * [buflen][elen][alen][clen][dlen][ecur][acur][ccur][elems][attrs][cdata][depths]
 *
 * nothing is done with endianness or word length, so the nad must be
 * serialized and deserialized on the same platform
 *
 * buflen is not actually used by deserialize(), but is provided as a
 * convenience to the application so it knows how many bytes to read before
 * passing them in to deserialize()
 */

void nad_serialize(nad_t nad, char **buf, int *len) {
    char *pos;

    *len = sizeof(int) * 8 + /* 7 ints in nad_t, plus one for len */
           sizeof(struct nad_elem_st) * nad->elen +
           sizeof(struct nad_attr_st) * nad->alen +
           sizeof(char) * nad->clen +
           sizeof(int) * nad->dlen;

    *buf = (char *) malloc(*len);

    pos = *buf;         * (int *) pos = *len;
    pos += sizeof(int); * (int *) pos = nad->elen;
    pos += sizeof(int); * (int *) pos = nad->alen;
    pos += sizeof(int); * (int *) pos = nad->clen;
    pos += sizeof(int); * (int *) pos = nad->dlen;
    pos += sizeof(int); * (int *) pos = nad->ecur;
    pos += sizeof(int); * (int *) pos = nad->acur;
    pos += sizeof(int); * (int *) pos = nad->ccur;

    pos += sizeof(int);                            memcpy(pos, nad->elems, sizeof(struct nad_elem_st) * nad->elen);
    pos += sizeof(struct nad_elem_st) * nad->elen; memcpy(pos, nad->attrs, sizeof(struct nad_attr_st) * nad->alen);
    pos += sizeof(struct nad_attr_st) * nad->alen; memcpy(pos, nad->cdata, sizeof(char) * nad->clen);
    pos += sizeof(char) * nad->clen;               memcpy(pos, nad->depths, sizeof(int) * nad->dlen);
}

nad_t nad_deserialize(nad_cache_t cache, char *buf) {
    nad_t nad = nad_new(cache);
    char *pos = buf + sizeof(int);  /* skip len */

    nad->elen = * (int *) pos; pos += sizeof(int);
    nad->alen = * (int *) pos; pos += sizeof(int);
    nad->clen = * (int *) pos; pos += sizeof(int);
    nad->dlen = * (int *) pos; pos += sizeof(int);
    nad->ecur = * (int *) pos; pos += sizeof(int);
    nad->acur = * (int *) pos; pos += sizeof(int);
    nad->ccur = * (int *) pos; pos += sizeof(int);

    nad->elems = (struct nad_elem_st *) malloc(sizeof(struct nad_elem_st) * nad->elen);
    memcpy(nad->elems, pos, sizeof(struct nad_elem_st) * nad->elen);
    pos += sizeof(struct nad_elem_st) * nad->elen;

    nad->attrs = (struct nad_attr_st *) malloc(sizeof(struct nad_attr_st) * nad->alen);
    memcpy(nad->attrs, pos, sizeof(struct nad_attr_st) * nad->alen);
    pos += sizeof(struct nad_attr_st) * nad->alen;

    nad->cdata = (char *) malloc(sizeof(char) * nad->clen);
    memcpy(nad->cdata, pos, sizeof(char) * nad->clen);
    pos += sizeof(char) * nad->clen;

    nad->depths = (int *) malloc(sizeof(int) * nad->dlen);
    memcpy(nad->depths, pos, sizeof(int) * nad->dlen);

    return nad;
}
