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

#include <jabberdlib.h>


#ifdef POOL_DEBUG
int pool__total = 0;
int pool__ltotal = 0;
xht pool__disturbed = NULL;
void *_pool__malloc(size_t size)
{
    pool__total++;
    return malloc(size);
}
void _pool__free(void *block)
{
    pool__total--;
    free(block);
}
#else
#define _pool__malloc malloc
#define _pool__free free
#endif


/* make an empty pool */
pool _pool_new(char *zone, int line)
{
#ifdef POOL_DEBUG
    int old__pool__total;
#endif

    pool p;
    while((p = _pool__malloc(sizeof(_pool))) == NULL) sleep(1);
    p->cleanup = NULL;
    p->heap = NULL;
    p->size = 0;

#ifdef POOL_DEBUG
    p->lsize = -1;
    p->zone[0] = '\0';
    strcat(p->zone,zone);
    snprintf(p->zone, sizeof(p->zone), "%s:%i", zone, line);
    snprintf(p->name, sizeof(p->name), "%X", p);

    if(pool__disturbed == NULL)
    {
        pool__disturbed = (xht)1; /* reentrancy flag! */
	old__pool__total = pool__total; /* we won't be able to free this xhash */
        pool__disturbed = xhash_new(POOL_NUM);
	pool__total = old__pool__total;
    }
    if(pool__disturbed != (xht)1)
        xhash_put(pool__disturbed,p->name,p);
#endif

    return p;
}

/* free a heap */
void _pool_heap_free(void *arg)
{
    struct pheap *h = (struct pheap *)arg;

    _pool__free(h->block);
    _pool__free(h);
}

/* mem should always be freed last */
void _pool_cleanup_append(pool p, struct pfree *pf)
{
    struct pfree *cur;

    if(p->cleanup == NULL)
    {
        p->cleanup = pf;
        return;
    }

    /* fast forward to end of list */
    for(cur = p->cleanup; cur->next != NULL; cur = cur->next);

    cur->next = pf;
}

/* create a cleanup tracker */
struct pfree *_pool_free(pool p, pool_cleaner f, void *arg)
{
    struct pfree *ret;

    /* make the storage for the tracker */
    while((ret = _pool__malloc(sizeof(struct pfree))) == NULL) sleep(1);
    ret->f = f;
    ret->arg = arg;
    ret->next = NULL;

    return ret;
}

/* create a heap and make sure it get's cleaned up */
struct pheap *_pool_heap(pool p, int size)
{
    struct pheap *ret;
    struct pfree *clean;

    /* make the return heap */
    while((ret = _pool__malloc(sizeof(struct pheap))) == NULL) sleep(1);
    while((ret->block = _pool__malloc(size)) == NULL) sleep(1);
    ret->size = size;
    p->size += size;
    ret->used = 0;

    /* append to the cleanup list */
    clean = _pool_free(p, _pool_heap_free, (void *)ret);
    clean->heap = ret; /* for future use in finding used mem for pstrdup */
    _pool_cleanup_append(p, clean);

    return ret;
}

pool _pool_new_heap(int size, char *zone, int line)
{
    pool p;
    p = _pool_new(zone, line);
    p->heap = _pool_heap(p,size);
    return p;
}

void *pmalloc(pool p, int size)
{
    void *block;

    if(p == NULL)
    {
        fprintf(stderr,"Memory Leak! [pmalloc received NULL pool, unable to track allocation, exiting]\n");
        abort();
    }

    /* if there is no heap for this pool or it's a big request, just raw, I like how we clean this :) */
    if(p->heap == NULL || size > (p->heap->size / 2))
    {
        while((block = _pool__malloc(size)) == NULL) sleep(1);
        p->size += size;
        _pool_cleanup_append(p, _pool_free(p, _pool__free, block));
        return block;
    }

    /* we have to preserve boundaries, long story :) */
    if(size >= 4)
        while(p->heap->used&7) p->heap->used++;

    /* if we don't fit in the old heap, replace it */
    if(size > (p->heap->size - p->heap->used))
        p->heap = _pool_heap(p, p->heap->size);

    /* the current heap has room */
    block = (char *)p->heap->block + p->heap->used;
    p->heap->used += size;
    return block;
}

void *pmalloc_x(pool p, int size, char c)
{
   void* result = pmalloc(p, size);
   if (result != NULL)
           memset(result, c, size);
   return result;
}  

/* easy safety utility (for creating blank mem for structs, etc) */
void *pmalloco(pool p, int size)
{
    void *block = pmalloc(p, size);
    memset(block, 0, size);
    return block;
}  

/* XXX efficient: move this to const char * and then loop throug the existing heaps to see if src is within a block in this pool */
char *pstrdup(pool p, const char *src)
{
    char *ret;

    if(src == NULL)
        return NULL;

    ret = pmalloc(p,strlen(src) + 1);
    strcpy(ret,src);

    return ret;
}

/* when move above, this one would actually return a new block */
char *pstrdupx(pool p, const char *src)
{
    return pstrdup(p, src);
}

int pool_size(pool p)
{
    if(p == NULL) return 0;

    return p->size;
}

void pool_free(pool p)
{
    struct pfree *cur, *stub;

    if(p == NULL) return;

    cur = p->cleanup;
    while(cur != NULL)
    {
        (*cur->f)(cur->arg);
        stub = cur->next;
        _pool__free(cur);
        cur = stub;
    }

#ifdef POOL_DEBUG
    xhash_zap(pool__disturbed,p->name);
#endif

    _pool__free(p);

}

/* public cleanup utils, insert in a way that they are run FIFO, before mem frees */
void pool_cleanup(pool p, pool_cleaner f, void *arg)
{
    struct pfree *clean;

    clean = _pool_free(p, f, arg);
    clean->next = p->cleanup;
    p->cleanup = clean;
}

#ifdef POOL_DEBUG
void debug_log(char *zone, const char *msgfmt, ...);
void _pool_stat(xht h, const char *key, void *data, void *arg)
{
    pool p = (pool)data;

    if(p->lsize == -1)
        debug_log("pool_debug","%s: %s is a new pool",p->zone, p->name);
    else if(p->size > p->lsize)
        debug_log("pool_debug","%s: %s grew %d",p->zone, p->name, p->size - p->lsize);
    else if((int)arg)
        debug_log("pool_debug","%s: %s exists %d",p->zone,p->name, p->size);
    p->lsize = p->size;
}

/**
 * print memory pool statistics
 *
 * @param full make a full report? (0 = no, 1 = yes)
 */
void pool_stat(int full)
{
    if (pool__disturbed == NULL || pool__disturbed == (xht)1)
	return;
    
    xhash_walk(pool__disturbed,_pool_stat,(void *)full);
    if(pool__total != pool__ltotal)
        debug_log("pool_debug","%d\ttotal missed mallocs",pool__total);
    pool__ltotal = pool__total;

    return;
}
#else
void pool_stat(int full)
{
    return;
}
#endif
