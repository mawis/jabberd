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

#include <sstream>
#include <string>

/**
 * @file pool.c
 * @brief Handling of memory pools
 *
 * jadc2s handles memory in pools. Memory can be allocated from a memory pool,
 * and all memory allocated from this pool gets freed if the pool is freed.
 * This makes it more easy to not miss freeing some memory.
 *
 * To use memory pool, you first have to create a memory pool using
 * pool_new(), or pool_heap(). Use pool_heap() if you expect that you
 * will have many small allocations of memory, and pass a bit more than the
 * size you expect to get allocated as the parameter to pool_heap().
 *
 * If you have a pool, you can allocate as much memory as you want from this
 * pool using the functions pmalloc(), pmalloco(), pstrdup(), and pstrdupx().
 *
 * You cannot individually free the memory you allocated in a memory pool.
 * All memory allocated in a memory pool gets freed, when you free the pool.
 * In addition when you free the pool, all functions you registered using
 * pool_cleanup() get called before the actual freeing of the memory is done.
 *
 * The following describes how memory management inside memory pools is
 * done internally. You do not need to know or understand this, if you are
 * just using a pool.
 *
 * Memory pools can allocate the memory they return with the allocation functions
 * (pmalloc(), pmalloco(), pstrdup(), pstrdupx()) on two different ways:
 * - Some memory can be preallocated where memory is then used from. This is
 *   done if a pool is generated using pool_heap(). In that case the amount
 *   if memory, that gets preallocated is the argument of pool_heap().
 * - If no memory has been preallocated (because the memory pool has been
 *   created with pool_new() instead of pool_heap()) each memory allocation
 *   will trigger a memory allocation from the system. The same is done
 *   if the allocated memory chunk is bigger than half the size of the
 *   preallocation.
 * - If memory would be allocated using a preallocation, but the
 *   preallocation has not enough space left to fullfill the request,
 *   a new preallocation of the same size as the first preallocation is done.
 */

#ifdef POOL_DEBUG
int pool__total = 0;
int pool__ltotal = 0;
std::map<std::string, pool> pool__disturbed;
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
#define _pool__malloc malloc	/**< alias for malloc, redefined to a tracking function if POOL_DEBUG is defined */
#define _pool__free free	/**< alias for free, redefined to a tracking function if POOL_DEBUG is defined */
#endif


/**
 * make an empty memory pool
 *
 * Do not use this function directly but instead use pool_new() which will automatically fill in the parameters
 *
 * @param zone the file this function is called from (for pool debugging)
 * @param line the line number this function is called from (for pool debugging)
 * @return the new memory pool
 */
pool _pool_new(char *zone, int line) {
    pool p;
    while ((p = static_cast<pool>(_pool__malloc(sizeof(_pool)))) == NULL)
	sleep(1);
    memset(p, 0, sizeof(_pool));
    p->cleanup = NULL;
    p->heap = NULL;

#ifdef POOL_DEBUG
    p->size = 0;
    p->lsize = -1;
    p->zone[0] = '\0';
    std::ostringstream zone_stream;
    zone_stream << zone << ":" << line;
    std::string zone_str = zone_stream.str();
    if (zone_str.length() >= sizeof(p->zone) - 1)
	zone_str.erase(sizeof(p->zone) - 1);
    strcpy(p->zone, zone_str.c_str());

    std::ostringstream name_stream;
    name_stream << std::hex << static_cast<void*>(p);
    std::string name_str = name_stream.str();
    if (name_str.length() >= sizeof(p->name) -1)
	name_str.erase(sizeof(p->name) - 1);
    strcpy(p->name, name_str.c_str());

    pool__disturbed[p->name] = p;
#endif

    return p;
}

/**
 * free a heap
 *
 * @param arg the pheap to free
 */
static void _pool_heap_free(void *arg) {
    struct pheap *h = (struct pheap *)arg;

    _pool__free(h->block);
    _pool__free(h);
}

/**
 * append a cleanup tracker to the list of cleanup trackers
 *
 * This appends an entry at the end of the list. It should only
 * be used for trackers, that free memory. Trackers that
 * are created for user functions, should be prepended to the
 * list, as this functions should be called before memory is
 * freed.
 *
 * @param p memory pool to add the tracker to
 * @param pf the tracker to add (probably created by _pool_free())
 */
static void _pool_cleanup_append(pool p, struct pfree *pf) {
    struct pfree *cur;

    if (p->cleanup == NULL) {
        p->cleanup = pf;
        return;
    }

    /* fast forward to end of list */
    for (cur = p->cleanup; cur->next != NULL; cur = cur->next)
	/* nothing */;

    cur->next = pf;
}

/**
 * create a cleanup tracker
 *
 * Creates a new list entry for the list of things to do when a pool is freed, but does not
 * add this list item to the list.
 *
 * @param p the memory pool this item is for
 * @param f the function to call when the pool is freed
 * @param arg the argument that should be passed to the function if the pool is freed
 * @return the new list entry (must be added to the list by the caller)
 */
static struct pfree *_pool_free(pool p, pool_cleaner f, void *arg) {
    struct pfree *ret;

    /* make the storage for the tracker */
    while((ret = static_cast<struct pfree*>(_pool__malloc(sizeof(struct pfree)))) == NULL) sleep(1);
    ret->f = f;
    ret->arg = arg;
    ret->next = NULL;

    return ret;
}

/**
 * create a new heap where memory can be allocated from
 *
 * Allocate memory for the heap, initialize the heap, and make sure that this heap gets freed if the memory pool is freed
 *
 * @param p the memory pool the heap should belong to
 * @param size the size for this heap
 * @return the newly created heap
 */
static struct pheap *_pool_heap(pool p, int size) {
    struct pheap *ret;
    struct pfree *clean;

    /* make the return heap */
    while ((ret = static_cast<struct pheap*>(_pool__malloc(sizeof(struct pheap)))) == NULL)
	sleep(1);
    while ((ret->block = _pool__malloc(size)) == NULL)
	sleep(1);
    ret->size = size;
#ifdef POOL_DEBUG
    p->size += size;
#endif
    ret->used = 0;

    /* append to the cleanup list */
    clean = _pool_free(p, _pool_heap_free, (void *)ret);
    _pool_cleanup_append(p, clean);

    return ret;
}

/**
 * create a new memory pool and initialize the memory pool to already contain initial heap size
 *
 * This is the same as _pool_new() but in addition _pool_new_heap() will already create an initial heap.
 *
 * @note This function should not be called directly. Use the pool_heap() macro instead, which will pass zone and line automatically to this function.
 *
 * @param size the size for the initial heap allocation
 * @param zone the file fron which this function is called.
 * @param line the line number from which this function is called
 * @return the new memory pool
 */
pool _pool_new_heap(int size, char *zone, int line) {
    pool p;
    p = _pool_new(zone,line);
    p->heap = _pool_heap(p,size);
    return p;
}

/**
 * allocate memory from a memory pool
 *
 * @param p the pool to allocate the memory from
 * @param size the number of bytes to allocate
 */
void *pmalloc(pool p, int size) {
    void *block;

    if (p == NULL) {
        fprintf(stderr,"Internal error! [pmalloc received NULL pool, unable to track allocation, exiting]\n");
        abort();
    }

    /* if there is no heap for this pool or it's a big request, just raw, I like how we clean this :) */
    if (p->heap == NULL || size > (p->heap->size / 2)) {
        while ((block = _pool__malloc(size)) == NULL)
	    sleep(1);
#ifdef POOL_DEBUG
        p->size += size;
#endif
	/* ensure that this block of memory gets freed when the pool is freed */
        _pool_cleanup_append(p, _pool_free(p, _pool__free, block));
        return block;
    }

    /* if we allocate at least 4 bytes of memory, then take care, that we are alligned to a 4 byte boundary of the memory */
    if (size >= 4)
        while (p->heap->used&7)
	    p->heap->used++;

    /* if the new allocation does not fit in the free part of the existing heap, make a new heap of the same size
     * (if the request would need more memory, we would not have reached here) */
    if (size > (p->heap->size - p->heap->used))
        p->heap = _pool_heap(p, p->heap->size); /* _pool_heap() already registers heap for cleanup */

    /* the current heap has room */
    block = (char *)p->heap->block + p->heap->used;
    p->heap->used += size;
    return block;
}

/**
 * allocate memory from a memory pool and initialize the memory with 0 bytes
 *
 * @param p the pool to allocate the memory in
 * @param size the number of bytes to allocate
 * @return pointer to the new memory block
 */
void *pmalloco(pool p, int size) {
    void *block = pmalloc(p, size);
    memset(block, 0, size);
    return block;
}  

/**
 * make a copy of a zero-terminated string using a memory pool
 * 
 * @param p the memory pool to allocate the new memory in
 * @param src pointer to the zero-terminated string
 * @return copy of the string
 */
char *pstrdup(pool p, const char *src) {
    char *ret;

    if (src == NULL)
        return NULL;

    ret = static_cast<char*>(pmalloc(p,strlen(src) + 1));
    strcpy(ret,src);

    return ret;
}

/**
 * make a copy of some memory content using a memory pool
 *
 * @param p the memory pool to allocate the new memory in
 * @param src pointer to the begin of the memory block that should be copied (block may contain 0 bytes)
 * @param len length of the memory block
 * @return pointer to the copy of the memory block
 */
char *pstrdupx(pool p, const char *src, int len) {
    char *ret;

    if (src == NULL || len <= 0)
        return NULL;

    ret = static_cast<char*>(pmalloc(p,len + 1));
    memcpy(ret,src,len);
    ret[len] = '\0';

    return ret;
}

/**
 * free a memory pool
 *
 * First call all functions that have been registered for this pool using pool_cleanup().
 * Then free all memory allocated with this pool
 *
 * @param p the memory pool to free
 */
void pool_free(pool p) {
    struct pfree *cur, *stub;

    if (p == NULL)
	return;

    cur = p->cleanup;
    while (cur != NULL) {
        (*cur->f)(cur->arg);
        stub = cur->next;
        _pool__free(cur);
        cur = stub;
    }

#ifdef POOL_DEBUG
    pool__disturbed.erase(p->name);
#endif

    _pool__free(p);

}

/**
 * public cleanup utils, insert in a way that they are run FIFO, before mem frees
 *
 * @param p the memory pool the cleanup function should be related to
 * @param f which function to call when the pool p is freed
 * @param arg argument to pass to the cleanup function
 */
void pool_cleanup(pool p, pool_cleaner f, void *arg) {
    struct pfree *clean;

    clean = _pool_free(p, f, arg);
    clean->next = p->cleanup;
    p->cleanup = clean;
}

#ifdef POOL_DEBUG
void pool_stat(int full) {
    std::map<std::string, pool>::iterator p;
    for (p=pool__disturbed.begin(); p!=pool__disturbed.end(); ++p) {
	if (p->second->lsize == -1)
	    std::cout << p->second->zone << ": " << p->second->name << " is a new pool" << std::endl;
	else if (p->second->size > p->second->lsize)
	    std::cout << p->second->zone << ": " << p->second->name << " grew " << (p->second->size - p->second->lsize) << std::endl;
	else if (full)
	    std::cout << p->second->zone << ": " << p->second->name << " exists " << p->second->size << std::endl;
	p->second->lsize = p->second->size;
    }

    if (pool__total != pool__ltotal)
	std::cout << pool__total << "\ttotal missed mallocs" << std::endl;
    pool__ltotal = pool__total;
    return;
}
#else
/**
 * Write pool statistics to the standard output
 *
 * @note If not compiled with POOL_DEBUG definied, this has an empty implementation and nothing is done
 *
 * @param full 0 only changes are written, else full output (full output shut be used on last print before exiting jadc2s
 */
void pool_stat(int full) {
    return;
}
#endif
