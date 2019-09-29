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

#ifndef __POOL_H
#define __POOL_H

#ifdef POOL_DEBUG
#define POOL_NUM 40009
#endif

typedef struct pool_struct _pool, *pool;

/* pool_cleaner - callback type which is associated
   with a pool entry; invoked when the pool entry is
   free'd */
typedef void (*pool_cleaner)(void *arg);

#ifdef POOL_DEBUG
#  define pool_new() _pool_new(__FILE__, __LINE__)
#  define pool_heap(i) _pool_new_heap(i, __FILE__, __LINE__)
#else
#  define pool_heap(i) _pool_new_heap(i, NULL, 0)
#  define pool_new() _pool_new(NULL, 0)
#endif

pool _pool_new(char const *zone, int line);
pool _pool_new_heap(int size, char const *zone, int line);
void *pmalloco(pool p, int size);
char *pstrdup(pool p, char const *src);
void pool_stat(int full);
void pool_cleanup(pool p, pool_cleaner f, void *arg);
void pool_free(pool p);
int pool_size(_pool const *p);

#endif // __POOL_H
