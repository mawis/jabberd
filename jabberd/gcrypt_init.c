/*
 * Copyright (c) 2006-2007 Matthias Wimmer
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

/**
 * @file gcrypt_init.c
 * @brief Init the gcrypt library
 *
 * This would be part of mio_tls.cc, but the code produced by the macro cannot be compiled with a C++ compiler, so I have to place this in a C file.
 */

#include <gcrypt.h>
#include <pth.h>
#include <errno.h>

/* prepare gcrypt for libpth */
GCRY_THREAD_OPTION_PTH_IMPL;

/**
 * Tell gcrypt we are using libpth
 */
void mio_tls_gcrypt_init(void) {
    /* prepare gcrypt with libpth */
    gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pth);
}
