/*
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 *
 * Portions Copyright (c) 2006-2007 Matthias Wimmer
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
 * @file mio_raw.cc
 * @brief MIO read/write functions to read/write on unencrypted network sockets
 */

#include <jabberd.h>

/**
 * receiving bytes on a network socket
 *
 * the _mio_raw_parser implements a mio parser, that does not parse the received
 * data at all, but just passes the received data as bytes to the application
 * callback function, that registered for this mio object
 *
 * @param m the mio object where the data has been read
 * @param buf the data that has been read
 * @param bufsz the number of bytes, that have been read on the socket
 */
void _mio_raw_parser(mio m, const void *buf, size_t bufsz) {
    (*m->cb)(m, MIO_BUFFER, m->cb_arg, NULL, (char*)buf, bufsz);
}

/**
 * read data from a network socket, that does not use TLS encryption
 *
 * m->flags.recall_read_when_writeable is cleared, m->flags.recall_read_when_readable is updated by this function
 *
 * @param m the mio representing this socket
 * @param buf the buffer where to read data to
 * @param count size of the buffer, how many data should be read at most
 * @return 0 < ret < count: ret bytes read and no more bytes to read; ret = count: ret bytes read, possibly more bytes to read; ret = 0: currently nothing to read; ret < 0: non-recoverable error or connection closed
 */
ssize_t _mio_raw_read(mio m, void *buf, size_t count) {
    ssize_t read_return = 0;

    read_return = pth_read(m->fd, buf, count);

    if (read_return > 0) {
	return read_return;
    }

    if (read_return == -1 && (errno == EINTR || errno == EAGAIN)) {
	return 0;
    }

    return -1;
}

/**
 * write data to a network socket, that does not use TLS encryption
 *
 * m->flags.recall_write_when_readable is clared, m->flags.recall_write_when_writeable is updated by this function
 *
 * @param m the mio representing this socket
 * @param buf the data that should be written
 * @param count how many bytes should be written (at most)
 * @return ret > 0: ret bytes written; ret == 0: no bytes could be written; ret < 0: non-recoverable error or connection closed
 */
ssize_t _mio_raw_write(mio m, void *buf, size_t count) {
    ssize_t write_return = 0;

    write_return = pth_write(m->fd, buf, count);

    if (write_return > 0) {
	return write_return;
    }

    if (write_return == -1 && (errno == EINTR || errno == EAGAIN)) {
	return 0;
    }

    return -1;
}
