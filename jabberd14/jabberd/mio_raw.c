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
 * @file mio_raw.c
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
    (*(mio_raw_cb)m->cb)(m, MIO_BUFFER, m->cb_arg, (char*)buf, bufsz);
}

/**
 * read data from a network socket, that does not use TLS encryption
 *
 * m->flags.recall_read_when_writeable is cleared, m->flags.recall_read_when_readable is updated by this function
 *
 * @param m the mio representing this socket
 * @param buf the buffer where to read data to
 * @param count size of the buffer, how many data should be read at most
 * @return number of bytes read if positive, 0 on EOF, -1 on error (which might be an indication for no data available for reading, in which case m->flags.recall_read_when_readable gets set)
 */
ssize_t _mio_raw_read(mio m, void *buf, size_t count) {
    int ret = 0;

    /* reset recall flags */
    m->flags.recall_read_when_readable = 0;
    m->flags.recall_read_when_writeable = 0;

    /* read ... */
    ret = MIO_READ_FUNC(m->fd, buf, count);

    /* set the recall flag if neccessary */
    if (ret == -1 && (errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)) {
	m->flags.recall_read_when_readable = 1;
    }

    return ret;
}

/**
 * write data to a network socket, that does not use TLS encryption
 *
 * m->flags.recall_write_when_readable is clared, m->flags.recall_write_when_writeable is updated by this function
 *
 * @param m the mio representing this socket
 * @param buf the data that should be written
 * @param count how many bytes should be written (at most)
 * @return number of written bytes if positive, 0 on EOF, -1 on error (which might be an indication that writing would have blocked, in which case m->flags.recall_write_when_writeable gets set)
 */
ssize_t _mio_raw_write(mio m, void *buf, size_t count) {
    int ret = 0;

    /* reset recall flags */
    m->flags.recall_write_when_readable = 0;
    m->flags.recall_write_when_writeable = 0;

    /* write ... */
    ret = MIO_WRITE_FUNC(m->fd, buf, count);

    /* set the recall flag if neccessary */
    if (ret == -1 && (errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)) {
	m->flags.recall_write_when_writeable = 1;
    }
    
    return ret;
}
