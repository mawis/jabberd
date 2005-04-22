/* --------------------------------------------------------------------------
 *
 *  jabberd 1.4.4 GPL - XMPP/Jabber server implementation
 *
 *  Copyrights
 *
 *  Portions created by or assigned to Jabber.com, Inc. are
 *  Copyright (C) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 *  information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 *  Portions Copyright (C) 1998-1999 Jeremie Miller.
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 *  Special exception for linking jabberd 1.4.4 GPL with OpenSSL:
 *
 *  In addition, as a special exception, you are allowed to link the code
 *  of jabberd 1.4.4 GPL with the OpenSSL library (or with modified versions
 *  of OpenSSL that use the same license as OpenSSL), and distribute linked
 *  combinations including the two. You must obey the GNU General Public
 *  License in all respects for all of the code used other than OpenSSL.
 *  If you modify this file, you may extend this exception to your version
 *  of the file, but you are not obligated to do so. If you do not wish
 *  to do so, delete this exception statement from your version.
 *
 * --------------------------------------------------------------------------*/

#include <jabberd.h>

void _mio_raw_parser(mio m, const void *buf, size_t bufsz)
{
    (*(mio_raw_cb)m->cb)(m, MIO_BUFFER, m->cb_arg, (char*)buf, bufsz);
}

ssize_t _mio_raw_read(mio m, void *buf, size_t count)
{
    return MIO_READ_FUNC(m->fd, buf, count);
}

ssize_t _mio_raw_write(mio m, void *buf, size_t count)
{
    return MIO_WRITE_FUNC(m->fd, buf, count);
}

int _mio_raw_accept(mio m, struct sockaddr* serv_addr, socklen_t* addrlen)
{
    return MIO_ACCEPT_FUNC(m->fd, serv_addr, addrlen);
}

int _mio_raw_connect(mio m, struct sockaddr* serv_addr, socklen_t  addrlen)
{
    sigset_t set;
    int sig;
    pth_event_t wevt;

    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);

    wevt = pth_event(PTH_EVENT_SIGS, &set, &sig);
    pth_fdmode(m->fd, PTH_FDMODE_BLOCK);
    return pth_connect_ev(m->fd, serv_addr, addrlen, wevt);
}
