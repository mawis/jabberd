/*
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
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Jabber
 *  Copyright (C) 1998-1999 The Jabber Team http://jabber.org/
 *
 *  shutdown.c -- server shutdown functions
 *
 */

#include "jsm.h"

/*
 *  jabber_transport_exit -- notify all modules that we are exiting
 *  Get the master list of MAPI callbacks for the shut down phase,
 *  call them, and clean up user sessions
 *
 */
void jabber_transport_exit()
{
    mmaster m; /* MAPI master callback list */

    /* get the call back list for the the shutdown phase */
    m = js_mapi_master(P_SHUTDOWN);

    /* call all the shutdown functions */
    js_mapi_call(P_SHUTDOWN, m->l, NULL, NULL, NULL, 0);

    /* close all user sessions */
    js_users_exit();

}
