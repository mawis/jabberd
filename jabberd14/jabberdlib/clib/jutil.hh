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

#ifndef __JUTIL_HH
#define __JUTIL_HH

#include <xmlnode.hh>

#ifndef N_
#define N_(n) (n)
#endif

typedef struct xterror_struct {
    int code;
    char msg[256];
    char type[9];
    char condition[64];
} xterror;

xmlnode
jutil_presnew(int type, char const *to,
              const char *status); /* Create a skeleton presence packet */
xmlnode jutil_iqnew(int type, char const *ns); /* Create a skeleton iq packet */
xmlnode jutil_msgnew(char const *type, char const *to, char const *subj,
                     char const *body);
/* Create a skeleton message packet */
int jutil_priority(xmlnode x); /* Determine priority of this packet */
void jutil_tofrom(xmlnode x);  /* Swaps to/from fields on a packet */
xmlnode
jutil_iqresult(xmlnode x); /* Generate a skeleton iq/result, given a iq/query */
char *jutil_timestamp(void); /* Get stringified timestamp */
char *jutil_timestamp_ms(
    char *buffer); /* Get stringified timestamp including milliseconds */
void jutil_error_xmpp(
    xmlnode x, xterror E); /* Append an <error> node to x using XMPP syntax */
void jutil_delay(xmlnode msg,
                 char const *reason); /* Append a delay packet to msg */
char *jutil_regkey(char *key,
                   char *seed); /* pass a seed to generate a key, pass the key
                                   again to validate (returns it) */

#define XTERROR_BAD                                                            \
    (xterror) { 400, N_("Bad Request"), "modify", "bad-request" }
#define XTERROR_CONFLICT                                                       \
    (xterror) { 409, N_("Conflict"), "cancel", "conflict" }
#define XTERROR_NOTIMPL                                                        \
    (xterror) {                                                                \
        501, N_("Not Implemented"), "cancel", "feature-not-implemented"        \
    }
#define XTERROR_FORBIDDEN                                                      \
    (xterror) { 403, N_("Forbidden"), "auth", "forbidden" }
#define XTERROR_GONE                                                           \
    (xterror) { 302, N_("Gone"), "modify", "gone" }
#define XTERROR_INTERNAL                                                       \
    (xterror) {                                                                \
        500, N_("Internal Server Error"), "wait", "internal-server-error"      \
    }
#define XTERROR_NOTFOUND                                                       \
    (xterror) { 404, N_("Not Found"), "cancel", "item-not-found" }
#define XTERROR_JIDMALFORMED                                                   \
    (xterror) { 400, N_("Bad Request"), "modify", "jid-malformed" }
#define XTERROR_NOTACCEPTABLE                                                  \
    (xterror) { 406, N_("Not Acceptable"), "modify", "not-acceptable" }
#define XTERROR_NOTALLOWED                                                     \
    (xterror) { 405, N_("Not Allowed"), "cancel", "not-allowed" }
#define XTERROR_AUTH                                                           \
    (xterror) { 401, N_("Unauthorized"), "auth", "not-authorized" }
#define XTERROR_PAY                                                            \
    (xterror) { 402, N_("Payment Required"), "auth", "payment-required" }
#define XTERROR_RECIPIENTUNAVAIL                                               \
    (xterror) {                                                                \
        404, N_("Recipient Is Unavailable"), "wait", "recipient-unavailable"   \
    }
#define XTERROR_REDIRECT                                                       \
    (xterror) { 302, N_("Redirect"), "modify", "redirect" }
#define XTERROR_REGISTER                                                       \
    (xterror) {                                                                \
        407, N_("Registration Required"), "auth", "registration-required"      \
    }
#define XTERROR_REMOTENOTFOUND                                                 \
    (xterror) {                                                                \
        404, N_("Remote Server Not Found"), "cancel",                          \
            "remote-server-not-found"                                          \
    }
#define XTERROR_REMOTETIMEOUT                                                  \
    (xterror) {                                                                \
        504, N_("Remote Server Timeout"), "wait", "remote-server-timeout"      \
    }
#define XTERROR_RESCONSTRAINT                                                  \
    (xterror) { 500, N_("Resource Constraint"), "wait", "resource-constraint" }
#define XTERROR_UNAVAIL                                                        \
    (xterror) {                                                                \
        503, N_("Service Unavailable"), "cancel", "service-unavailable"        \
    }
#define XTERROR_SUBSCRIPTIONREQ                                                \
    (xterror) {                                                                \
        407, N_("Subscription Required"), "auth", "subscription-required"      \
    }
#define XTERROR_UNDEF_CANCEL                                                   \
    (xterror) { 500, NULL, "cancel", "undefined-condition" }
#define XTERROR_UNDEF_CONTINUE                                                 \
    (xterror) { 500, NULL, "continue", "undefined-condition" }
#define XTERROR_UNDEF_MODIFY                                                   \
    (xterror) { 500, NULL, "modify", "undefined-condition" }
#define XTERROR_UNDEF_AUTH                                                     \
    (xterror) { 500, NULL, "auth", "undefined-condition" }
#define XTERROR_UNDEF_WAIT                                                     \
    (xterror) { 500, NULL, "wait", "undefined-condition" }
#define XTERROR_UNEXPECTED                                                     \
    (xterror) { 400, N_("Unexpected Request"), "wait", "unexpected-request" }

#define XTERROR_REQTIMEOUT                                                     \
    (xterror) { 408, N_("Request Timeout"), "wait", "remote-server-timeout" }
#define XTERROR_EXTERNAL                                                       \
    (xterror) { 502, N_("Remote Server Error"), "wait", "service-unavailable" }
#define XTERROR_EXTTIMEOUT                                                     \
    (xterror) {                                                                \
        504, N_("Remote Server Timeout"), "wait", "remote-server-timeout"      \
    }
#define XTERROR_DISCONNECTED                                                   \
    (xterror) { 510, N_("Disconnected"), "cancel", "service-unavailable" }
#define XTERROR_STORAGE_FAILED                                                 \
    (xterror) { 500, N_("Storage Failed"), "wait", "internal-server-error" }

#endif // __JUTIL_HH
