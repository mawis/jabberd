/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/
// #define KARMA_DEBUG
#define KARMA_READ_MAX(k) (k*100) /* how much you are allowed to read off the sock */
#define KARMA_INIT -100   /* internal "init" value, should not be able to get here */
#define KARMA_HEARTBEAT 2 /* seconds to register for heartbeat */
#define KARMA_MAX 10     /* total max karma you can have */
#define KARMA_INC 1      /* how much to increment every KARMA_HEARTBEAT seconds */
#define KARMA_DEC 1      /* how much to penalize for reading KARMA_READ_MAX in
                            KARMA_HEARTBEAT seconds */
#define KARMA_PENALTY -5 /* where you go when you hit 0 karma */
#define KARMA_RESTORE 5  /* where you go when you payed your penelty or INIT */

struct karma
{
    int val; /* current karma value */
    long bytes; /* total bytes read (in that time period) */
    int max;  /* max karma you can have */
    int inc,dec; /* how much to increment/decrement */
    int penalty,restore; /* what penalty (<0) or restore (>0) */
    time_t last_update; /* time this was last incremented */
};

void karma_copy(struct karma *new, struct karma *old); /* makes a copy of old in new */
void karma_increment(struct karma *k);          /* inteligently increments karma */
void karma_decrement(struct karma *k);          /* inteligently decrements karma */
int karma_check(struct karma *k,long bytes_read); /* checks to see if we have good karma */
