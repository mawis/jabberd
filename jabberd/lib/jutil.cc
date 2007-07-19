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
 * @file jutil.cc
 * @brief various utilities mainly for handling xmlnodes containing stanzas
 */

#include <jabberdlib.h>

/**
 * utility for making presence stanzas
 *
 * @param type the type of the presence (one of the JPACKET__* contants)
 * @param to to whom the presence should be sent, NULL for a broadcast presence
 * @param status optional status (CDATA for the &lt;status/&gt; element, NULL for no &lt;status/&gt; element)
 * @return the xmlnode containing the created presence stanza
 */
xmlnode jutil_presnew(int type, const char *to, const char *status) {
    xmlnode pres;

    pres = xmlnode_new_tag_ns("presence", NULL, NS_SERVER);
    switch(type) {
	case JPACKET__SUBSCRIBE:
	    xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "subscribe");
	    break;
	case JPACKET__UNSUBSCRIBE:
	    xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "unsubscribe");
	    break;
	case JPACKET__SUBSCRIBED:
	    xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "subscribed");
	    break;
	case JPACKET__UNSUBSCRIBED:
	    xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "unsubscribed");
	    break;
	case JPACKET__PROBE:
	    xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "probe");
	    break;
	case JPACKET__UNAVAILABLE:
	    xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "unavailable");
	    break;
	case JPACKET__INVISIBLE:
	    xmlnode_put_attrib_ns(pres, "type", NULL, NULL, "invisible");
	    break;
    }
    if (to != NULL)
        xmlnode_put_attrib_ns(pres, "to", NULL, NULL, to);
    if (status != NULL)
        xmlnode_insert_cdata(xmlnode_insert_tag_ns(pres, "status", NULL, NS_SERVER), status, j_strlen(status));

    return pres;
}

/**
 * utility for making IQ stanzas, that contain a &lt;query/&gt; element in a different namespace
 *
 * @note In traditional Jabber protocols the element inside an iq element has the name "query".
 * This util is not able to create IQ stanzas that contain a query which a element that does
 * not have the name "query"
 *
 * @param type the type of the iq stanza (one of JPACKET__GET, JPACKET__SET, JPACKET__RESULT, JPACKET__ERROR)
 * @param ns the namespace of the &lt;query/&gt; element
 * @return the created xmlnode
 */
xmlnode jutil_iqnew(int type, const char *ns) {
    xmlnode iq;

    iq = xmlnode_new_tag_ns("iq", NULL, NS_SERVER);
    switch(type) {
	case JPACKET__GET:
	    xmlnode_put_attrib_ns(iq, "type", NULL, NULL, "get");
	    break;
	case JPACKET__SET:
	    xmlnode_put_attrib_ns(iq, "type", NULL, NULL, "set");
	    break;
	case JPACKET__RESULT:
	    xmlnode_put_attrib_ns(iq, "type", NULL, NULL, "result");
	    break;
	case JPACKET__ERROR:
	    xmlnode_put_attrib_ns(iq, "type", NULL, NULL, "error");
	    break;
    }
    if (ns != NULL)
	xmlnode_insert_tag_ns(iq, "query", NULL, ns);

    return iq;
}

/**
 * utility for making message stanzas
 *
 * @param type the type of the message (as a string!)
 * @param to the recipient of the message
 * @param subj the subject of the message (NULL for no subject element)
 * @param body the body of the message
 * @return the xmlnode containing the new message stanza
 */
xmlnode jutil_msgnew(const char *type, const char *to, const char *subj, const char *body) {
    xmlnode msg;

    msg = xmlnode_new_tag_ns("message", NULL, NS_SERVER);

    if (type != NULL) {
	xmlnode_put_attrib_ns(msg, "type", NULL, NULL, type);
    }

    if (to != NULL) {
	xmlnode_put_attrib_ns(msg, "to", NULL, NULL, to);
    }

    if (subj != NULL) {
	xmlnode_insert_cdata(xmlnode_insert_tag_ns(msg, "subject", NULL, NS_SERVER), subj, j_strlen(subj));
    }

    if (body != NULL) {
	xmlnode_insert_cdata(xmlnode_insert_tag_ns(msg, "body", NULL, NS_SERVER), body, j_strlen(body));
    }

    return msg;
}

/**
 * returns the priority on an available presence packet
 *
 * @param x the xmlnode containing the presence packet
 * @return the presence priority, -129 for unavailable presences and errors
 */
int jutil_priority(xmlnode x) {
    char *str;
    int p;
    xht namespaces = NULL;

    if(x == NULL)
        return -129;

    if(xmlnode_get_attrib_ns(x,"type", NULL) != NULL)
        return -129;

    pool temp_pool = pool_new();
    namespaces = xhash_new(3);
    xhash_put(namespaces, "", const_cast<char*>(NS_SERVER));
    x = xmlnode_get_list_item(xmlnode_get_tags(x, "priority", namespaces, temp_pool), 0);
    xhash_free(namespaces);
    if(x == NULL) {
	pool_free(temp_pool);
        return 0;
    }

    str = xmlnode_get_data((x));
    if(str == NULL) {
	pool_free(temp_pool);
        return 0;
    }

    p = atoi(str);
    pool_free(temp_pool);

    /* xmpp-im section 2.2.2.3 */
    return p<-128 ? -128 : p>127 ? 127 : p;
}

/**
 * reverse sender and destination of a packet
 *
 * @param x the xmlnode where sender and receiver should be exchanged
 */
void jutil_tofrom(xmlnode x) {
    char *to, *from;

    to = xmlnode_get_attrib_ns(x, "to", NULL);
    from = xmlnode_get_attrib_ns(x,"from", NULL);
    xmlnode_put_attrib_ns(x, "from", NULL, NULL, to);
    xmlnode_put_attrib_ns(x, "to", NULL, NULL, from);
}

/**
 * change and xmlnode to be the result xmlnode for the original iq query
 *
 * @param x the xmlnode that should become the result for itself
 * @return the result xmlnode (same as given as parameter x)
 */
xmlnode jutil_iqresult(xmlnode x) {
    xmlnode cur;

    jutil_tofrom(x);

    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "result");

    /* hide all children of the iq, they go back empty */
    for(cur = xmlnode_get_firstchild(x); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        xmlnode_hide(cur);

    return x;
}

/**
 * get the present time as a textual timestamp in the format YYYYMMDDTHH:MM:SS
 *
 * @note this function is not thread safe
 *
 * @return pointer to a static (!) buffer containing the timestamp (or NULL on failure)
 */
char *jutil_timestamp(void) {
    time_t t;
    struct tm *new_time;
    static char timestamp[18];
    int ret;

    t = time(NULL);

    if(t == (time_t)-1)
        return NULL;
    new_time = gmtime(&t);

    ret = snprintf(timestamp, sizeof(timestamp), "%d%02d%02dT%02d:%02d:%02d", 1900+new_time->tm_year,
                   new_time->tm_mon+1, new_time->tm_mday, new_time->tm_hour,
                   new_time->tm_min, new_time->tm_sec);

    if(ret == -1)
        return NULL;

    return timestamp;
}

/**
 * get the present time as a textual timestamp in the format YYYY-MM-DDTHH:MM:SS.MMMZ
 *
 * @param buffer place where the timestamp should be written
 * @return pointer to the buffer
 */
char *jutil_timestamp_ms(char buffer[25]) {
    struct timeval tv;
    time_t secpart_of_tv;
    struct timezone tz;
    struct tm *new_time = NULL;

    gettimeofday(&tv, &tz);
    secpart_of_tv = static_cast<time_t>(tv.tv_sec);
    new_time = gmtime(&secpart_of_tv);
    snprintf(buffer, sizeof(char[25]), "%d-%02d-%02dT%02d:%02d:%02d.%03dZ", 1900+new_time->tm_year,
	     new_time->tm_mon+1, new_time->tm_mday, new_time->tm_hour,
	     new_time->tm_min, new_time->tm_sec, tv.tv_usec/1000);
    
    return buffer;
}

/**
 * map a terror structure to a xterror structure
 *
 * terror structures have been used in jabberd14 up to version 1.4.3 but
 * are not able to hold XMPP compliant stanza errors. The xterror
 * structure has been introduced to be XMPP compliant. This function
 * is to ease writting wrappers that accept terror structures and call
 * the real functions that require now xterror structures
 *
 * @param old the terror struct that should be converted
 * @param mapped pointer to the xterror struct that should be filled with the converted error
 */
void jutil_error_map(terror old, xterror *mapped) {
    mapped->code = old.code;
    if (old.msg == NULL)
	mapped->msg[0] = 0;
    else
	strncpy(mapped->msg, old.msg, sizeof(mapped->msg));

    switch (old.code) {
	case 302:
	    strcpy(mapped->type, "modify");
	    strcpy(mapped->condition, "redirect");
	    break;
	case 400:
	    strcpy(mapped->type, "modify");
	    strcpy(mapped->condition, "bad-request");
	    break;
	case 401:
	    strcpy(mapped->type, "auth");
	    strcpy(mapped->condition, "not-authorized");
	    break;
	case 402:
	    strcpy(mapped->type, "auth");
	    strcpy(mapped->condition, "payment-required");
	    break;
	case 403:
	    strcpy(mapped->type, "auth");
	    strcpy(mapped->condition, "forbidden");
	    break;
	case 404:
	    strcpy(mapped->type, "cancel");
	    strcpy(mapped->condition, "item-not-found");
	    break;
	case 405:
	    strcpy(mapped->type, "cancel");
	    strcpy(mapped->condition, "not-allowed");
	    break;
	case 406:
	    strcpy(mapped->type, "modify");
	    strcpy(mapped->condition, "not-acceptable");
	    break;
	case 407:
	    strcpy(mapped->type, "auth");
	    strcpy(mapped->condition, "registration-requited");
	    break;
	case 408:
	    strcpy(mapped->type, "wait");
	    strcpy(mapped->condition, "remote-server-timeout");
	    break;
	case 409:
	    strcpy(mapped->type, "cancel");
	    strcpy(mapped->condition, "conflict");
	    break;
	case 500:
	    strcpy(mapped->type, "wait");
	    strcpy(mapped->condition, "internal-server-error");
	    break;
	case 501:
	    strcpy(mapped->type, "cancel");
	    strcpy(mapped->condition, "feature-not-implemented");
	    break;
	case 502:
	    strcpy(mapped->type, "wait");
	    strcpy(mapped->condition, "service-unavailable");
	    break;
	case 503:
	    strcpy(mapped->type, "cancel");
	    strcpy(mapped->condition, "service-unavailable");
	    break;
	case 504:
	    strcpy(mapped->type, "wait");
	    strcpy(mapped->condition, "remote-server-timeout");
	    break;
	case 510:
	    strcpy(mapped->type, "cancel");
	    strcpy(mapped->condition, "service-unavailable");
	    break;
	default:
	    strcpy(mapped->type, "wait");
	    strcpy(mapped->condition, "undefined-condition");
    }
}

/**
 * update an xmlnode to be the error stanza for itself
 *
 * @param x the xmlnode that should become an stanza error message
 * @param E the structure that holds the error information
 */
void jutil_error_xmpp(xmlnode x, xterror E)
{
    xmlnode err;
    char code[4];

    xmlnode_put_attrib_ns(x, "type", NULL, NULL, "error");
    err = xmlnode_insert_tag_ns(x, "error", NULL, NS_SERVER);

    snprintf(code, sizeof(code), "%d", E.code);
    xmlnode_put_attrib_ns(err, "code", NULL, NULL, code);
    if (E.type != NULL)
	xmlnode_put_attrib_ns(err, "type", NULL, NULL, E.type);
    if (E.condition != NULL)
	xmlnode_insert_tag_ns(err, E.condition, NULL, NS_XMPP_STANZAS);
    if (E.msg != NULL) {
	xmlnode text;
	text = xmlnode_insert_tag_ns(err, "text", NULL, NS_XMPP_STANZAS);
	xmlnode_insert_cdata(text, messages_get(xmlnode_get_lang(x), E.msg), -1);
    }

    jutil_tofrom(x);
}

/**
 * wrapper around jutil_error_xmpp for compatibility with modules for jabberd up to version 1.4.3
 *
 * @deprecated use jutil_error_xmpp instead!
 *
 * @param x the xmlnode that should become an stanza error message
 * @param E the strucutre that holds the error information
 */
void jutil_error(xmlnode x, terror E)
{
    xterror xE;
    jutil_error_map(E, &xE);
    jutil_error_xmpp(x, xE);
}

/**
 * add a delayed delivery (XEP-0091) element to a message using the
 * present timestamp.
 * If a reason is given, this reason will be added as CDATA to the
 * inserted element
 *
 * @param msg the message where the element should be added
 * @param reason plain text information why the delayed delivery information has been added
 */
void jutil_delay(xmlnode msg, const char *reason)
{
    xmlnode delay;

    delay = xmlnode_insert_tag_ns(msg, "x", NULL, NS_DELAY);
    xmlnode_put_attrib_ns(delay, "from", NULL, NULL, xmlnode_get_attrib_ns(msg, "to", NULL));
    xmlnode_put_attrib_ns(delay, "stamp", NULL, NULL, jutil_timestamp());
    if(reason != NULL)
        xmlnode_insert_cdata(delay, messages_get(xmlnode_get_lang(msg), reason), -1);
}

#define KEYBUF 100

/**
 * create or validate a key value for stone-age jabber protocols
 *
 * Before dialback had been introduced for s2s (and therefore only in jabberd 1.0),
 * Jabber used these keys to protect some iq requests. A client first had to
 * request a key with a IQ get and use it inside the IQ set request. By being able
 * to receive the key in the IQ get response, the client (more or less) proved to be
 * who he claimed to be.
 *
 * The implementation of this function uses a static array with KEYBUF entries (default
 * value of KEYBUF is 100). Therefore a key gets invalid at the 100th key that is created
 * afterwards. It is also invalidated after it has been validated once.
 *
 * @deprecated This function is not really used anymore. jabberd14 does not check any
 * keys anymore and only creates them in the jsm's mod_register.c for compatibility. This
 * function is also used in mod_groups.c and the key is even checked there, but I do not
 * know if mod_groups.c still works at all.
 *
 * @param key for validation the key the client sent, for generation of a new key NULL
 * @param seed the seed for generating the key, must stay the same for the same user
 * @return the new key when created, the key if the key has been validated, NULL if the key is invalid
 */
char *jutil_regkey(char *key, char *seed) {
    static char keydb[KEYBUF][41];
    static char seeddb[KEYBUF][41];
    static int last = -1;
    char *str, strint[32];
    int i;

    /* blanket the keydb first time */
    if (last == -1) {
        last = 0;
        memset(&keydb,0,KEYBUF*41);
        memset(&seeddb,0,KEYBUF*41);
        srand(time(NULL));
    }

    /* creation phase */
    if (key == NULL && seed != NULL) {
        /* create a random key hash and store it */
        snprintf(strint, sizeof(strint), "%d", rand());
        strcpy(keydb[last],shahash(strint));

        /* store a hash for the seed associated w/ this key */
        strcpy(seeddb[last],shahash(seed));

        /* return it all */
        str = keydb[last];
        last++;
        if (last == KEYBUF)
	    last = 0;
        return str;
    }

    /* validation phase */
    str = shahash(seed);
    for (i=0;i<KEYBUF;i++) {
        if (j_strcmp(keydb[i],key) == 0 && j_strcmp(seeddb[i],str) == 0) {
            seeddb[i][0] = '\0'; /* invalidate this key */
            return keydb[i];
        }
    }

    return NULL;
}
