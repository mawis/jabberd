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
 */

#include "jabberd.h"

int debug_flag = 0;
extern HASHTABLE debug__zones, cmd__line;

char *debug_log_timestamp(void)
{
    time_t t;
    int sz;
    char *tmp_str;

    t = time(NULL);

    if(t == (time_t)-1)
        return NULL;

    tmp_str = ctime(&t);
    sz = strlen(tmp_str);
    /* chop off the \n */
    tmp_str[sz-1]=' ';

    return tmp_str;
}

void debug_log(char *zone, const char *msgfmt, ...)
{
    va_list ap;
    char message[MAX_LOG_SIZE];
    char *pos, c;
    int offset;

    /* special per-zone filtering */
    if(zone != NULL && debug__zones != NULL)
    {
        pos = strchr(zone,'.');
        if(pos != NULL)
        {
            c = *pos;
            *pos = '\0'; /* chop */
        }
        if(ghash_get(debug__zones,zone) == NULL)
            return;
        if(pos != NULL)
            *pos = c; /* restore */
    }

    snprintf(message, MAX_LOG_SIZE, "%s %s ", debug_log_timestamp(), zone);
    for (pos = message; *pos != '\0'; pos++); //empty statement
     
    offset = pos - message;

    va_start(ap, msgfmt);
    vsnprintf(pos, MAX_LOG_SIZE - offset, msgfmt, ap);
    fprintf(stderr,"%s", message);
    fprintf(stderr, "\n");
}

void logger(char *type, char *host, char *message)
{
    xmlnode log;

    if(type == NULL || message == NULL)
    {
        fprintf(stderr, "Unrecoverable: logger function called with illegal arguments!\n");
        return;
    }

    log = xmlnode_new_tag("log");
    xmlnode_put_attrib(log,"type",type);
    if(host != NULL)
        xmlnode_put_attrib(log,"from",host);
    else
        xmlnode_put_attrib(log,"from","-internal");
    xmlnode_insert_cdata(log,message,strlen(message));

    log_debug(ZONE,"%s",xmlnode2str(log));
    deliver(dpacket_new(log), NULL);
}

void log_notice(char *host, const char *msgfmt, ...)
{
    va_list ap;
    char logmsg[512] = "";


    va_start(ap, msgfmt);
    vsnprintf(logmsg, 512, msgfmt, ap);

    logger("notice",host,logmsg);
}

void log_warn(char *host, const char *msgfmt, ...)
{
    va_list ap;
    char logmsg[512] = "";


    va_start(ap, msgfmt);
    vsnprintf(logmsg, 512, msgfmt, ap);

    logger("warn",host,logmsg);
}

void log_alert(char *host, const char *msgfmt, ...)
{
    va_list ap;
    char logmsg[512] = "";


    va_start(ap, msgfmt);
    vsnprintf(logmsg, 512, msgfmt, ap);

    logger("alert",host,logmsg);
}

