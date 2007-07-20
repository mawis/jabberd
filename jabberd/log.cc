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
 * @file log.cc
 * @brief functions used to generate log messages, and logging of debug messages
 *
 * Generated log messages are routed to a logging component using the XML router.
 * Generated debug log messages are not routed but either displayed to the
 * standard error output or sent to the syslog (Depending on the jabberd
 * configuration).
 */

#include "jabberd.h"

int _debug_facility = -1;	/**< facility to use for sending debugging messages to syslog - or -1 for not using syslog but stderr */
int debug_flag = 0;		/**< the active debugging mask (this is a bitmask of ORed LOGT_* constents) */
int cmdline_debug_flag = 0;	/**< the debug mask given at the command line - this is ORed with the mask given in the configuration file */

extern xht debug__zones;

/**
 * get the formated current time for use as a timestamp in logging messages
 *
 * The returned pointer points to statically allocated memory used by the date
 * and time functions of the C library. This memory might be overwritten by
 * subsequent calls to date and time functions of the C library.
 *
 * This function returns ctime(time(NULL)) with the '\n' at the end of the
 * result replaced by a space character.
 *
 * @return formated time stamp (NULL on error - should not happen)
 */
static char *debug_log_timestamp(void) {
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

/**
 * check if the specified debugging zone has been selected
 *
 * @param zone the zone where the logging message comes from
 * @return 1 if it should be logged, 0 if not
 */
static inline int _debug_log_zonefilter(char const* zone) {
    char *pos, c = '\0';
    if(zone != NULL && debug__zones != NULL)
    {
	pos = strchr(zone,'.');
        if(pos != NULL)
        {
            c = *pos;
            *pos = '\0'; /* chop */
        }
        if(xhash_get(debug__zones,zone) == NULL)
            return 0;
        if(pos != NULL)
            *pos = c; /* restore */
    }
    return 1;
}

/**
 * Generate a debug log message
 *
 * This generates a debugging message. The function should not be called
 * directly. Instead the macro ::log_debug should be called, which first
 * checks if debugging is enabled.
 *
 * Do not use this function or ::log_debug at all. Better use ::log_debug2.
 *
 * @param zone the zone (file) the function is called from. __ZONE__ should be used here.
 * @param msgfmt the format string for the log message, parameters like for printf() are given afterwards
 */
void debug_log(char const* zone, char const* msgfmt, ...) {
    va_list ap;
    char message[MAX_LOG_SIZE];
    int offset;
    char *pos;

    /* special per-zone filtering */
    if (!_debug_log_zonefilter(zone))
	return;

    /* only add timestamps if writing to standard output */
    if (_debug_facility == -1) {
	snprintf(message, sizeof(message), "%s %s ", debug_log_timestamp(), zone);
	for (pos = message; *pos != '\0'; pos++); /* empty statement */
     
	offset = pos - message;
    } else {
	pos = message;
	offset = 0;
    }

    va_start(ap, msgfmt);
    vsnprintf(pos, sizeof(message) - offset, msgfmt, ap);
#ifdef HAVE_SYSLOG
    if (_debug_facility == -1) {
	fprintf(stderr,"%s\n", message);
    } else {
	syslog(LOG_DEBUG|_debug_facility, "%s", message);
    }
#else
    syslog(LOG_DEBUG|_debug_facility, "%s", message);
#endif
}

/**
 * Generate a debug log message
 *
 * This generates a debugging message. The function should not be called
 * directly. Instead the macro ::log_debug2 should be called, which first
 * checks if debugging is enabled.
 *
 * @param zone the zone (file) the function is called from. __ZONE__ should be used here.
 * @param type LOGT_* constent telling which type of debug log message is passed
 * @param msgfmt the format string for the log message, parameters like for printf() are given afterwards
 */
void debug_log2(char const* zone, int type, char const* msgfmt, ...) {
    va_list ap;
    char message[MAX_LOG_SIZE];
    int offset;
    char *pos;

    /* debug type filtering */
    if (!(get_debug_flag()&type))
	return;

    /* special per-zone filtering */
    if (!_debug_log_zonefilter(zone))
	return;

    /* only add timestamps if writing to standard output */
    if (_debug_facility == -1) {
	snprintf(message, sizeof(message), "%s %s ", debug_log_timestamp(), zone);
	for (pos = message; *pos != '\0'; pos++); /* empty statement */
     
	offset = pos - message;
    } else {
	pos = message;
	offset = 0;
    }

    va_start(ap, msgfmt);
    vsnprintf(pos, sizeof(message) - offset, msgfmt, ap);
#ifdef HAVE_SYSLOG
    if (_debug_facility == -1) {
	fprintf(stderr,"%s\n", message);
    } else {
	syslog(LOG_DEBUG|_debug_facility, "%s", message);
    }
#else
    syslog(LOG_DEBUG|_debug_facility, "%s", message);
#endif
}

/**
 * send a log message to the logging components
 *
 * @param type the type of log message (one of "notice"+/"record", "warn"+, "alert", "stat"+, "info", "emerg", "crit", or "err"+ - in jabberd only the marked ones are used - "debug" should not be used as debugging messages should not be routed on the XML router)
 * @param host the sending host (domain) of the message, or NULL if no sending host is known (the message are than logged as jabberd internal)
 * @param message The message to be logged
 */
void logger(char const* type, char const* host, char const* message) {
    xmlnode log;

    if (type == NULL || message == NULL) {
        fprintf(stderr, "Unrecoverable: logger function called with illegal arguments!\n");
        return;
    }

    log = xmlnode_new_tag_ns("log", NULL, NS_SERVER);
    xmlnode_put_attrib_ns(log, "type", NULL, NULL, type);
    if (host != NULL)
        xmlnode_put_attrib_ns(log, "from", NULL, NULL, host);
    else
        xmlnode_put_attrib_ns(log, "from", NULL, NULL, "-internal");
    xmlnode_insert_cdata(log, message, j_strlen(message));

    log_debug2(ZONE, LOGT_DELIVER, "%s", xmlnode_serialize_string(log, xmppd::ns_decl_list(), 0));
    deliver(dpacket_new(log), NULL);
}

/**
 * generate a log message of type "notice"
 *
 * @param host the sending host (domain) of the log message - NULL if the host is not known, in that case the message is logged as jabberd internal
 * @param msgfmt the format string for the message, parameters are passed afterwards like for the printf() function
 */
void log_notice(char const* host, char const* msgfmt, ...) {
    va_list ap;
    char logmsg[512] = "";


    va_start(ap, msgfmt);
    vsnprintf(logmsg, sizeof(logmsg), msgfmt, ap);

    logger("notice",host,logmsg);
}

/**
 * generate a log message of type "warn"
 *
 * @param host the sending host (domain) of the log message - NULL if the host is not known, in that case the message is logged as jabberd internal
 * @param msgfmt the format string for the message, parameters are passed afterwards like for the printf() function
 */
void log_warn(char const* host, char const* msgfmt, ...) {
    va_list ap;
    char logmsg[512] = "";


    va_start(ap, msgfmt);
    vsnprintf(logmsg, sizeof(logmsg), msgfmt, ap);

    logger("warn",host,logmsg);
}

/**
 * generate a log message of type "alert"
 *
 * @param host the sending host (domain) of the log message - NULL if the host is not known, in that case the message is logged as jabberd internal
 * @param msgfmt the format string for the message, parameters are passed afterwards like for the printf() function
 */
void log_alert(char const* host, char const* msgfmt, ...) {
    va_list ap;
    char logmsg[512] = "";


    va_start(ap, msgfmt);
    vsnprintf(logmsg, sizeof(logmsg), msgfmt, ap);

    logger("alert",host,logmsg);
}

/**
 * writing log messages of arbitrary logging type
 *
 * @param logtype logging type (e.g. "record")
 * @param id to which id is the message related
 * @param type type of the log message (e.g. "session")
 * @param action action that is logged (e.g. a failed auth)
 * @param msgfmt printf()-like format string, parameters are following
 */
void log_generic(char const* logtype, char const* id, char const* type, char const* action, char const* msgfmt, ...) {
    va_list ap;
    char logmsg[512] = "";
    xmlnode log;

    /* sanity check */
    if (logtype == NULL) {
	return;
    }

    va_start(ap, msgfmt);
    vsnprintf(logmsg, sizeof(logmsg), msgfmt, ap);

    log = xmlnode_new_tag_ns("log", NULL, NS_SERVER);
    xmlnode_put_attrib_ns(log, "type", NULL, NULL, logtype);
    if(id != NULL)
        xmlnode_put_attrib_ns(log, "from", NULL, NULL, id);
    else
        xmlnode_put_attrib_ns(log, "from", NULL, NULL, "-internal");

    /* make log record like "type action rest-of-data" */
    if(type != NULL)
        xmlnode_insert_cdata(log, type, j_strlen(type));
    else
        xmlnode_insert_cdata(log, "unknown", 7);
    xmlnode_insert_cdata(log, " ", 1);
    if(action != NULL)
        xmlnode_insert_cdata(log, action, j_strlen(action));
    else
        xmlnode_insert_cdata(log, "unknown", 7);
    xmlnode_insert_cdata(log, " ", 1);
    xmlnode_insert_cdata(log, logmsg, j_strlen(logmsg));

    log_debug2(ZONE, LOGT_DELIVER, "%s", xmlnode_serialize_string(log, xmppd::ns_decl_list(), 0));
    deliver(dpacket_new(log), NULL);
}

/**
 * generic log record support
 *
 * @param id to which id is the message related
 * @param type the type of the log message (e.g. "session")
 * @param action action that is logged (e.g. a failed auth)
 * @param msgfmt printf()-like format string, parameters are following
 */
void log_record(char const* id, char const* type, char const* action, char const* msgfmt, ...) {
    va_list ap;
    char logmsg[512] = "";

    va_start(ap, msgfmt);
    vsnprintf(logmsg, sizeof(logmsg), msgfmt, ap);

    log_generic("record", id, type, action, "%s", logmsg);
}

/**
 * get the current debugging mask
 */
inline int get_debug_flag() {
    return debug_flag;
}

/**
 * set the debugging mask, if 0 no debugging is requested
 * for other values debugging is enabled, the different bits in the value enable different log message types
 * the value set with set_cmdline_debug_flag() (what the user specified on the command line) is always ORed to this value
 *
 * @param v the new debugging mask
 */
void set_debug_flag(int v) {
    debug_flag = v|cmdline_debug_flag;
}

/**
 * set the value of the cmdline_debug_flag which is always ORed to the value that is set by set_debug_flag()
 * this will reset the mask set with set_debug_flag(), so set_cmdline_debug_flag() should be called first.
 *
 * @param v the debug mask given on the command line
 */
void set_cmdline_debug_flag(int v) {
    debug_flag = cmdline_debug_flag = v;
}

/**
 * set the facility used to write debugging messages to syslog
 *
 * @param facility the facility to use, -1 if writing to the standard output is requested
 */
void set_debug_facility(int facility) {
#ifdef HAVE_SYSLOG
    _debug_facility = facility;
#else
    if (facility != -1) {
	log_warn(NULL, PACKAGE " configured to debug to syslog, but compiled without syslog support");
    }
#endif
}

/**
 * get the level value for a syslog level
 *
 * @param level as a string
 * @return numerical level value or -1 on error
 */
int log_get_level(const char *level) {
    /* XXX is there any portable way other than this? */
#ifdef LOG_NOTICE
    if (j_strcmp(level, "notice") == 0 || j_strcmp(level, "record") == 0)
	return LOG_NOTICE;
#endif
#ifdef LOG_WARN
    if (j_strcmp(level, "warn") == 0)
	return LOG_WARN;
#endif
#ifdef LOG_ALERT
    if (j_strcmp(level, "alert") == 0)
	return LOG_ALERT;
#endif
#ifdef LOG_INFO
    if (j_strcmp(level, "stat") == 0 || j_strcmp(level, "info") == 0)
	return LOG_INFO;
#endif
#ifdef LOG_EMERG
    if (j_strcmp(level, "emerg") == 0)
	return LOG_EMERG;
#endif
#ifdef LOG_CRIT
    if (j_strcmp(level, "crit") == 0)
	return LOG_CRIT;
#endif
#ifdef LOG_ERR
    if (j_strcmp(level, "err") == 0)
	return LOG_ERR;
#endif
#ifdef LOG_DEBUG
    if (j_strcmp(level, "debug") == 0)
	return LOG_DEBUG;
#endif
    return -1;
}

/**
 * get the facility value for a syslog facility
 *
 * @param facility as a string
 * @return numerical facility value or -1 on error
 */
int log_get_facility(const char *facility) {
    /* XXX is there any portable way other than this? */
#ifdef LOG_DAEMON
    if (j_strcmp(facility, "daemon") == 0)
	return LOG_DAEMON;
#endif
#ifdef LOG_LOCAL0
    if (j_strcmp(facility, "local0") == 0)
	return LOG_LOCAL0;
#endif
#ifdef LOG_LOCAL1
    if (j_strcmp(facility, "local1") == 0)
	return LOG_LOCAL1;
#endif
#ifdef LOG_LOCAL2
    if (j_strcmp(facility, "local2") == 0)
	return LOG_LOCAL2;
#endif
#ifdef LOG_LOCAL3
    if (j_strcmp(facility, "local3") == 0)
	return LOG_LOCAL3;
#endif
#ifdef LOG_LOCAL4
    if (j_strcmp(facility, "local4") == 0)
	return LOG_LOCAL4;
#endif
#ifdef LOG_LOCAL5
    if (j_strcmp(facility, "local5") == 0)
	return LOG_LOCAL5;
#endif
#ifdef LOG_LOCAL6
    if (j_strcmp(facility, "local6") == 0)
	return LOG_LOCAL6;
#endif
#ifdef LOG_LOCAL7
    if (j_strcmp(facility, "local7") == 0)
	return LOG_LOCAL7;
#endif
#ifdef LOG_AUTH
    if (j_strcmp(facility, "auth") == 0)
	return LOG_AUTH;
#endif
#ifdef LOG_AUTHPRIV
    if (j_strcmp(facility, "authpriv") == 0)
	return LOG_AUTHPRIV;
#endif
#ifdef LOG_CRON
    if (j_strcmp(facility, "cron") == 0)
	return LOG_CRON;
#endif
#ifdef LOG_KERN
    if (j_strcmp(facility, "kern") == 0)
	return LOG_KERN;
#endif
#ifdef LOG_LPR
    if (j_strcmp(facility, "lpr") == 0)
	return LOG_LPR;
#endif
#ifdef LOG_MAIL
    if (j_strcmp(facility, "mail") == 0)
	return LOG_MAIL;
#endif
#ifdef LOG_NEWS
    if (j_strcmp(facility, "news") == 0)
	return LOG_NEWS;
#endif
#ifdef LOG_SYSLOG
    if (j_strcmp(facility, "syslog") == 0)
	return LOG_SYSLOG;
#endif
#ifdef LOG_USER
    if (j_strcmp(facility, "user") == 0)
	return LOG_USER;
#endif
#ifdef LOG_UUCP
    if (j_strcmp(facility, "uucp") == 0)
	return LOG_UUCP;
#endif
    return -1;
}
