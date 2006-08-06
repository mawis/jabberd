/**
 * @file log.c
 * @brief handling of logging
 *
 * In this file the functions needed to log messages are contained.
 * Logging is possible to either syslog or files, depending on how the source has been configured
 */

#include "util.h"

#ifdef USE_SYSLOG
/**
 * create a new logging instance
 *
 * @note only one logging instance can be created when using syslog, so you should only open one instance
 *
 * @param ident the identity to log as
 * @return the logging instance
 */
log_t log_new(const char *ident) {
    openlog(ident, LOG_PID, USE_SYSLOG);

    return NULL;
}

/**
 * write a logging message
 *
 * @param l the logging instance to write to
 * @param level the severity level for the message
 * @param msgfmt printf like string what to write
 */
void log_write(log_t l, int level, const char *msgfmt, ...) {
    va_list ap;

    va_start(ap, msgfmt);
    vsyslog(level, msgfmt, ap);
    va_end(ap);
}

/**
 * free a logging instance
 */
void log_free(log_t l) {
    closelog();
}
#else
log_t log_new(const char *ident) {
    FILE *f;
    char *buf;

    if (ident == NULL) {
	buf = strdup("logfile.log");
    } else {
	buf = (char *)malloc(strlen(ident)+5);
	strcpy(buf,ident);
	strcat(buf, ".log");
    }

    f = fopen(buf, "a+");
    free(buf);
    if(f == NULL) {
        fprintf(stderr,
            "couldn't open %s for append: %s\n"
            "logging will go to stdout instead\n", buf, strerror(errno));
        f = stdout;
    }

    return (void *) f;
}

static const char *log_level[] = {
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug"
};

void log_write(log_t l, int level, const char *msgfmt, ...) {
    FILE *f = (FILE *) l;
    va_list ap;
    char *pos, message[MAX_LOG_LINE];
    int sz;
    time_t t;

    /* timestamp */
    t = time(NULL);
    pos = ctime(&t);
    sz = strlen(pos);
    /* chop off the \n */
    pos[sz-1]=' ';

    /* insert the header */
    snprintf(message, MAX_LOG_LINE, "%s[%s] ", pos, log_level[level]);

    /* find the end and attach the rest of the msg */
    for (pos = message; *pos != '\0'; pos++)
	/* nothing */;
    sz = pos - message;
    va_start(ap, msgfmt);
    vsnprintf(pos, MAX_LOG_LINE - sz, msgfmt, ap);
    fprintf(f,"%s", message);
    fprintf(f, "\n");

#ifdef DEBUG
    /* If we are in debug mode we want everything copied to the stdout */
    if (level != LOG_DEBUG)
        fprintf(stdout, "%s\n", message);
#endif /*DEBUG*/
}

void log_free(log_t l) {
    FILE *f = (FILE *) l;

    if(f != stdout)
        fclose(f);
}
#endif

#ifdef USE_SSL
/**
 * log all pending OpenSSL error message
 *
 * @param l the logging instance to log to
 * @param level the error level to log the messages as
 */
void log_ssl_errors(log_t l, int level) {
    unsigned long sslerr;

    while ((sslerr = ERR_get_error()) != 0)
	log_write(l, level, "ssl: %s", ERR_error_string(sslerr, NULL));
}
#endif
