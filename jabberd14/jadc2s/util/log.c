#include "util.h"

#ifdef USE_SYSLOG
log_t log_new(char *ident)
{
    openlog(ident, LOG_PID, LOG_LOCAL7);

    return NULL;
}

void log_write(log_t l, int level, const char *msgfmt, ...)
{
    va_list ap;

    va_start(ap, msgfmt);
    vsyslog(level, msgfmt, ap);
    va_end(ap);
}

void log_free(log_t l)
{
    closelog();
}
#else
log_t log_new(char *ident)
{
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

static const char *log_level[] =
{
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug"
};

void log_write(log_t l, int level, const char *msgfmt, ...)
{
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
    for (pos = message; *pos != '\0'; pos++); //empty statement
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

void log_free(log_t l)
{
    FILE *f = (FILE *) l;

    if(f != stdout)
        fclose(f);
}
#endif

#ifdef USE_SSL
void log_ssl_errors(log_t l, int level)
{
    unsigned long sslerr;

    while ((sslerr = ERR_get_error()) != 0)
	log_write(l, level, "ssl: %s", ERR_error_string(sslerr, NULL));
}
#endif
