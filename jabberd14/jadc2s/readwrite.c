#include "jadc2s.h"

/* wrappers around read() and write(), with ssl support */
int _read_actual(conn_t c, int fd, char *buf, size_t count)
{
    if(c->ssl_flag)
        return SSL_read(c->ssl, buf, count);
    else
        return read(fd, buf, count);
}

int _write_actual(conn_t c, int fd, const char *buf, size_t count)
{
    if(c->ssl_flag)
        return SSL_write(c->ssl, buf, count);
    else
        return write(fd, buf, count);
}
