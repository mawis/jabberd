#include <jabberd.h>

void _mio_raw_parser(mio m, const void *buf, size_t bufsz)
{
    (*(mio_raw_cb)m->cb)(m, MIO_BUFFER, m->cb_arg, (char*)buf, bufsz);
}
