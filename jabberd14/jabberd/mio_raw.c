#include <jabberd.h>

int _mio_std_read(mio m)
{
    int  maxlen, 
         len;
    char buff[8192]; /* max socket read */

    maxlen = KARMA_READ_MAX(m->k.val);

    if(maxlen > 8191) maxlen = 8191;

    len = MIO_READ_FUNC(m->fd, buff, maxlen);

    if(len == 0)
    {
        if(m->cb != NULL)
            (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb_arg);
        return -1;
    }

    if(len < 0)
    {
        if(errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN) 
            return 0;

        if(m->cb != NULL)
            (*(mio_std_cb)m->cb)(m, MIO_ERROR, m->cb_arg);
        return -1;
    }

    if(karma_check(&m->k, len))
    { /* they read the max, tsk tsk */
        if(m->k.val <= 0) /* ran out of karma */
        {
            log_notice("MIO_XML_READ", "socket from %s is out of karma", m->ip);
            return 0;
        }
    }

    buff[len] = '\0';
    
    if(m->cb != NULL)
        (*(mio_raw_cb)m->cb)(m, MIO_BUFFER, m->cb_arg, buff, len);

    return 0;
}
