#include "mio.h"

int actor(mio_t m, mio_action_t a, int fd, void *data, void *arg)
{
    char buf[1024];

    switch(a)
    {
    case action_ACCEPT:
        printf("accepting %d\n",fd);
        mio_read(m, fd); /* get read events */
        break;
    case action_READ:
        printf("reading from %d\n",fd);
        if(read(fd,buf,1024) > 0)
            mio_write(m, fd);
        else
            mio_close(m, fd);
        return 1; /* get more read events */
        break;
    case action_WRITE:
        printf("writing to %d\n",fd);
        write(fd,"GET / HTTP/1.0\r\n\r\n",18);
        return 0; /* no more write events please */
        break;
    case action_CLOSE:
        printf("closing %d\n",fd);
        break;
    }
    return 0;
}

int main()
{
    mio_t m;
    int jo;

    m = mio_new(30);
    mio_fd(m,0,actor,NULL);
    mio_listen(m,5555,NULL,actor,NULL);
    if((jo = mio_connect(m,80,"208.245.212.108",actor,NULL)) > 0)
    {
        printf("connected to j.o on %d\n",jo);
        mio_write(m,jo);
        mio_read(m,jo);
    }else{
        printf("failed to connect to j.o: %s\n",strerror(errno));
    }
    while(1) mio_run(m,30000);
    mio_free(m);
}
