#include <libxode.h>

/* DUDE, this is a PROTOTYPE playground, go away :) */

/* resolve an address and send the result to the parent */
void dnsrv_worker_resolve(char *addr, int parent)
{
    struct in_addr *in;

 /* struct hostent *hp;
    hp = gethostbyname(buff); 
    printf("resolved ip %s\n",inet_ntoa((struct in_addr)**(hp->h_addr_list))); */

    printf("resolving name %s\n",addr);
    in = make_addr(addr);
    printf("resolved ip %s\n",inet_ntoa(*in));

}

/* simple xstream callback, we only care about data in the nodes */
void dnsrv_worker_stream(int type, xmlnode x, void *arg)
{

    if(type == XSTREAM_NODE)
        dnsrv_worker_resolve(xmlnode_get_data(x),(int)arg);

    xmlnode_free(x);
}

void dnsrv_worker_main(int io[2])
{
    pool p = pool_new();
    xstream xs;

    xs = xstream_new(p, dnsrv_worker_resolve, (void *)io[1]);
    while(1)
    {
        printf("child waiting\n");
        n = read(socks[0],buff,1023);
        if(n < 0)
        {
            printf("child died %s\n",strerror(errno));
            break;
        }

        buff[n] = '\0';
        printf("child read %s\n",buff);
        xstream_eat(xs,buff,n);
    }

    pool_free(p);
}


/* xstream callback, resolved ip's being returned */
void dnsrv_parent_stream(int type, xmlnode x, void *arg)
{

    if(type == XSTREAM_NODE)
    {
        printf("parent got node %s\n",xmlnode2str(x));
    }

    xmlnode_free(x);
}

void dnsrv_parent_main(int io[2])
{
    pool p = pool_new();
    xstream xs;

    xs = xstream_new(p, dnsrv_worker_resolve, (void *)io[1]);
    while(1)
    {
        printf("parent waiting\n");
        n = read(socks[0],buff,1023);
        if(n < 0)
        {
            printf("child died %s\n",strerror(errno));
            break;
        }

        buff[n] = '\0';
        printf("child read %s\n",buff);
        xstream_eat(xs,buff,n);
    }

    pool_free(p);
}

int main(void)
{
    int io_child[2];
    int io_parent[2];
    int io_pass[2];
    int n;
    char buff[1024];
    int i=0;

    printf("starting\n");

    n = pipe(socks);

    printf("%d got server %d client %d\n",n,socks[0],socks[1]);

    if(fork())
    {
        while(1)
        {
            usleep(1000);
            printf("parent writing\n");
            write(socks[1],"foobar",6);
            if(n < 0)
            {
                printf("parent died %s\n",strerror(errno));
                exit(1);
            }
        }
    }


}