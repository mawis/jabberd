#include <libxode.h>

/* DUDE, this is a PROTOTYPE playground, go away :) */

int main(void)
{
    int socks[2];
    int n;
    char buff[1024];
    struct in_addr *in;
    int i=0;
    struct hostent *hp;

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

    while(1)
    {
        printf("child waiting\n");
        n = read(socks[0],buff,1023);
        if(n < 0)
        {
            printf("child died %s\n",strerror(errno));
            exit(1);
        }

        buff[n] = '\0';

        printf("child read %s\n",buff);

       /* hp = gethostbyname(buff); 
        printf("resolved ip %s\n",inet_ntoa((struct in_addr)**(hp->h_addr_list))); */

        in = make_addr(buff);
        printf("resolved ip %s\n",inet_ntoa(*in));

        usleep(1000);
    }

}