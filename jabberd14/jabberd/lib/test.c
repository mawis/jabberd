#include "lib.h"

void _xstream_callback(int type, xmlnode x, void *arg)
{
    printf("_xstream_callback(%d, %X, %X) fired\n", type, x, arg);

    if(type == 1)
        printf("FULL XMLNODE: %s", xmlnode2str(x));
}

int main(void)
{
    pool p = pool_new();
    xstream xs = xstream_new(p, _xstream_callback, NULL);

    xstream_eat(xs, "<header><tag1><tag2><tag", 24);
    xstream_eat(xs, "3><tag4><tag5>cdata</tag", 24);
    xstream_eat(xs, "5></tag4></tag3></tag2><", 24);
    xstream_eat(xs, "/tag1></header>         ", 24);
    pool_free(p);
    return 0;
}
