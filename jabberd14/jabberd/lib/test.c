#include "lib.h"

long total__tags = 0;
long total__time = 0;
long total__parse_time = 0;
long total__chew_time = 0;
long total__serialize_time = 0;
long total__bytes = 0;
long total__pre_traverse_memory = 0;
long total__memory = 0;

void _traverse_node(xmlnode node)
{
    xmlnode cur = xmlnode_get_firstchild(node);
    
   
    for(;cur != NULL; cur = xmlnode_get_nextsibling(cur))
        _traverse_node(cur);
}

void _xstream_callback(int type, xmlnode x, void *arg)
{
        struct timeval tv;
        long temp;
        char *foo;

        if(type != XSTREAM_NODE) 
        {
                if(type == XSTREAM_ERR)
                {
                    printf("ERROR: %s", xmlnode_get_data(x));
                }
                return;
        }
        total__tags++;

        total__pre_traverse_memory += (xmlnode_pool(x))->size;

        /* see how fast we can serialize nodes */
        gettimeofday(&tv, NULL);
        temp = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
        foo = xmlnode2str(x);
        gettimeofday(&tv, NULL);
        temp = (tv.tv_sec * 1000) + (tv.tv_usec / 1000) - temp;
        total__serialize_time += temp;
        
        /* see how fast we can traverse all nodes */
        gettimeofday(&tv, NULL);
        temp = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
        _traverse_node(x);
        gettimeofday(&tv, NULL);
        temp = (tv.tv_sec * 1000) + (tv.tv_usec / 1000) - temp;
        total__chew_time += temp;

        total__memory += (xmlnode_pool(x))->size;
}

int main(void)
{
    int fd, len;
    pool p = pool_new();
    xstream xs = xstream_new(p, _xstream_callback, NULL);
    char buff[1000];
    struct timeval tv;
    printf("Running Simulation...\n");

    fd = open("test.xml", O_RDONLY);
    if(fd <=0 )
        return 1;

    gettimeofday(&tv, NULL);
    total__time = (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
    while((len = read(fd, (char*)&buff, 1000)) > 0)
    {
            total__bytes += len;
            xstream_eat(xs, (char*)&buff, len);
    }
    gettimeofday(&tv, NULL);
    total__time = (tv.tv_sec * 1000) + (tv.tv_usec / 1000) - total__time;
    total__parse_time = total__time - total__serialize_time - total__chew_time;

    pool_free(p);
    printf("%d total child tags parsed (%d bytes) in %dms\n", total__tags, total__bytes, total__parse_time); 
    printf("took %dms to completely chew all nodes\n", total__chew_time);
    printf("took %dms to serialize all nodes\n", total__serialize_time);
    printf("total pre-travere memory used: %dk\n", total__pre_traverse_memory / 1024);
    printf("total memory used: %dk\n", total__memory / 1024);
    printf("total time for simulation: %dms\n", total__time);
    return 0;
}
