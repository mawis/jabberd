#include "jabberd.h"

result base_file_deliver(instance id, dpacket p, void* arg)
{
    FILE* f = (FILE*)arg;
    char* message = NULL;

    message = xmlnode_get_data(p->x);
    if (message == NULL)
    {
       printf("base_file_deliver error: no message available to print.\n");
       return r_ERR;
    }
    
    if (fprintf(f,"%s\n", message) == EOF)
    {
        printf("base_file_deliver error: error writing to file(%d).\n", errno);
        return r_ERR;
    }
    fflush(f);

    /* Release the packet */
    pool_free(p->p);
    return r_DONE;    
}

result base_file_config(instance id, xmlnode x, void *arg)
{
    FILE* filehandle = NULL;
        
    if(id == NULL)
    {
        if (xmlnode_get_data(x) == NULL)
        {
            printf("base_file_config error: no filename provided.\n");
            return r_ERR;
        }
        printf("base_file_config validating configuration\n");
        return r_PASS;
    }

    /* Attempt to open/create the file */
    filehandle = fopen(xmlnode_get_data(x), "a");
    if (filehandle == NULL)
    {
        printf("base_file_config error: error opening file (%d)\n", errno);
        return r_ERR;
    }

    /* Register a handler for this instance... */
    register_phandler(id, o_DELIVER, base_file_deliver, (void*)filehandle); 
    
    printf("base_file_config performing configuration %s\n",xmlnode2str(x));
    return r_DONE;
}

void base_file(void)
{
    printf("base_file loading...\n");

    register_config("file",base_file_config,NULL);
}
