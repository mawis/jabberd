#include "jabberd.h"

result base_stderr_display(instance i, dpacket p, void* args)
{   
    char* message = NULL;
    
    /* Get the raw data from the packet */
    message = xmlnode_get_data(p->x);

    if (message == NULL)
    {
        printf("base_stderr_deliver: no message available to print.\n");
        return r_ERR;
    }

    fprintf(stderr, "%s\n", message);

    pool_free(p->p);
    return r_DONE;
}

result base_stderr_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_stderr_config validating configuration\n");
        return r_PASS;
    }

    /* Register the handler, for this instance */
    register_phandler(id, o_DELIVER, base_stderr_display, (void*) 0);

    printf("base_stderr_config performing configuration %s\n",xmlnode2str(x));
    return r_DONE;
}

void base_stderr(void)
{
    printf("base_stderr loading...\n");

    register_config("stderr",base_stderr_config,NULL);
}
