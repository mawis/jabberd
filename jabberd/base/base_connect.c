#include "jabberd.h"

/* create a "connection storage struct" */
/* register a handler w/ the instance asap, start a thread to connect, when it does it puts it in the connection storage struct */
/* incoming packets for the handler check the struct, if connected, send to the connection (msgport->write), else ERR */
/* two threads, one for read, one for write, each uses struct, when there's an error it gets flagged in the struct */
/* when disconnected, waiting write packets buffered (keep checking for reconnect, after X times bounce?), read thread attempts reconnect */


result base_connect_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_connect_config validating configuration\n");
        return r_PASS;
    }

    printf("base_connect_config performing configuration %s\n",xmlnode2str(x));
}

void base_connect(void)
{
    printf("base_connect loading...\n");

    register_config("connect",base_connect_config,NULL);
}