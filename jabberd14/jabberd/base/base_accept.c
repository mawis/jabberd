#include "jabberd.h"

/* each instance can share ports */

/*

<accept>
  <ip>1.2.3.4</ip>
  <port>2020</port>
  <secret>foobar</secret>
</accept>

*/

base_accept_phandler(instance, packet, sink)
{
    /* write packets to sink */
}

void *base_accept_write(void *arg)
{
    /* first, block on a condition from the read thread, then write the header and block on the sink */
    /* second, block on a condition from the read thread for success/failure of secret negotiation, write <secret/> or stream:error & close */
    /* if the write() fails, return the packet to the sink */
}

void base_accept_read_packets(xstream...)
{
    /* after getting a root, send header */
    /* check status on socket, if it's sent a secret, then deliver the packet, otherwise only validate a secret */
    /* based on secret, store instance this socket is associated with */
    /* need the ring of secrets for validation from the parent listen thread */
}

void *base_accept_read(void *arg)
{
    /* thread to read from socket */
    /* create/deliver to xstream */
    /* spawn base_accept_write */
    /* if error on read(), just cleanup and quit */
}


result base_accept_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_accept_config validating configuration\n");
	if(xmlnode_get_data(xmlnode_get_tag(x, "port")) == NULL || xmlnode_get_data(xmlnode_get_tag(x, "secret")) == NULL)
	    return r_ERR;
        return r_PASS;
    }

    printf("base_accept_config performing configuration %s\n",xmlnode2str(x));
    /* find existing listen thread (or create) */
    /* add secret+instance to listen thread ring */
    /* create sink and register phandler, and register cleanup heartbeat */
}

void base_accept(void)
{
    printf("base_accept loading...\n");

    register_config("accept",base_accept_config,NULL);
}