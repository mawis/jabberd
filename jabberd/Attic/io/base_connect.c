#include "jabberd.h"

/*

<connect>
  <ip>1.2.3.4</ip>
  <port>2020</port>
  <secret>foobar</secret>
</connect>

*/

typedef struct sink_struct
{
    void *foo;
} *sink, _sink;

void base_connect_phandler(instance i, dpacket p, sink s)
{
    /* write packets to sink */
}

void *base_connect_write(void *arg)
{
    /* first, write header and secret, then block on condition from read thread to be ok'd to start */
    /* block on packets in the sink, write them to the socket */
    /* if the write() fails, return the packet to the sink and die */
}

void base_connect_read_packets(xstream xs)
{
    /* check status on socket, if the secret has been accepted, unblock the write thread */
    /* deliver packets normally */
}

void *base_connect_read(void *arg)
{
    /* attempt to create socket and connect to host */
    /* thread to read from socket */
    /* create/deliver to xstream */
    /* spawn base_accept_write */
    /* if error on read(), wait a bit and start over attempting to reconnect, log error */
}


result base_connect_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_connect_config validating configuration\n");
	if(xmlnode_get_data(xmlnode_get_tag(x, "port")) == NULL || xmlnode_get_data(xmlnode_get_tag(x, "secret")) == NULL)
	    return r_ERR;
        return r_PASS;
    }

    printf("base_connect_config performing configuration %s\n",xmlnode2str(x));
    /* spawn base_connect_read thread */
    /* create sink and register phandler, and register cleanup heartbeat */
}

void base_connect(void)
{
    printf("base_connect loading...\n");

    register_config("connect",base_connect_config,NULL);
}
