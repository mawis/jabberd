#include "jabberd.h"

/* each instance can share ports */

/*

<accept>
  <ip>1.2.3.4</ip>
  <port>2020</port>
  <secret>foobar</secret>
</accept>

*/

typedef struct sink_struct
{
    void *foo;
} *sink, _sink;

typedef struct acceptor_struct
{
    int sock, flag_ok, flag_read, flag_write;
    pth_cond_t cond_secret;
    instance i;
} *acceptor, _acceptor;

void base_accept_phandler(instance i, dpacket p, sink s)
{
    /* write packets to sink */
}

void *base_accept_write(void *arg)
{
    /* write the header */
    /* block on a condition from the read thread for success/failure of secret negotiation, write <secret/> or stream:error & close */
    /* then block on the sink */
    /* if the write() fails, return the packet to the sink and close */
}

void base_accept_read_packets(xstream xs, void *arg)
{
    acceptor a = (acceptor)arg;

    /* after getting a root, spawn write thread */
    pth_spawn(PTH_ATTR_DEFAULT,base_accept_write,arg)

    /* check status on socket, if it's sent a secret, then deliver the packet */
    if(a->flag_ok)
    {
        /* deliver */
        return;
    }

    /* check the secret */
    /* based on secret, store instance this socket is associated with */

}

/* thread to read from socket */
void *base_accept_read(void *arg)
{
    acceptor a = (acceptor)arg;

    /* create/deliver to xstream */
    /* if error on read(), just cleanup and quit */
}

/* thread to listen on a particular port/ip */
void *base_accept_listen(void *arg)
{
    acceptor a;

    /* look at the port="" and optional ip="" attribs and start listening */

    /* when we get a new socket */
    /* create acceptor */
    pth_spwan(PTH_ATTR_DEFAULT, base_accept_read, (void *)a);
}

xmlnode base_accept__listeners;

result base_accept_config(instance id, xmlnode x, void *arg)
{
    char *port, *ip;
    xmlnode cur;
    sink s;

    port = xmlnode_get_data(xmlnode_get_tag(x, "port"));
    ip = xmlnode_get_data(xmlnode_get_tag(x, "ip"));
    if(id == NULL)
    {
        printf("base_accept_config validating configuration\n");
	if(port == NULL || xmlnode_get_data(xmlnode_get_tag(x, "secret")) == NULL)
	    return r_ERR;
        return r_PASS;
    }

    printf("base_accept_config performing configuration %s\n",xmlnode2str(x));

    /* look for an existing accept section that is the same */
    for(cur = xmlnode_get_firstchild(base_accept__listeners); cur != NULL; cur = xmlnode_get_nextsibling(cur))
        if(strcmp(port,xmlnode_get_attrib(cur,"port")) == 0 && (ip == NULL && xmlnode_get_attrib(cur,"ip") == NULL || strcmp(ip,xmlnode_get_attrib(cur,"ip")) == 0))
            break;

    /* create a new section for this section */
    if(cur == NULL)
    {
        cur = xmlnode_insert_tag(base_accept__listeners, "listen");
        xmlnode_put_attrib(cur,"port",port);
        xmlnode_put_attrib(cur,"ip",ip);

        /* start a new listen thread */
        pth_spawn(PTH_ATTR_DEFAULT, base_accept_listen, (void *)cur);
    }

    /* insert secret into it and hide instance in that new secret */
    xmlnode_put_vattrib(xmlnode_insert_tag_node(cur,xmlnode_get_tag(x,"secret")),"i",(void *)id);

    /* create sink and register phandler, and register cleanup heartbeat */
    s = pmalloc_x(id->p, sizeof(_sink));

    /* hide sink as an attrib on the section */
}

void base_accept(void)
{
    printf("base_accept loading...\n");

    /* master list of all listen threads */
    base_accept__listeners = xmlnode_new_tag("listeners");

    register_config("accept",base_accept_config,NULL);
}
