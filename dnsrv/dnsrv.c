#include "jabberd.h"

typedef int (*RESOLVEFUNC)(int in, int out);

#define DNS_PACKET_TABLE_SZ 100

/* --------------------------------------- */
/* Struct to keep track of a DNS coprocess */
typedef struct
{
     int           in;		 /* Inbound data handle */
     int           out;		 /* Outbound data handle */
     int           pid;		 /* Coprocess PID */
     pth_msgport_t write_queue;
     HASHTABLE     packet_table; /* Hash of dns_packet_lists */
     pth_event_t   e_read;
     pth_event_t   e_write;
     pth_event_t   events;
     char*         resend_host;
     pool          mempool;
} *dns_io, _dns_io;


/* --------------------------------------------------- */
/* Struct to store a dpacket that needs to be resolved */
typedef struct
{
     pth_message_t head;
     dpacket       packet;
} *dns_write_buf, _dns_write_buf;


/* ----------------------------------------------------------- */
/* Struct to store list of dpackets which need to be delivered */
typedef struct __dns_packet_list
{
     dpacket           packet;
     struct __dns_packet_list* next;
} *dns_packet_list, _dns_packet_list;

/* ----------------------- */
/* Coprocess functionality */
void dnsrv_child_process_xstream_io(int type, xmlnode x, void* args)
{
     int out = *((int*)args);
     char*  hostname;
     struct hostent *hp;
     struct in_addr ip_addr;
     char*  response = NULL;

     if (type == XSTREAM_NODE)
     {
	  /* Get the hostname out... */
	  hostname = xmlnode_get_data(x);
	  if (hostname != NULL)
	  {
	       /* Lookup host name */
	       hp      = gethostbyname(hostname);
	       if (!hp) 
	       {
		    log_debug(ZONE, "dnsrv_child: Unable to resolve: %s\n", hostname);
	       }
	       else 
	       {
		    ip_addr = *(struct in_addr *)(hp->h_addr);
		    /* Insert attribute into the node.. */
		    xmlnode_put_attrib(x, "ip", inet_ntoa(ip_addr));
	       }
	       /* Transmit the result... */
	       response = xmlnode2str(x);
	       pth_write(out, response, strlen(response));
	  }
     }   
}

int dnsrv_child_main(int in, int out)
{
     int     fout= out;
     pool    p   = pool_new();
     xstream xs  = xstream_new(p, dnsrv_child_process_xstream_io, &fout);
     int     readlen = 0;
     char    readbuf[1024];

     /* Transmit stream header */
     pth_write(out, "<stream>", strlen("<stream>"));

     /* Loop forever, processing requests and feeding them to the xstream*/     
     while ( ((readlen = pth_read(in, &readbuf, 1024)) > 0) &&
	     (xstream_eat(xs, readbuf, readlen)))
     {}	  

     return 0;
}



/* Core functionality */
int dnsrv_fork_and_capture(RESOLVEFUNC f, int* in, int* out)
{
     int left_fds[2], right_fds[2];
     int pid;

     /* Create left and right pipes */
     if (pipe(left_fds) < 0 || pipe(right_fds) < 0)
	  return r_ERR;

     pid = pth_fork();
     if (pid < 0)
	  return r_ERR;
     else if (pid > 0)		/* Parent */
     {
	  /* Close unneeded file handles */
	  close(left_fds[STDIN_FILENO]);
	  close(right_fds[STDOUT_FILENO]);
	  /* Return the in and out file descriptors */
	  *in = right_fds[STDIN_FILENO];
	  *out = left_fds[STDOUT_FILENO];
	  return pid;
     }
     else			/* Child */
     {
	  /* Close unneeded file handles */
	  close(left_fds[STDOUT_FILENO]);
	  close(right_fds[STDIN_FILENO]);
	  /* Start the specified function, passing the in/out descriptors */
	  return (*f)(left_fds[STDIN_FILENO], right_fds[STDOUT_FILENO]);
     }
}

result dnsrv_deliver(instance i, dpacket p, void* args)
{
     dns_io di = (dns_io)args;
     dns_write_buf wb = NULL;

     /* Allocate a new write buffer */
     wb = pmalloco(p->p, sizeof(_dns_write_buf));
     wb->packet = p;

     /* Send the buffer to the IO thread */
     pth_msgport_put(di->write_queue, (pth_message_t*)wb);

     return r_DONE;
}

void dnsrv_process_xstream_io(int type, xmlnode x, void* arg)
{
     dns_io di            = (dns_io)arg;
     char* hostname       = NULL;
     char* ipaddr         = NULL;
     dns_packet_list head = NULL;

     /* Node Format: <host ip="201.83.28.2">foo.org</host> */
     if (type == XSTREAM_NODE)
     {	  
	  hostname = xmlnode_get_data(x);
	  /* Get the hostname and look it up in the hashtable */
	  head = ghash_get(di->packet_table, hostname);
	  /* Process the packet list */
	  if (head != NULL)
	  {
	       ipaddr = xmlnode_get_attrib(x, "ip");

	       /* Remove the list from the hashtable */
	       ghash_remove(di->packet_table, hostname);
	       
	       /* Walk the list and insert IPs */
	       while(head != NULL)
	       {
		    xmlnode_put_attrib(head->packet->x, "ip", ipaddr);
		    xmlnode_put_attrib(head->packet->x, "sto", di->resend_host);
		    /* Deliver the packet */
		    deliver(head->packet, NULL);
		    /* Move to next.. */
		    head = head->next;
	       }
	  }
	  /* Host name was not found, something is _TERRIBLY_ wrong! */
	  else
	       log_debug(ZONE, "Recv'd unknown host/ip request: %s\n", xmlnode2str(x));
     }
}

void* dnsrv_process_io(void* threadarg)
{
     /* Get DNS IO info */
     dns_io di = (dns_io)threadarg;

     int  retcode       = 0;
     int  readlen       = 0;
     char readbuf[1024];

     dns_write_buf   wb       = NULL;
     dns_packet_list lst      = NULL;
     dns_packet_list lsthead  = NULL;

     xstream  xs       = NULL;       
     pool     listpool = NULL;
     char*    request  = NULL;

     /* Allocate an xstream for talking to the process */
     xs = xstream_new(di->mempool, dnsrv_process_xstream_io, di);

     /* Transmit root element to coprocess */
     pth_write(di->out, "<stream>", strlen("<stream>"));

     /* Setup a new pool to keep track of packet lists */
     listpool = pool_new();

     /* Setup event ring for coprocess reading and message queue events */
     di->e_read  = pth_event(PTH_EVENT_FD|PTH_UNTIL_FD_READABLE, di->in);
     di->e_write = pth_event(PTH_EVENT_MSG, di->write_queue);
     di->events  = pth_event_concat(di->e_read, di->e_write, NULL);

     /* Loop on events */
     while (pth_wait(di->events) > 0)
     {
	  /* Hostname lookup completed from coprocess */
	  if (pth_event_occurred(di->e_read))
	  {
	       /* Read the data from the coprocess into the parser */
	       readlen = pth_read(di->in, readbuf, sizeof(readbuf));
               if (readlen <= 0)
               {
                    log_debug(ZONE,"dnsrv: Read error on coprocess!\n");
                    break;
               }

               if (xstream_eat(xs, readbuf, readlen) > XSTREAM_NODE)
                    break;

	  }
	  /* Hostname lookup requested */
	  if (pth_event_occurred(di->e_write))
	  {
	       /* Get the packet from the write_queue */
	       wb = (dns_write_buf)pth_msgport_get(di->write_queue);

	       /* Attempt to lookup this hostname in the packet table */
	       lsthead = (dns_packet_list)ghash_get(di->packet_table, wb->packet->host);
	       
	       /* IF: hashtable has the hostname, a lookup is already pending,
		  so stick the packet in the list */
	       if (lsthead != NULL)
	       {
		    /* Allocate a new list entry */
		    lst = pmalloco(listpool, sizeof(_dns_packet_list));
		    lst->packet   = wb->packet;
		    lst->next     = lsthead->next;
		    lsthead->next = lst;		    
	       }
	       /* ELSE: insert the packet into the packet_table using the hostname
		  as the key and send a request to the coprocess */
	       else
	       {
		    /* Allocate a new list head */
		    lsthead = pmalloco(listpool, sizeof(_dns_packet_list));
		    lsthead->packet = wb->packet;
		    lsthead->next   = NULL;
		    /* Insert the packet list into the hash */
		    ghash_put(di->packet_table, lsthead->packet->host, lsthead);
		    /* Spool up a request */
		    request = spools(listpool, "<host>", lsthead->packet->host, "</host>", listpool);
		    /* Send a request to the coprocess */
		    pth_write(di->out, request, strlen(request));
	       }
	  }
     }

     /* If we reached this point, the coprocess probably is dead, so 
	process the SIG_CHLD */
     pth_waitpid(di->pid, &retcode, 0);

     /* Cleanup */
     close(di->in);
     close(di->out);
     pth_event_free(di->e_read, PTH_FREE_THIS);
     pth_event_free(di->e_write, PTH_FREE_THIS);

     /* Fork out resolver function/process */
     di->pid = dnsrv_fork_and_capture(dnsrv_child_main, &(di->in), &(di->out));

     /* Start IO thread */
     pth_spawn(PTH_ATTR_DEFAULT, dnsrv_process_io, (void*)di);

     return NULL;
}


void dnsrv(instance i, xmlnode x)
{
     xdbcache xc = NULL;
     xmlnode  config = NULL;

     /* Setup a struct to hold dns_io handles */
     dns_io di;
     di = pmalloco(i->p, sizeof(_dns_io));

     di->mempool = i->p;

     /* Load config from xdb */
     xc = xdb_cache(i);
     config = xdb_get(xc, NULL, jid_new(xmlnode_pool(x), "config@-internal"), "jabberd:dnsrv:config");

     /* Extract destination host from config */
     di->resend_host = pstrdup(di->mempool, xmlnode_get_tag_data(config, "resendhost"));

     /* Initialize a message port to handle incoming dpackets */
     di->write_queue = pth_msgport_create(i->id);

     /* Setup the hash of dns_packet_list */
     di->packet_table = ghash_create(DNS_PACKET_TABLE_SZ, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);

     /* Fork out resolver function/process */
     di->pid = dnsrv_fork_and_capture(dnsrv_child_main, &(di->in), &(di->out));

     /* Start IO thread */
     pth_spawn(PTH_ATTR_DEFAULT, dnsrv_process_io, di);

     /* Register an incoming packet handler */
     register_phandler(i, o_DELIVER, dnsrv_deliver, (void*)di);
}
