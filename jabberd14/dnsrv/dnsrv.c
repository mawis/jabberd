#include "jabberd.h"
#include "srv_resolv.h"
#include <sys/wait.h>

/* Config format:
   <dnsrv xmlns='jabber:config:dnsrv'>
      <resend service="_jabber._tcp">foo.org</resend>
      ...
   </dnsrv>

   Notes:
   * You must specify the services in the order you want them tried
*/

#define DNS_PACKET_TABLE_SZ 100

/* ------------------------------------------------- */
/* Struct to store list of services and resend hosts */
typedef struct __dns_resend_list
{
     char* service;
     char* host;
     struct __dns_resend_list* next;
} *dns_resend_list, _dns_resend_list;


/* --------------------------------------- */
/* Struct to keep track of a DNS coprocess */
typedef struct
{
     int             in;		 /* Inbound data handle */
     int             out;		 /* Outbound data handle */
     int             pid;		 /* Coprocess PID */
     pth_msgport_t   write_queue;
     HASHTABLE       packet_table; /* Hash of dns_packet_lists */
     pth_event_t     e_read;
     pth_event_t     e_write;
     pth_event_t     events;
     pool            mempool;
     dns_resend_list svclist;
} *dns_io, _dns_io;

typedef int (*RESOLVEFUNC)(dns_io di);

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
     dns_io di = (dns_io)args;
     char*  hostname;
     char*  resolvestr = NULL;
     char*  response = NULL;
     dns_resend_list iternode = NULL;

     if (type == XSTREAM_NODE)
     {
	  /* Get the hostname out... */
	  hostname = xmlnode_get_data(x);
	  log_debug(ZONE, "dnsrv: Recv'd lookup request for %s", hostname);
	  if (hostname != NULL)
	  {
	       /* For each entry in the svclist, try and resolve using
		  the specified service and resend it to the specified host */
	       iternode = di->svclist;
	       while (iternode != NULL)
	       {
		    resolvestr = srv_lookup(x->p, iternode->service, hostname);
		    if (resolvestr != NULL)
		    {
			 log_debug(ZONE, "Resolved %s(%s): %s\tresend to:%s", hostname, iternode->service, resolvestr, iternode->host);
			 xmlnode_put_attrib(x, "ip", resolvestr);
			 xmlnode_put_attrib(x, "resend", iternode->host);
			 break;
		    }
		    iternode = iternode->next;
	       }
	       response = xmlnode2str(x);
	       pth_write(di->out, response, strlen(response));
	  }
     }
     xmlnode_free(x);
}

int dnsrv_child_main(dns_io di)
{
     pool    p   = pool_new();
     xstream xs  = xstream_new(p, dnsrv_child_process_xstream_io, di);
     int     readlen = 0;
     char    readbuf[1024];

     /* Transmit stream header */
     pth_write(di->out, "<stream>", strlen("<stream>"));

     /* Loop forever, processing requests and feeding them to the xstream*/     
     while (1)
     {
       readlen = pth_read(di->in, &readbuf, 1024);
       if(readlen > 0)
       {
        xstream_eat(xs, readbuf, readlen);
       }
       else
       {
         if(getppid()==1) break; /* our parent has died */
       }
     }	  
     /* child is out of loop... normal exit so parent will start us again */
     exit(0);
     return 0;
}



/* Core functionality */
int dnsrv_fork_and_capture(RESOLVEFUNC f, dns_io di)
{
     int left_fds[2], right_fds[2];
     int pid;

     /* Create left and right pipes */
     if (pipe(left_fds) < 0 || pipe(right_fds) < 0)
	  return -1;

     pid = pth_fork();
     if (pid < 0)
	  return -1;
     else if (pid > 0)		/* Parent */
     {
	  /* Close unneeded file handles */
	  close(left_fds[STDIN_FILENO]);
	  close(right_fds[STDOUT_FILENO]);
	  /* Return the in and out file descriptors */
	  di->in = right_fds[STDIN_FILENO];
	  di->out = left_fds[STDOUT_FILENO];
	  return pid;
     }
     else			/* Child */
     {
	  /* Close unneeded file handles */
	  close(left_fds[STDOUT_FILENO]);
	  close(right_fds[STDIN_FILENO]);
	  /* Start the specified function, passing the in/out descriptors */
	  di->in = left_fds[STDIN_FILENO]; di->out = right_fds[STDOUT_FILENO];
	  return (*f)(di);
     }
}

result dnsrv_deliver(instance i, dpacket p, void* args)
{
     dns_io di = (dns_io)args;
     dns_write_buf wb = NULL;

     if(p->type==p_ROUTE&&xmlnode_get_firstchild(p->x)!=NULL)
         p->x=xmlnode_get_firstchild(p->x);
     else if(p->type==p_ROUTE)
     { /* bad route packet */
         xmlnode_free(p->x);
         return r_DONE;
     }
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
     char* resendhost     = NULL;
     dns_packet_list head = NULL;
     dns_packet_list heado = NULL;

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
	       resendhost = xmlnode_get_attrib(x, "resend");

	       /* Remove the list from the hashtable */
	       ghash_remove(di->packet_table, hostname);
	       
	       /* Walk the list and insert IPs */
	       while(head != NULL)
	       {
		    head->packet->x=xmlnode_wrap(head->packet->x,"route");
		    if (ipaddr != NULL)
		    {
			 xmlnode_put_attrib(head->packet->x, "to", resendhost);
			 xmlnode_put_attrib(head->packet->x, "ip", ipaddr);
			 /* Fixup the dpacket host ptr */
			 head->packet->host = resendhost;
		    }
		    else
		    {
			 log_debug(ZONE, "dnsrv: Unable to resolve ip for %s\n", hostname);
			 jutil_error(head->packet->x, (terror){502, "Unable to resolve hostname."});
			 xmlnode_put_attrib(head->packet->x, "iperror", "");
		    }

		    heado = head;
		    /* Move to next.. */
		    head = head->next;
		    /* Deliver the packet */
		    deliver(dpacket_new(heado->packet->x), NULL);
	       }
	  }
	  /* Host name was not found, something is _TERRIBLY_ wrong! */
	  else
	       log_debug(ZONE, "Recv'd unknown host/ip request: %s\n", xmlnode2str(x));

     }
     xmlnode_free(x);
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
     char*    request  = NULL;

     /* Allocate an xstream for talking to the process */
     xs = xstream_new(di->mempool, dnsrv_process_xstream_io, di);

     /* Transmit root element to coprocess */
     pth_write(di->out, "<stream>", strlen("<stream>"));

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

	       log_debug(ZONE, "dnsrv: Recv'd a lookup request: %s", wb->packet->host);

	       /* Ensure this packet doesn't already have an IP */
	       if (xmlnode_get_attrib(wb->packet->x, "ip") ||
		   xmlnode_get_attrib(wb->packet->x, "iperror"))
	       {
		    /* Print an error and drop the packet.. */
		    log_debug(ZONE, "dnsrv: Looping IP lookup on %s\n", xmlnode2str(wb->packet->x));
		    xmlnode_free(wb->packet->x);
	       }
	       else 
	       {
		    /* Attempt to lookup this hostname in the packet table */
		    lsthead = (dns_packet_list)ghash_get(di->packet_table, wb->packet->host);
		    
		    /* IF: hashtable has the hostname, a lookup is already pending,
		       so stick the packet in the list */
		    if (lsthead != NULL)
		    {
			 log_debug(ZONE, "dnsrv: Adding lookup request for %s to pending queue.", wb->packet->host);
			 /* Allocate a new list entry */
			 lst = pmalloco(wb->packet->p, sizeof(_dns_packet_list));
			 lst->packet   = wb->packet;
			 lst->next     = lsthead->next;
			 lsthead->next = lst;		    
		    }
		    /* ELSE: insert the packet into the packet_table using the hostname
		       as the key and send a request to the coprocess */
		    else
		    {
			 log_debug(ZONE, "dnsrv: Creating lookup request queue for %s", wb->packet->host);
			 /* Allocate a new list head */
			 lsthead = pmalloco(wb->packet->p, sizeof(_dns_packet_list));
			 lsthead->packet = wb->packet;
			 lsthead->next   = NULL;
			 /* Insert the packet list into the hash */
			 ghash_put(di->packet_table, lsthead->packet->host, lsthead);
			 /* Spool up a request */
			 request = spools(lsthead->packet->p, "<host>", lsthead->packet->host, "</host>", lsthead->packet->p);

			 log_debug(ZONE, "dnsrv: Transmitting lookup request for %s to coprocess", wb->packet->host);
			 /* Send a request to the coprocess */
			 pth_write(di->out, request, strlen(request));
		    }
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

     log_debug(ZONE,"child returned %d",WEXITSTATUS(retcode));

     if(WIFEXITED(retcode)&&!WIFSIGNALED(retcode)) /* if the child exited normally */
     {
        /* Fork out resolver function/process */
        di->pid = dnsrv_fork_and_capture(dnsrv_child_main, di);

        /* Start IO thread */
        pth_spawn(PTH_ATTR_DEFAULT, dnsrv_process_io, (void*)di);
     }

     return NULL;
}

void *dnsrv_thread(void *arg)
{
     dns_io di=(dns_io)arg;
     /* Fork out resolver function/process */
     di->pid = dnsrv_fork_and_capture(dnsrv_child_main, di);
     return NULL;
}

void dnsrv(instance i, xmlnode x)
{
     xdbcache xc = NULL;
     xmlnode  config = NULL;
     xmlnode  iternode   = NULL;
     dns_resend_list tmplist = NULL;

     /* Setup a struct to hold dns_io handles */
     dns_io di;
     di = pmalloco(i->p, sizeof(_dns_io));

     di->mempool = i->p;

     /* Load config from xdb */
     xc = xdb_cache(i);
     config = xdb_get(xc, NULL, jid_new(xmlnode_pool(x), "config@-internal"), "jabber:config:dnsrv");

     /* Build a list of services/resend hosts */
     iternode = xmlnode_get_lastchild(config);
     while (iternode != NULL)
     {
	  if (j_strcmp("resend", xmlnode_get_name(iternode)) != 0)
	  {
	       iternode = xmlnode_get_prevsibling(iternode);
	       continue;
	  }

	  /* Allocate a new list node */
	  tmplist = pmalloco(di->mempool, sizeof(_dns_resend_list));
	  tmplist->service = pstrdup(di->mempool, xmlnode_get_attrib(iternode, "service"));
	  tmplist->host    = pstrdup(di->mempool, xmlnode_get_data(iternode));
	  /* Insert this node into the list */
	  tmplist->next = di->svclist;	  
	  di->svclist = tmplist;
	  /* Move to next child */
	  iternode = xmlnode_get_prevsibling(iternode);
     }
     log_debug(ZONE, "dnsrv debug: %s\n", xmlnode2str(config));

     /* Initialize a message port to handle incoming dpackets */
     di->write_queue = pth_msgport_create(i->id);

     /* Setup the hash of dns_packet_list */
     di->packet_table = ghash_create(DNS_PACKET_TABLE_SZ, (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);

     /* spawn a thread that get's forked, and wait for it since it sets up the fd's */
     pth_join(pth_spawn(PTH_ATTR_DEFAULT,(void*)dnsrv_thread,(void*)di),NULL);

     if(di->pid < 0)
     {
         log_error(i->id,"dnsrv failed to start, unable to fork and/or create pipes");
         return;
     }

     /* Start IO thread */
     pth_spawn(PTH_ATTR_DEFAULT, dnsrv_process_io, di);

     /* Register an incoming packet handler */
     register_phandler(i, o_DELIVER, dnsrv_deliver, (void*)di);
}
