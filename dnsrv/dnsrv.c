/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "License").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the License.  You
 * may obtain a copy of the License at http://www.jabber.com/license/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2000 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * --------------------------------------------------------------------------*/
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
     int             packet_timeout; /* how long to keep packets in the queue */
     HASHTABLE       cache_table; /* Hash of resolved IPs */
     int             cache_timeout; /* how long to keep resolutions in the cache */
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
     int               stamp;
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
     xmlnode c;

     if (type == XSTREAM_NODE)
     {
	  /* Get the hostname out... */
	  hostname = xmlnode_get_data(x);
	  log_debug(ZONE, "dnsrv: Recv'd lookup request for %s", hostname);
	  if (hostname != NULL)
	  {
               /* try the cache first */
               if((c = ghash_get(di->cache_table, hostname)) != NULL)
               {
                    if((time(NULL) - (int)xmlnode_get_vattrib(c,"t")) > di->cache_timeout)
                    { /* timed out of the cache, lookup again */
                        xmlnode_free(c);
                        ghash_remove(di->cache_table,hostname);
                    }else{
                        /* yay, send back right from the cache */
                        response = xmlnode2str(c);
                        pth_write(di->out, response, strlen(response));
                        xmlnode_free(x);
                        return;
                    }
               }

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
               /* whatever the response was, let's cache it */
               xmlnode_put_vattrib(x,"t",(void*)time(NULL));
               ghash_put(di->cache_table,hostname,(void*)x);
               return;
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
     sigset_t sigs;


     sigemptyset(&sigs);
     sigaddset(&sigs, SIGHUP);
     sigprocmask(SIG_BLOCK, &sigs, NULL);

     /* Transmit stream header */
     write(di->out, "<stream>", 8);

     /* Loop forever, processing requests and feeding them to the xstream*/     
     while (1)
     {
        log_debug(ZONE, "DNSRV CHILD: Reading from buffer");
       readlen = read(di->in, &readbuf, 1024);
       if(readlen > 0)
       {
        log_debug(ZONE, "DNSRV CHILD: eating read buffer");
        xstream_eat(xs, readbuf, readlen);
       }
       else
       {
        if(errno == EINTR)
        {
            log_debug(ZONE, "DNSRV CHILD: EINTR");
        }
        log_debug(ZONE, "DNSRV CHILD: error on read");
         if(getppid()==1) break; /* our parent has died */
       }
     }	  
     /* child is out of loop... normal exit so parent will start us again */
        log_debug(ZONE, "DNSRV CHILD: out of loop.. exiting normal");
     pool_free(p);
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
          pth_kill();
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
	       log_debug(ZONE, "Resolved unknown host/ip request: %s\n", xmlnode2str(x));

     }
     xmlnode_free(x);
} 

void* dnsrv_process_io(void* threadarg)
{
     /* Get DNS IO info */
     dns_io di = (dns_io)threadarg;

     int  retcode       = 0;
     int  pid           = 0;
     int  readlen       = 0;
     char readbuf[1024];

     dns_write_buf   wb       = NULL;
     dns_packet_list lst      = NULL;
     dns_packet_list lsthead  = NULL;

     xstream  xs       = NULL;       
     char*    request  = NULL;
     sigset_t sigs;

     sigemptyset(&sigs);
     sigaddset(&sigs, SIGHUP);
     sigprocmask(SIG_BLOCK, &sigs, NULL);

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
                    if(errno == EINTR) 
                    {
                        log_debug(ZONE, "socket interupted");
                    }
                    log_debug(ZONE,"dnsrv: Read error on coprocess!\n");
	                while((wb = (dns_write_buf)pth_msgport_get(di->write_queue)) != NULL)
                    {
                        pool_free(wb->packet->p);
                    }
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
			 lst->stamp    = time(NULL);
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
			 lsthead->stamp  = time(NULL);
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
     pid = pth_waitpid(di->pid, &retcode, 0);

     if(pid == -1)
     {
        log_debug(ZONE, "pth_waitpid returned -1: %s", strerror(errno));
     }
     else if(pid == 0)
     {
        log_debug(ZONE, "no child available to call waitpid on");
     }
     else
     {
        log_debug(ZONE, "pid %d, exit status: %d", pid, WEXITSTATUS(retcode));
     }

     /* Cleanup */
     close(di->in);
     close(di->out);

     log_debug(ZONE,"child returned %d",WEXITSTATUS(retcode));

     if(WIFEXITED(retcode)&&WIFSIGNALED(retcode)) /* if the child exited normally */
     {
        log_debug(ZONE, "child being restarted...");
        /* Fork out resolver function/process */
        di->pid = dnsrv_fork_and_capture(dnsrv_child_main, di);

        /* Start IO thread */
        pth_spawn(PTH_ATTR_DEFAULT, dnsrv_process_io, (void*)di);
        return NULL;
     }

     log_debug(ZONE, "child dying...4");
     log_debug(ZONE, "child dying...3");
     pth_event_free(di->e_read, PTH_FREE_THIS);
     log_debug(ZONE, "child dying...2");
     pth_event_free(di->e_write, PTH_FREE_THIS);
     log_debug(ZONE, "child dying...1");
     pth_msgport_destroy(di->write_queue);
     log_debug(ZONE, "child dying...0");
     return NULL;
}

void *dnsrv_thread(void *arg)
{
     dns_io di=(dns_io)arg;
     /* Fork out resolver function/process */
     di->pid = dnsrv_fork_and_capture(dnsrv_child_main, di);
     return NULL;
}

void dnsrv_shutdown(void *arg)
{
     dns_io di=(dns_io)arg;
     ghash_destroy(di->packet_table);

     /* spawn a thread that get's forked, and wait for it since it sets up the fd's */
}

/* callback for walking the connecting hash tree */
int _dnsrv_beat_packets(void *arg, const void *key, void *data)
{
    dns_io di = (dns_io)arg;
    dns_packet_list n, l = (dns_packet_list)data, d = (dns_packet_list)data;
    int now = time(NULL);
    int reap = 0;

    /* first, check the head */
    if((now - l->stamp) > di->packet_timeout)
    {
        log_notice(l->packet->host,"timed out from dnsrv queue");
        ghash_remove(di->packet_table,l->packet->host);
        reap = 1;
    }else{
        while(l->next != NULL)
        {
            if((now - l->next->stamp) > di->packet_timeout)
            {
                reap = 1;
                n = l->next;
                l->next = NULL; /* chop off packets to be killed */
                l = n;
                /* tricky!  if we're going to reap packets on the end of the list, one if these contains the char* that's the key for ghash, reset ghash! */
                ghash_put(di->packet_table,d->packet->host, data);
                break;
            }
            l = l->next;
        }
    }

    if(reap == 0) return 1;

    /* time out individual queue'd packets */
    while(l != NULL)
    {
        n = l->next;
        deliver_fail(l->packet,"Hostname Resolution Timeout");
        l = n;
    }

    return 1;
}

result dnsrv_beat_packets(void *arg)
{
    dns_io di = (dns_io)arg;
    ghash_walk(di->packet_table,_dnsrv_beat_packets,arg);
    return r_DONE;
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
     config = xdb_get(xc, jid_new(xmlnode_pool(x), "config@-internal"), "jabber:config:dnsrv");

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
     di->packet_table = ghash_create(j_atoi(xmlnode_get_attrib(config,"queuemax"),101), (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);
     di->packet_timeout = j_atoi(xmlnode_get_attrib(config,"queuetimeout"),60);
     register_beat(di->packet_timeout, dnsrv_beat_packets, (void *)di);


     /* Setup the internal hostname cache */
     di->cache_table = ghash_create(j_atoi(xmlnode_get_attrib(config,"cachemax"),1999), (KEYHASHFUNC)str_hash_code, (KEYCOMPAREFUNC)j_strcmp);
     di->cache_timeout = j_atoi(xmlnode_get_attrib(config,"cachetimeout"),21600); /* 6 hour dns cache? XXX would be nice to get the right value from dns! */

     xmlnode_free(config);

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
     /* register a cleanup function */
     pool_cleanup(i->p, dnsrv_shutdown, (void*)di);
}
