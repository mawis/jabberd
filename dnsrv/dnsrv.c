/* --------------------------------------------------------------------------
 *
 * License
 *
 * The contents of this file are subject to the Jabber Open Source License
 * Version 1.0 (the "JOSL").  You may not copy or use this file, in either
 * source code or executable form, except in compliance with the JOSL. You
 * may obtain a copy of the JOSL at http://www.jabber.org/ or at
 * http://www.opensource.org/.  
 *
 * Software distributed under the JOSL is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the JOSL
 * for the specific language governing rights and limitations under the
 * JOSL.
 *
 * Copyrights
 * 
 * Portions created by or assigned to Jabber.com, Inc. are 
 * Copyright (c) 1999-2002 Jabber.com, Inc.  All Rights Reserved.  Contact
 * information for Jabber.com, Inc. is available at http://www.jabber.com/.
 *
 * Portions Copyright (c) 1998-1999 Jeremie Miller.
 * 
 * Acknowledgements
 * 
 * Special thanks to the Jabber Open Source Contributors for their
 * suggestions and support of Jabber.
 * 
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 or later (the "GPL"), in which case
 * the provisions of the GPL are applicable instead of those above.  If you
 * wish to allow use of your version of this file only under the terms of the
 * GPL and not to allow others to use your version of this file under the JOSL,
 * indicate your decision by deleting the provisions above and replace them
 * with the notice and other provisions required by the GPL.  If you do not
 * delete the provisions above, a recipient may use your version of this file
 * under either the JOSL or the GPL. 
 * 
 * 
 * --------------------------------------------------------------------------*/
#include "jabberd.h"
#include "srv_resolv.h"
#include <sys/wait.h>

#ifdef LIBIDN
#  include <idna.h>
#endif
/* Config format:
   <dnsrv xmlns='jabber:config:dnsrv'>
      <resend service="_jabber._tcp">foo.org</resend>
      ...
   </dnsrv>

   Notes:
   * You must specify the services in the order you want them tried
*/

/**
 * @brief structure to build a list that holds all hosts to which the packets are resent for a service
 */
typedef struct __dns_resend_list_host_list {
    char *host;
    int weight;
    struct __dns_resend_list_host_list *next;
} *dns_resend_list_host_list, _dns_resend_list_host_list;

/* ------------------------------------------------- */
/* Struct to store list of services and resend hosts */
typedef struct __dns_resend_list
{
     char* service;
     dns_resend_list_host_list hosts;
     int weight_sum;
     struct __dns_resend_list* next;
} *dns_resend_list, _dns_resend_list;


/* --------------------------------------- */
/* Struct to keep track of a DNS coprocess */
typedef struct
{
     int             in;		 /* Inbound data handle */
     int             out;		 /* Outbound data handle */
     int             pid;		 /* Coprocess PID */
     xht	     packet_table; /* Hash of dns_packet_lists */
     int             packet_timeout; /* how long to keep packets in the queue */
     xht       	     cache_table; /* Hash of resolved IPs */
     int             cache_timeout; /* how long to keep resolutions in the cache */
     pool            mempool;
     dns_resend_list svclist;
} *dns_io, _dns_io;

typedef int (*RESOLVEFUNC)(dns_io di);

/* ----------------------------------------------------------- */
/* Struct to store list of dpackets which need to be delivered */
typedef struct __dns_packet_list
{
     dpacket           packet;
     int               stamp;
     struct __dns_packet_list* next;
} *dns_packet_list, _dns_packet_list;


/* ------------------------- */
/* just die after any signal */
void _dnsrv_signal(int sig)
{
    exit(0);
}

/* ----------------------- */
/* Coprocess functionality */
void dnsrv_child_process_xstream_io(int type, xmlnode x, void* args)
{
     dns_io di = (dns_io)args;
     char *hostname, *ascii_hostname = NULL;
     char *str = NULL;
     dns_resend_list iternode = NULL;

     if (type == XSTREAM_NODE)
     {
	  /* Get the hostname out... */
	  hostname = xmlnode_get_data(x);
	  log_debug2(ZONE, LOGT_IO, "dnsrv: Recv'd lookup request for %s", hostname);
	  if (hostname != NULL)
	  {
#ifdef LIBIDN
	      if (idna_to_ascii_8z(hostname, &ascii_hostname, 0) == IDNA_SUCCESS)
	      {
		  log_debug2(ZONE, LOGT_IO, "dnsrv: IDN conversion %s to %s", hostname, ascii_hostname);
		  hostname = ascii_hostname;
	      }
#endif
	       /* For each entry in the svclist, try and resolve using
		  the specified service and resend it to the specified host */
	       iternode = di->svclist;
	       while (iternode != NULL)
	       {
		    str = srv_lookup(x->p, iternode->service, hostname);
		    if (str != NULL)
		    {
			 dns_resend_list_host_list iterhost = iternode->hosts;

			 /* play the dice, to select one of the s2s hosts */
			 /* XXX should we statically distribute to the hosts using a hash over the destination? */
			 int host_die = iternode->weight_sum <= 1 ? 0 : rand()%(iternode->weight_sum);

			 /* find the host selected by our host_die */
			 while (host_die >= iterhost->weight && iterhost->next != NULL) {
			     /* try next host */
			     host_die -= iterhost->weight;
			     iterhost = iterhost->next;
			 }

			 log_debug2(ZONE, LOGT_IO, "Resolved %s(%s): %s\tresend to:%s", hostname, iternode->service, str, iterhost->host);
			 xmlnode_put_attrib(x, "ip", str);
			 xmlnode_put_attrib(x, "to", iterhost->host);
			 break;
		    }
		    iternode = iternode->next;
	       }
               str = xmlnode2str(x);
	       write(di->out, str, strlen(str));
#ifdef LIBIDN
	       if (ascii_hostname != NULL)
		   free(ascii_hostname);
#endif
          }
     }
     xmlnode_free(x);
}

int dnsrv_child_main(dns_io di)
{
     pool    p   = pool_new();
     xstream xs  = xstream_new(p, dnsrv_child_process_xstream_io, di);
     int     len;
     char    readbuf[1024];

     log_debug2(ZONE, LOGT_INIT, "DNSRV CHILD: starting");

     /* Transmit stream header */
     write(di->out, "<stream>", 8);

     /* Loop forever, processing requests and feeding them to the xstream*/     
     while (1)
     {
       len = read(di->in, &readbuf, 1024);
       if (len <= 0)
       {
           log_debug2(ZONE, LOGT_IO|LOGT_STRANGE, "dnsrv: Read error on coprocess(%d): %d %s",getppid(),errno,strerror(errno));
           break;
       }

       log_debug2(ZONE, LOGT_IO, "DNSRV CHILD: Read from buffer: %.*s",len,readbuf);

       if (xstream_eat(xs, readbuf, len) > XSTREAM_NODE)
       {
           log_debug2(ZONE, LOGT_IO|LOGT_STRANGE, "DNSRV CHILD: xstream died");
           break;
       }
     }

     /* child is out of loop... normal exit so parent will start us again */
     log_debug2(ZONE, LOGT_STRANGE|LOGT_CLEANUP, "DNSRV CHILD: out of loop.. exiting normal");
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

     pid = fork();
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
          /* Transmit root element to coprocess */
          pth_write(di->out, "<stream>", 8);
	  return pid;
     }
     else			/* Child */
     {
          /* set up the new process */
          pth_kill();
	  signal(SIGHUP,_dnsrv_signal);
	  signal(SIGINT,_dnsrv_signal);
	  signal(SIGTERM,_dnsrv_signal);
	  close(left_fds[STDOUT_FILENO]);
	  close(right_fds[STDIN_FILENO]);
	  /* Start the specified function, passing the in/out descriptors */
	  di->in = left_fds[STDIN_FILENO]; di->out = right_fds[STDOUT_FILENO];
	  return (*f)(di);
     }
}

void dnsrv_resend(xmlnode pkt, char *ip, char *to)
{
    if(ip != NULL)
    {
	 /* maybe the packet as a query by a component, that wants to get the result back to itself */
	 /* this is needed for handling db:verify by the s2s component: if the component is clustered,
	  * the result for the db:verify packet has to be the s2s component that verifies the db */
	 char *dnsresultto = xmlnode_get_attrib(pkt, "dnsqueryby");
	 if (dnsresultto == NULL)
	     dnsresultto = to;

	 log_debug2(ZONE, LOGT_IO, "delivering DNS result to: %s", dnsresultto);

         pkt = xmlnode_wrap(pkt,"route");
	 xmlnode_put_attrib(pkt, "to", dnsresultto);
	 xmlnode_put_attrib(pkt, "ip", ip);
    }else{
	 jutil_error_xmpp(pkt, (xterror){502, "Unable to resolve hostname.","wait","service-unavailable"});
	 xmlnode_put_attrib(pkt, "iperror", "");
    }
    deliver(dpacket_new(pkt),NULL);
}


/* Hostname lookup requested */
void dnsrv_lookup(dns_io d, dpacket p)
{
    dns_packet_list l, lnew;
    xmlnode req;
    char *reqs;

    /* make sure we have a child! */
    if(d->out <= 0)
    {
        deliver_fail(p, "DNS Resolver Error");
        return;
    }

    /* Attempt to lookup this hostname in the packet table */
    l = (dns_packet_list)xhash_get(d->packet_table, p->host);

    /* IF: hashtable has the hostname, a lookup is already pending,
       so push the packet on the top of the list (most recent at the top) */
    if (l != NULL)
    {
	 log_debug2(ZONE, LOGT_IO, "dnsrv: Adding lookup request for %s to pending queue.", p->host);
	 lnew = pmalloco(p->p, sizeof(_dns_packet_list));
	 lnew->packet = p;
	 lnew->stamp = time(NULL);
	 lnew->next = l;
         xhash_put(d->packet_table, p->host, lnew);
         return;
    }

    /* insert the packet into the packet_table using the hostname
       as the key and send a request to the coprocess */
    log_debug2(ZONE, LOGT_IO, "dnsrv: Creating lookup request queue for %s", p->host);
    l = pmalloco(p->p, sizeof(_dns_packet_list));
    l->packet = p;
    l->stamp  = time(NULL);
    xhash_put(d->packet_table, p->host, l);
    req = xmlnode_new_tag_pool(p->p,"host");
    xmlnode_insert_cdata(req,p->host,-1);

    reqs = xmlnode2str(req);
    log_debug2(ZONE, LOGT_IO, "dnsrv: Transmitting lookup request: %s", reqs);
    pth_write(d->out, reqs, strlen(reqs));
}


result dnsrv_deliver(instance i, dpacket p, void* args)
{
     dns_io di = (dns_io)args;
     xmlnode c;
     int timeout = di->cache_timeout;
     char *ip;
     jid to;

     /* if we get a route packet, it has to be to *us* and have the child as the real packet */
     if(p->type == p_ROUTE)
     {
        if(j_strcmp(p->host,i->id) != 0 || (to = jid_new(p->p,xmlnode_get_attrib(xmlnode_get_firstchild(p->x),"to"))) == NULL)
            return r_ERR;
        p->x=xmlnode_get_firstchild(p->x);
        p->id = to;
        p->host = to->server;
     }

     /* Ensure this packet doesn't already have an IP */
     if(xmlnode_get_attrib(p->x, "ip") || xmlnode_get_attrib(p->x, "iperror"))
     {
        log_notice(p->host, "dropping looping dns lookup request: %s", xmlnode2str(p->x));
        xmlnode_free(p->x);
        return r_DONE;
     }

     /* try the cache first */
     if((c = xhash_get(di->cache_table, p->host)) != NULL)
     {
         /* if there's no IP, cached failed lookup, time those out 10 times faster! (weird, I know, *shrug*) */
         if((ip = xmlnode_get_attrib(c,"ip")) == NULL)
            timeout = timeout / 10;
         if((time(NULL) - *(time_t*)xmlnode_get_vattrib(c,"t")) > timeout)
         { /* timed out of the cache, lookup again */
             xhash_zap(di->cache_table,p->host);
             xmlnode_free(c);
         }else{
             /* yay, send back right from the cache */
             dnsrv_resend(p->x, ip, xmlnode_get_attrib(c,"to"));
             return r_DONE;
         }
     }

    dnsrv_lookup(di, p);
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
     time_t *ttmp;

     /* Node Format: <host ip="201.83.28.2">foo.org</host> */
     if (type == XSTREAM_NODE)
     {	  
          log_debug2(ZONE, LOGT_IO, "incoming resolution: %s",xmlnode2str(x));
	  hostname = xmlnode_get_data(x);

          /* whatever the response was, let's cache it */
          xmlnode_free((xmlnode)xhash_get(di->cache_table,hostname)); /* free any old cache, shouldn't ever be any */
          ttmp = pmalloc(xmlnode_pool(x),sizeof(time_t));
          time(ttmp);
          xmlnode_put_vattrib(x,"t",(void*)ttmp);
          xhash_put(di->cache_table,hostname,(void*)x);

	  /* Get the hostname and look it up in the hashtable */
	  head = xhash_get(di->packet_table, hostname);
	  /* Process the packet list */
	  if (head != NULL)
	  {
	       ipaddr = xmlnode_get_attrib(x, "ip");
	       resendhost = xmlnode_get_attrib(x, "to");

	       /* Remove the list from the hashtable */
	       xhash_zap(di->packet_table, hostname);
	       
	       /* Walk the list and insert IPs */
	       while(head != NULL)
	       {
		    heado = head;
		    /* Move to next.. */
		    head = head->next;
		    /* Deliver the packet */
                    dnsrv_resend(heado->packet->x, ipaddr, resendhost);
	       }
	  }
	  /* Host name was not found, something is _TERRIBLY_ wrong! */
	  else
	       log_debug2(ZONE, LOGT_IO, "Resolved unknown host/ip request: %s\n", xmlnode2str(x));

          return; /* we cached x above, so we don't free it below :) */
     }
     xmlnode_free(x);
} 

void* dnsrv_process_io(void* threadarg)
{
     /* Get DNS IO info */
     dns_io di = (dns_io)threadarg;
     int  readlen       = 0;
     char readbuf[1024];
     xstream  xs       = NULL;       

     /* Allocate an xstream for talking to the process */
     xs = xstream_new(di->mempool, dnsrv_process_xstream_io, di);

     /* Loop forever */
     while (1)
     {
       /* Hostname lookup completed from coprocess */
       readlen = pth_read(di->in, readbuf, sizeof(readbuf));
       if (readlen <= 0)
       {
           log_debug2(ZONE, LOGT_IO|LOGT_STRANGE, "dnsrv: Read error on coprocess: %d %s",errno,strerror(errno));
           break;
       }

       if (xstream_eat(xs, readbuf, readlen) > XSTREAM_NODE)
           break;
     }

     /* Cleanup */
     close(di->in);
     close(di->out);
     di->out = 0;
     waitpid(di->pid, &readlen, WNOHANG); /* reap any dead children */

     /* silly to restart it if it died cuz we're shutting down, pretty hackish to do it this way tho... must be hackish when the comment is longer than the code itself, but I'm rambling */
     if(jabberd__signalflag == SIGTERM || jabberd__signalflag == SIGINT) return NULL;

     log_debug2(ZONE, LOGT_INIT, "child being restarted...");

     /* Fork out resolver function/process */
     di->pid = dnsrv_fork_and_capture(dnsrv_child_main, di);

     /* Start new IO thread */
     pth_spawn(PTH_ATTR_DEFAULT, dnsrv_process_io, (void*)di);
     return NULL;
}

void *dnsrv_thread(void *arg)
{
     dns_io di=(dns_io)arg;
     /* Fork out resolver function/process */
     di->pid = dnsrv_fork_and_capture(dnsrv_child_main, di);
     return NULL;
}

/* callback for walking the connecting hash tree */
void _dnsrv_beat_packets(xht h, const char *key, void *data, void *arg)
{
    dns_io di = (dns_io)arg;
    dns_packet_list n, l = (dns_packet_list)data;
    int now = time(NULL);
    int reap = 0;

    /* first, check the head */
    if((now - l->stamp) > di->packet_timeout)
    {
        log_notice(l->packet->host,"timed out from dnsrv queue");
        xhash_zap(di->packet_table,l->packet->host);
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
                break;
            }
            l = l->next;
        }
    }

    if(reap == 0) return;

    /* time out individual queue'd packets */
    while(l != NULL)
    {
        n = l->next;
        deliver_fail(l->packet,"Hostname Resolution Timeout");
        l = n;
    }
}

result dnsrv_beat_packets(void *arg)
{
    dns_io di = (dns_io)arg;
    xhash_walk(di->packet_table,_dnsrv_beat_packets,arg);
    return r_DONE;
}


void dnsrv(instance i, xmlnode x)
{
     xdbcache xc = NULL;
     xmlnode  config = NULL;
     xmlnode  iternode = NULL;
     xmlnode  inneriter = NULL;
     dns_resend_list tmplist = NULL;
     dns_resend_list_host_list tmphost = NULL;

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
	  tmplist->weight_sum = 0;

	  /* check for <partial/> childs */
	  inneriter = xmlnode_get_lastchild(iternode);
	  if (inneriter != NULL) {
	      while (inneriter != NULL) {
		  if (j_strcmp("partial", xmlnode_get_name(inneriter)) != 0) {
		      inneriter = xmlnode_get_prevsibling(inneriter);
		      continue;
		  }

		  /* build the list entry for this host */
		  tmphost = pmalloco(di->mempool, sizeof(_dns_resend_list_host_list));
		  tmphost->host = pstrdup(di->mempool, xmlnode_get_data(inneriter));
		  tmphost->weight = j_atoi(xmlnode_get_attrib(inneriter, "weight"), 1);

		  /* insert this host into the list for this service */
		  tmphost->next = tmplist->hosts;
		  tmplist->hosts = tmphost;

		  /* update the weight sum for this service */
		  tmplist->weight_sum += tmphost->weight;

		  /* move to the next child */
		  inneriter = xmlnode_get_prevsibling(inneriter);
	      }
	  }

	  /* if there were no <partial/> childs we read the CDATA for the <resend/> element (legacy configuration) */
	  if (tmplist->hosts == NULL) {
	      /* legacy configuration withouth <partial/> childs and only a single destination as direct CDATA */
	      tmplist->hosts = pmalloco(di->mempool, sizeof(_dns_resend_list_host_list));
	      tmplist->hosts->host = pstrdup(di->mempool, xmlnode_get_data(iternode));
	      tmplist->hosts->weight = 1;
	      tmplist->weight_sum = 1;
	  }

	  /* Insert this node into the list of services */
	  tmplist->next = di->svclist;	  
	  di->svclist = tmplist;
	  /* Move to next child */
	  iternode = xmlnode_get_prevsibling(iternode);
     }
     log_debug2(ZONE, LOGT_INIT|LOGT_CONFIG, "dnsrv debug: %s\n", xmlnode2str(config));

     /* Setup the hash of dns_packet_list */
     di->packet_table = xhash_new(j_atoi(xmlnode_get_attrib(config,"queuemax"),101));
     pool_cleanup(i->p, (pool_cleaner)xhash_free, di->packet_table);
     di->packet_timeout = j_atoi(xmlnode_get_attrib(config,"queuetimeout"),60);
     register_beat(di->packet_timeout, dnsrv_beat_packets, (void *)di);


     /* Setup the internal hostname cache */
     di->cache_table = xhash_new(j_atoi(xmlnode_get_attrib(config,"cachemax"),1999));
     pool_cleanup(i->p, (pool_cleaner)xhash_free, di->cache_table);
     di->cache_timeout = j_atoi(xmlnode_get_attrib(config,"cachetimeout"),3600); /* 1 hour dns cache? XXX would be nice to get the right value from dns! */

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
}
