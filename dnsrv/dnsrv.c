#include <libxode.h>

typedef int (*RESOLVEFUNC)(int in, int out);

/* --------------------------------------- */
/* Struct to keep track of a DNS coprocess */
typedef struct _dns_io
{
     int           in;		 /* Inbound data handle */
     int           out;		 /* Outbound data handle */
     pth_message_t write_queue;
} *dns_io;


/* --------------------------------------------------- */
/* Struct to store a dpacket that needs to be resolved */
typedef struct
{
     pth_message_t head;
     dpacket       packet;
} *dns_write_buf;


/* ----------------------------------------------------------- */
/* Struct to store list of dpackets which need to be delivered */
typedef struct _dns_packet_list
{
     dpacket           packet;
     _dns_packet_list* next;
} *dns_packet_list;


int dns_fork_and_capture(RESOLVEFUNC f, int* in, int* out)
{
     int left_fds[2], right_fds[2];
     int pid;

     /* Create left and right pipes */
     if (pipe(left_fds) < 0 || pipe(right_fds) < 0)
	  return r_ERR;

     pid = fork();
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

void dns_process_io(void* threadarg)
{
     dns_io di = (dns_io)threadarg;
}

int dnsrv_resolve_main(int in, int out)
{

}

void dnsrv(instance i, xmlnode x)
{
     /* Setup a struct to hold dns_io handles */
     dns_io di;
     di = pmalloco(i->p, sizeof(_dns_io));

     /* Initialize a message port to handle incoming dpackets */
     di->write_queue = pth_msgport_create(i->id);

     /* Fork out resolver function/process */
     dns_fork_and_capture(dnsrv_resolve_main, &(di->in), &(di->out));

     /* Start IO thread */
     pth_spawn(PTH_ATTR_DEFAULT, dnsrv_process_io, di);

     /* Register an incoming packet handler */
     register_phandler(id, o_DELIVER, dns_process_io, (void*)di);
}
