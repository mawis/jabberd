#include "jabberd.h"

/* ---------------------------------------------------------
   base_exec - Starts a specified coprocess and exchanges 
               xmlnodes with it via piped IO

   General Theory:
     For each call to base_exec_config:
     - Create a new thread
     - In the new thread, create two pipes
     - Fork and exec the new process

   Questions:
     - How does the child process recover when the pipe gets
       borken from the server shutting down?
   ---------------------------------------------------------*/

typedef struct
{
     pool     p;
     instance i;
     int      stdin;
     int      stdout;
} *exe_info, _exe_info;

int exec_and_capture(const char* exe, int* in, int* out)
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
	  return 0;
     }
     else			/* Child */
     {
	  /* Close unneeded file handles */
	  close(left_fds[STDOUT_FILENO]);
	  close(right_fds[STDIN_FILENO]);
	  /* Map left's STDIN to the child's STDIN */
	  if (left_fds[STDIN_FILENO] != STDIN_FILENO)
	  {
	       dup2(left_fds[STDIN_FILENO], STDIN_FILENO);
	       close(left_fds[STDIN_FILENO]);
	  }
	  /* Map right's STDOUT to the child's STDOUT */
	  if (right_fds[STDOUT_FILENO] != STDOUT_FILENO)
	  {
	       dup2(right_fds[STDOUT_FILENO], STDOUT_FILENO);
	       close(right_fds[STDOUT_FILENO]);
	  }
	  /* Execute another process */
	  if( execl(exe, exe, (char*) 0) < 0)
	       exit(1);
     }
}

/* Deliver packets to the coprocess*/
result base_exec_deliver(instance i, dpacket p, void* args)
{
     int result = 0;
     char* rawxml = NULL;
     exe_info ei = (exe_info)args;

     /* Serialize the node in the dpacket */
     rawxml = xmlnode2str(p->x);

     printf("base_exec_deliver: %s\n", rawxml);

     /* FIXME : this is a blocking write...no ability to queue up data properly */
     /* Write the raw data to the child process */
     result = pth_write(ei->stdout, (void*)rawxml, strlen(rawxml));
     if (result < 0)
     {
	  /* If the pipe is broken, go ahead and unregister this handler */
	  if (errno == EPIPE)
	  {
	       close(ei->stdout);
	       close(ei->stdin);
	       return r_UNREG;
	  }
	  /* Otherwise, return a general error */
	  else
	       return r_ERR;
     }
     return r_OK;          
}

void base_exec_handle_xstream_event(int type, xmlnode x, void* arg)
{
     exe_info ei = (exe_info)arg;

     switch(type)
     {
     case XSTREAM_ROOT:
	  /* Validate namespace */
	  break;
     case XSTREAM_NODE:
	  /* Deliver the packet */
	  deliver(dpacket_new(x), ei->i);
	  break;
     case XSTREAM_CLOSE:
     case XSTREAM_ERR:
	  /* Who knows? The _SHADOW_ knows. */
     }

}

/* Process incoming data from the coprocess */
void* base_exec_process_io(void* threadarg)
{
     xstream  xs;
     exe_info ei = (exe_info)threadarg;
     int len = 0;
     char buf[1024];

     /* Allocate a xstream for this coprocess */
     xs = xstream_new(ei->p, base_exec_handle_xstream_event, threadarg);

     /* Read from the coprocess until we get an error */
     while(1)
     {
	  len = pth_read(ei->stdin, buf, sizeof(buf));
	  if (len < 0)
	       break;
	  if (xstream_eat(xs, buf, len) > XSTREAM_NODE)
	       break;
     }

     /* Cleanup and quit...should be error handling here? */
     close(ei->stdout);
     close(ei->stdin);
}

result base_exec_config(instance id, xmlnode x, void *arg)
{
    char* exe_name = NULL;
    int   stdin, stdout;
    exe_info ei;
	  
    if(id == NULL)
    {	 
        printf("base_exec_config validating configuration\n");
        return r_PASS;
    }

    /* Get the executable name from the xmlnode */
    exe_name = xmlnode_get_data(x);
    
    /* Exec and capture the STDIN/STDOUT of the child process */
    exec_and_capture(exe_name, &stdin, &stdout);

    /* Allocate a info structure, and associate with the
       instance pool */
    ei = pmalloc(id->p, sizeof(_exe_info));
    ei->i       = id;
    ei->p       = id->p;
    ei->stdin   = stdin;
    ei->stdout  = stdout;

    /* Spawn a new thread to handle IO for this coprocess */
    pth_spawn(PTH_ATTR_DEFAULT, base_exec_process_io, (void*) ei);

    /* Register a handler to recieve inbound data */
    register_phandler(id, o_DELIVER, base_exec_deliver, (void*) ei);

    printf("base_exec_config performing configuration %s\n",xmlnode2str(x));
}

void base_exec(void)
{
    printf("base_exec loading...\n");

    register_config("exec",base_exec_config,NULL);
}
