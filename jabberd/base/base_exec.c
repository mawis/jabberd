#include "jabberd.h"

/* consult apache source to figure out how to do this */
/* fork/exec a command, serialize xmlnodes to its STDIN for incoming packets, read it's STDOUT as an xmlstream */

/* something along the lines of:
   int pid;
   int status;
   if((pid=fork())<0)
      log_error(ZONE,"failed to fork");
   else if(pid==0)
   { // child process
     execlp(filename,filename,(char*)0);
     exit(127);
   }
   // parent
   if((pid=waitpid(pid,&status,0))<0)
     log_error(ZONE,"wait_pid err??");
   if(status==127)
     log_error(ZONE,"child process died, restart it");

     but that will make the whole jabberd block on the child process won't it?  *shrug* well, that's just a start, I don't *really* know what I'm doing.. =]
    */ 

result base_exec_config(instance id, xmlnode x, void *arg)
{
    if(id == NULL)
    {
        printf("base_exec_config validating configuration\n");
        return r_PASS;
    }

    printf("base_exec_config performing configuration %s\n",xmlnode2str(x));
}

void base_exec(void)
{
    printf("base_exec loading...\n");

    register_config("exec",base_exec_config,NULL);
}
