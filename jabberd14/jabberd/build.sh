gcc -g -c *.c */*.c -DCONFIGXML="\"./jabberd.xml\"" -I. -I/opt/jabber-1.0/include
gcc -g -o jabberd *.o -lpth -ljabber -lxode -ldl -L/opt/jabber-1.0/lib
