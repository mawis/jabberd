gcc -c *.c */*.c -DCONFIGXML="\"./jabberd.xml\"" -I.
gcc -o jabberd *.o -lpth -ljabber -lxode -ldl
