gcc -c *.c -DCONFIGXML="\"./jabberd.xml\""
gcc -o jabberd *.o -lpth -ljabber -lxode
