#include "jabberd.h"

/* 

to compile:

   gcc -fPIC -shared -o test.so test.c -I../src

jabberd.xml:

  <service id="test section">
    <host>test</host>
    <load><test>../load/test.so</test></load>
    <testing xmlns="test"><a>foo</a>bar</testing>
  </service>

*/

void test(instance i, xmlnode x)
{
    xmlnode config;
    xdbcache xc;

    log_debug(ZONE,"lala, test loading!");

    xc = xdb_cache(i);
    config = xdb_get(xc, NULL, jid_new(xmlnode_pool(x),"config@-internal"),"test");

    log_debug(ZONE,"test loaded, got config %s",xmlnode2str(config));

}
