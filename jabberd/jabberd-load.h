/**** These are utility symbols for dynamically loaded jabberd extensions ****/

typedef struct instance_struct *instance, _instance;

typedef result (*phandler)(xmlnode x, void *arg);

void packet_handler(instance i, phandler f, void *arg); /* registers function and arg to handle incoming packets */

xmlnode xdb_get(instance i, char *host, jid to, char *ns); /* blocks until namespace is retrieved, host must map back to this service! */
int xdb_set(instance i, char *host, jid to, xmlnode data); /* sends new xml to replace old */

