#include "jabberd.h"

/* register a function to handle delivery for this idnode */
void hdreg(idnode id, order o, hdgene f, void *arg)
{
    /* make a handel and store it in this idnode, ordered correctly */
}

/* internal struct to store a list of idnodes based on hostname */
/* three, for log, xdb, and normal (session is same idnodes as normal) */

/* register an idnode into the delivery tree */
void idreg(ptype type, char *host, idnode id)
{

    /* store idnode in internal struct for that ptype */
    id->flag_used++;
}

void deliver(dpacket p)
{
    /* based on type, pick idnode list, match and copy to idnodes based on hostname, bounce if fail and print error */
}
