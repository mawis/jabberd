#include "jabberd.h"

extern xmlnode greymatter;

/* load all base modules */
void loader(void)
{
    /* call static modules */
    /* gen_foo(); io_foo(); ... */

    /* load dynamic modules */
    /* look for <base>/foo.so</base> in greymatter and load */
}
