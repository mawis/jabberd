#include "jabberd.h"

/***************************************************************************
 * This can return whatever we need, it is just designed to read a xmlnode
 * and hash the SSL contexts it creates from the keys in the node
 *
 * Sample node:
 * <ssl>
 *   <key hostname='jabber.org'>/path/to/the/key/file.pem</key>
 *   <key hostname='box5.net'>/path/to/the/key/file.pem</key>
 * </ssl>   
 **************************************************************************/
void mio_ssl_init(xmlnode x)
{
/* PSEUDO CODE

  for $key in children(xmlnode x)
  {
      - SSL init
      - Load key into SSL ctx
      - Hash ctx based on hostname
  }

  register a cleanup function to free our contexts
*/

int _mio_ssl_read(mio m)
{
    /* PSEUDO
     Return the SSL_read call
    */
}

ssize_t _mio_ssl_write(int fd, const void *buf, size_t count)
{
    /* PSEUDO
     Return the SSL_write call
    */
}

int _mio_ssl_accept(int fd, struct sockaddr * serv_addr, socklen_t *addrlen)
{
    /* PSEUDO
     Check the context validity
     SSL_set_fd(ctx, fd);
     SSL_set_accept_state(ssl);
     ERROR_CHECKING(SSL_accpet(ssl));
    */
}

int _mio_ssl_connect(int fd, struct sockaddr *serv_addr, socklen_t addrlen)
{
    /* PSEUDO
     I need to actually look this one up, but I assume it's similar to the
       SSL accept stuff.
    */
}
