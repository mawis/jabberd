#ifndef __HMAC_HH
#define __HMAC_HH

void hmac_sha1_ascii_r(char const *secret, unsigned char const *message,
                       size_t len, char hmac[41]);

#endif // __HMAC_HH
