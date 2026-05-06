#ifndef IRON_DNS_SERVER_H
#define IRON_DNS_SERVER_H

#include <stdint.h>

int dns_server_start(void);

/* For testing: lookup a name in the zone table, returns IP or 0 */
uint32_t dns_zone_lookup(const char *name);

/* For testing: add/overwrite a zone entry */
void dns_zone_add(const char *name, uint32_t ip);

/* DNS cache */
void dns_cache_add(const char *name, uint32_t ip, int ttl_sec);
int  dns_cache_add_secure(const char *name, uint32_t ip, int ttl_sec);
void dns_cache_flush(void);
void dns_cache_dump(void);

#endif /* IRON_DNS_SERVER_H */
