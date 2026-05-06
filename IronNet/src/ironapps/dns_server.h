#ifndef IRON_DNS_SERVER_H
#define IRON_DNS_SERVER_H

#include <stdint.h>

int dns_server_start(void);

/* For testing: lookup a name in the zone table, returns IP or 0 */
uint32_t dns_zone_lookup(const char *name);

/* For testing: add/overwrite a zone entry */
void dns_zone_add(const char *name, uint32_t ip);

#endif /* IRON_DNS_SERVER_H */
