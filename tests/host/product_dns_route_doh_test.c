/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_route.h"
#include <assert.h>
#include <stdio.h>

static sakamoto_product_dns_config_t config(const char *host, const char *path, unsigned family)
{
  sakamoto_product_dns_config_t c;
  memset(&c, 0, sizeof(c));
  c.enabled = 1; c.endpoint_count = 1; c.route_count = 1;
  c.routes[0].count = 1;
  sakamoto_product_dns_endpoint_t *e = &c.endpoints[0];
  e->transport = 4; e->port = 443; e->family = family;
  if (family == 4) { e->address[0] = 192; e->address[3] = 53; }
  size_t n = strlen(host);
  memcpy(e->identity, host, n);
  if (path) memcpy(e->identity + n + 1, path, strlen(path));
  c.family = e->family; c.port = e->port; memcpy(c.address, e->address, 16);
  return c;
}

int main(void)
{
  sakamoto_product_dns_config_t c = config("dns.test", "/dns-query", 4);
  assert(product_dns_route_valid(&c));
  c = config("dns.test", "/dns-query?x=1", 0);   /* original-network bootstrap */
  assert(product_dns_route_valid(&c));
  c = config("2001:db8::53", "/q", 6);
  c.endpoints[0].address[0] = 0x20; c.endpoints[0].address[1] = 0x01; c.endpoints[0].address[2] = 0x0d;
  c.endpoints[0].address[3] = 0xb8; c.endpoints[0].address[15] = 0x53;
  memcpy(c.address, c.endpoints[0].address, 16);
  assert(product_dns_route_valid(&c));

  c = config("dns.test", NULL, 4);                  /* path required */
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", "dns-query", 4);           /* origin form only */
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", "/a#fragment", 4);
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", "/a b", 4);
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", "/a\\b", 4);
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", "/dns-query", 4);
  c.endpoints[0].identity[sizeof(c.endpoints[0].identity) - 1] = 'x';   /* no terminating NUL */
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", "/dns-query", 4);
  c.endpoints[0].identity[40] = 'x';                                    /* junk after the path */
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", "/dns-query", 4);
  c.endpoints[0].reserved = 1;
  assert(!product_dns_route_valid(&c));

  /* Other transports keep the old identity-only shape: no embedded path. */
  c = config("dns.test", "/dns-query", 4);
  c.endpoints[0].transport = 3;
  assert(!product_dns_route_valid(&c));
  c = config("dns.test", NULL, 4);
  c.endpoints[0].transport = 3;
  assert(product_dns_route_valid(&c));
  c = config("dns.test", NULL, 4);
  c.endpoints[0].transport = 5;
  assert(!product_dns_route_valid(&c));

  char long_path[300];
  memset(long_path, 'a', sizeof(long_path)); long_path[0] = '/'; long_path[299] = 0;
  c = config("dns.test", long_path, 4);             /* host + path above the 255-byte identity */
  assert(!product_dns_route_valid(&c));
  puts("DoH endpoint identity validation PASS");
  return 0;
}
