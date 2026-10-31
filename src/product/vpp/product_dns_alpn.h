/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_DNS_ALPN_H
#define PRODUCT_DNS_ALPN_H
/* DoH ALPN outcome shared by the TLS transport and the normal observation.
 * Only "http/1.1" is ever offered; HTTP/2-only endpoints are not qualified. */
enum { PRODUCT_DNS_ALPN_NONE = 0,   /* not DoH, or no negotiation yet */
       PRODUCT_DNS_ALPN_HTTP11 = 1, /* server selected http/1.1 */
       PRODUCT_DNS_ALPN_ABSENT = 2, /* server omitted ALPN; HTTP/1.1 attempted */
       PRODUCT_DNS_ALPN_REFUSED = 3 /* no mutual protocol (e.g. HTTP/2-only) */ };
#endif
