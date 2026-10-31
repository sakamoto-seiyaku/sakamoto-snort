/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_root_dns_io.h"
#include "product_dns_route.h"
#include "product_dns_tls.h"
#include "product_dns_bootstrap.h"
#include "product_dns_http.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/random.h>
#include <unistd.h>

typedef struct {
  product_dns_proxy_key_t key;
  uint16_t id;
  uint8_t active, channel;
  uint8_t *pending; size_t length; uint64_t deadline;
} udp_request_t;
typedef struct {
  product_dns_proxy_key_t key;
  uint64_t cookie, deadline, progress_due;
  int fd;
  struct sockaddr_storage resolver;
  socklen_t resolver_length;
  uint8_t connecting, authorized, header[2];
  uint8_t *output, *input;
  size_t output_length, output_at, input_length, input_at, header_at;
  product_dns_tls_t *tls;
  product_dns_http_response_t *http; /* DoH response parser; body lands in input */
  uint8_t transport, verified;
  uint8_t bootstrap, bootstrap_type, bootstrap_retried;
  uint8_t bootstrap_address_count, bootstrap_address_at;
  product_dns_bootstrap_address_t bootstrap_addresses[PRODUCT_DNS_BOOTSTRAP_ADDRESSES];
  uint64_t bootstrap_retry;
  uint8_t bootstrap_wire[PRODUCT_DNS_BOOTSTRAP_QUERY_BYTES+2];
  size_t bootstrap_length, bootstrap_at;
  product_dns_proxy_io_event_t progress;
} tcp_socket_t;
#define ROOT_DNS_UPSTREAM_SOCKETS (PRODUCT_DNS_PROXY_SOCKETS - 2U)
typedef struct {
  uint64_t cookie, last_activity;
  int fd;
  struct sockaddr_storage resolver;
  socklen_t resolver_length;
  uint8_t authorized;
} udp_socket_t;
struct product_root_dns_io {
  uint64_t generation;
  uint64_t *sequence;
  uint32_t mark;
  size_t pending_bytes;
  struct sockaddr_storage resolver;
  socklen_t resolver_length;
  product_root_dns_io_callbacks_t callbacks;
  void *context;
  product_root_dns_io_status_t status;
  product_dns_proxy_route_t route;
  product_dns_tls_owner_t *tls;
  udp_socket_t channels[ROOT_DNS_UPSTREAM_SOCKETS];
  udp_request_t udp[PRODUCT_DNS_PROXY_TRANSACTIONS];
  tcp_socket_t tcp[PRODUCT_ROOT_DNS_TCP_SOCKETS];
  uint8_t received[PRODUCT_DNS_MESSAGE_MAX];
};
static int selected_address(product_root_dns_io_t *,const product_dns_proxy_key_t *,
  struct sockaddr_storage *,socklen_t *);

static uint64_t ordinary_reservation (void)
{
  return sizeof (product_root_dns_io_t) + PRODUCT_ROOT_DNS_TCP_SOCKETS *
    (2U * PRODUCT_DNS_MESSAGE_MAX + 2U) +
    PRODUCT_DNS_MESSAGE_MAX;
}
static int encrypted_transport(unsigned transport)
{return transport==PRODUCT_DNS_PROXY_DOT||transport==PRODUCT_DNS_PROXY_DOH;}
static uint64_t encrypted_reservation(int doh)
{
  return ordinary_reservation()+product_dns_tls_reservation(PRODUCT_ROOT_DNS_TCP_SOCKETS)+
    (doh?(uint64_t)PRODUCT_ROOT_DNS_TCP_SOCKETS*sizeof(product_dns_http_response_t):0);
}
uint64_t product_root_dns_io_reservation (void)
{return encrypted_reservation(1);}
uint64_t product_root_dns_io_config_reservation (const product_dns_proxy_route_t *route)
{
  int encrypted=0,doh=0;
  for(unsigned i=0;route&&i<route->endpoint_count;++i){
    encrypted|=encrypted_transport(route->endpoints[i].transport);
    doh|=route->endpoints[i].transport==PRODUCT_DNS_PROXY_DOH;
  }
  return encrypted?encrypted_reservation(doh):ordinary_reservation();
}

static int same_key (const product_dns_proxy_key_t *a, const product_dns_proxy_key_t *b)
{ return !memcmp (a, b, sizeof (*a)); }

static void allocation (product_root_dns_io_t *io, size_t bytes)
{
  io->status.allocated_bytes += bytes;
  if (io->status.allocated_bytes > io->status.high_water_bytes)
    io->status.high_water_bytes = io->status.allocated_bytes;
}

static int new_socket (product_root_dns_io_t *io, unsigned family, unsigned type, uint64_t *cookie)
{
  if (io->status.sockets >= ROOT_DNS_UPSTREAM_SOCKETS) { ++io->status.capacity; return -2; }
  if (*io->sequence == (UINT64_C(1) << 42) - 1) return -1;
  int fd = socket (family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  if (io->mark && setsockopt (fd, SOL_SOCKET, SO_MARK, &io->mark, sizeof (io->mark)))
    { close (fd); return -1; }
  *cookie = ++*io->sequence;
  ++io->status.sockets; ++io->status.opened;
  if (io->status.sockets > io->status.high_water_sockets)
    io->status.high_water_sockets = io->status.sockets;
  return fd;
}

static void close_socket (product_root_dns_io_t *io, int *fd, uint64_t cookie)
{
  if (*fd < 0) return;
  int owned = *fd; *fd = -1;
  (void) io->callbacks.watch (io->context, owned, 0, cookie);
  close (owned); --io->status.sockets; ++io->status.closed;
}

static void close_tcp (product_root_dns_io_t *io, tcp_socket_t *tcp)
{
  product_dns_tls_close(tcp->tls);
  close_socket (io, &tcp->fd, tcp->cookie);
  io->status.allocated_bytes -= tcp->output_length + tcp->input_length;
  if (tcp->http) io->status.allocated_bytes -= sizeof (*tcp->http);
  free (tcp->output); free (tcp->input); free (tcp->http);
  memset (tcp, 0, sizeof (*tcp)); tcp->fd = -1;
}

static void progress(product_root_dns_io_t *io,tcp_socket_t *tcp)
{
  if(encrypted_transport(tcp->transport)&&io->callbacks.progress)
    io->callbacks.progress(io->context,&tcp->key,&tcp->progress);
}

static int open_tcp_socket(product_root_dns_io_t *io,tcp_socket_t *tcp,unsigned type)
{
  tcp->fd=new_socket(io,tcp->resolver.ss_family,type,&tcp->cookie);
  if(tcp->fd<0){int result=tcp->fd==-2?0:-1;tcp->progress.error=result?-errno:-ENFILE;tcp->fd=-1;return result;}
  if(tcp->bootstrap&&io->mark){
    char name[IF_NAMESIZE];
    if(!if_indextoname(tcp->progress.bootstrap_ifindex,name)||
      setsockopt(tcp->fd,SOL_SOCKET,SO_BINDTODEVICE,name,strlen(name)+1)){
      tcp->progress.bootstrap=PRODUCT_DNS_BOOTSTRAP_FAILED;tcp->progress.error=-errno;return -1;
    }
  }
  tcp->authorized=!io->callbacks.authorize;
  tcp->progress.authorization=tcp->authorized?PRODUCT_DNS_AUTHORIZATION_GRANTED:PRODUCT_DNS_AUTHORIZATION_PENDING;
  if(!tcp->bootstrap&&encrypted_transport(tcp->transport)){
    const sakamoto_product_dns_endpoint_t *endpoint=&io->route.endpoints[tcp->key.resolver_id-1];
    tcp->tls=tcp->transport==PRODUCT_DNS_PROXY_DOH
      ?product_dns_tls_open_doh(io->tls,tcp->fd,(const char *)endpoint->identity)
      :product_dns_tls_open(io->tls,tcp->fd,(const char *)endpoint->identity);
    if(!tcp->tls){tcp->progress.tls=PRODUCT_DNS_TLS_FAILED;tcp->progress.error=-ENOMEM;progress(io,tcp);return -1;}
    ++io->status.tls_started;
  }
  progress(io,tcp);
  if(io->callbacks.authorize){
    if(!io->callbacks.authorize(io->context,tcp->fd,tcp->cookie))return 1;
    tcp->progress.authorization=PRODUCT_DNS_AUTHORIZATION_FAILED;tcp->progress.error=-EACCES;
    progress(io,tcp);return -1;
  }
  int result=connect(tcp->fd,(struct sockaddr *)&tcp->resolver,tcp->resolver_length);
  if(result&&(type!=SOCK_STREAM||errno!=EINPROGRESS)){tcp->progress.error=-errno;return -1;}
  tcp->connecting=result!=0;
  return io->callbacks.watch(io->context,tcp->fd,PRODUCT_ROOT_DNS_READ|PRODUCT_ROOT_DNS_WRITE,tcp->cookie)?1:-1;
}

static int bootstrap_question(product_root_dns_io_t *io,tcp_socket_t *tcp,unsigned type)
{
  uint16_t id;
  if(getrandom(&id,sizeof(id),GRND_NONBLOCK)!=sizeof(id))return 0;
  const char *identity=(const char *)io->route.endpoints[tcp->key.resolver_id-1].identity;
  size_t length=0;
  if(!product_dns_bootstrap_query(identity,id,type,tcp->bootstrap_wire+2,&length))return 0;
  tcp->bootstrap_wire[0]=length>>8;tcp->bootstrap_wire[1]=length;
  tcp->bootstrap_length=length+2;tcp->bootstrap_at=0;tcp->bootstrap_type=type;
  tcp->bootstrap_retried=0;tcp->bootstrap_retry=0;
  ++io->status.bootstrap_started;return 1;
}

static int start_bootstrap(product_root_dns_io_t *io,tcp_socket_t *tcp,unsigned type)
{
  product_root_dns_network_t network={0};
  tcp->progress.bootstrap=PRODUCT_DNS_BOOTSTRAP_PENDING;
  tcp->progress.tls=PRODUCT_DNS_TLS_NONE;tcp->progress.error=0;
  if(!io->callbacks.bootstrap_network||!io->callbacks.bootstrap_network(io->context,&network)||
      (network.family!=4&&network.family!=6)||!network.port||network.port>UINT16_MAX||
      (io->mark&&!network.ifindex)){
    tcp->progress.bootstrap=PRODUCT_DNS_BOOTSTRAP_FAILED;tcp->progress.error=-ENETUNREACH;
    progress(io,tcp);return -1;
  }
  product_dns_proxy_key_t resolver={.resolver_family=network.family,.resolver_port=network.port};
  memcpy(resolver.resolver_address,network.address,16);
  if(!selected_address(io,&resolver,&tcp->resolver,&tcp->resolver_length))return -1;
  if(network.family==6&&network.address[0]==0xfe&&(network.address[1]&0xc0)==0x80){
    if(!network.ifindex)return -1;
    ((struct sockaddr_in6 *)&tcp->resolver)->sin6_scope_id=network.ifindex;
  }
  tcp->progress.bootstrap_family=network.family;tcp->progress.bootstrap_port=network.port;
  tcp->progress.bootstrap_ifindex=network.ifindex;memcpy(tcp->progress.bootstrap_address,network.address,16);
  tcp->bootstrap=1;
  if(!bootstrap_question(io,tcp,type))return -1;
  return open_tcp_socket(io,tcp,SOCK_DGRAM);
}

static int same_address (const struct sockaddr_storage *a, socklen_t alen,
  const struct sockaddr_storage *b, socklen_t blen)
{ return alen == blen && !memcmp (a, b, alen); }

static int selected_address (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  struct sockaddr_storage *resolver, socklen_t *length)
{
  memset (resolver, 0, sizeof (*resolver));
  if (!key || !key->resolver_family) { *resolver = io->resolver; *length = io->resolver_length; return 1; }
  if (!key->resolver_port || key->resolver_port > UINT16_MAX) return 0;
  if (key->resolver_family == 4)
    {
      struct sockaddr_in *a = (struct sockaddr_in *) resolver;
      a->sin_family = AF_INET; a->sin_port = htons (key->resolver_port);
      memcpy (&a->sin_addr, key->resolver_address, 4); *length = sizeof (*a); return 1;
    }
  if (key->resolver_family == 6)
    {
      struct sockaddr_in6 *a = (struct sockaddr_in6 *) resolver;
      a->sin6_family = AF_INET6; a->sin6_port = htons (key->resolver_port);
      memcpy (&a->sin6_addr, key->resolver_address, 16); *length = sizeof (*a); return 1;
    }
  return 0;
}

static int udp_default (const product_root_dns_io_t *io, const udp_socket_t *channel)
{ return same_address (&io->resolver, io->resolver_length, &channel->resolver, channel->resolver_length); }
static int udp_busy (const product_root_dns_io_t *io, unsigned channel)
{
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active && io->udp[i].channel == channel) return 1;
  return 0;
}
static void close_udp (product_root_dns_io_t *io, udp_socket_t *channel, int failed)
{
  int is_default = udp_default (io, channel), authorized = channel->authorized;
  close_socket (io, &channel->fd, channel->cookie);
  channel->authorized = 0;
  if (is_default) io->status.udp_state = !failed && authorized
    ? PRODUCT_ROOT_DNS_UDP_IDLE : PRODUCT_ROOT_DNS_UDP_FAILED;
}

static udp_socket_t *open_udp (product_root_dns_io_t *io, const struct sockaddr_storage *resolver,
  socklen_t length, uint64_t now, int *result)
{
  *result = -1;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd >= 0 && same_address (&io->channels[i].resolver,
          io->channels[i].resolver_length, resolver, length)) { *result = 1; return &io->channels[i]; }
  if (io->status.sockets >= ROOT_DNS_UPSTREAM_SOCKETS)
    {
      udp_socket_t *oldest = NULL;
      for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
        if (io->channels[i].fd >= 0 && !udp_busy (io, i) &&
            (!oldest || io->channels[i].last_activity < oldest->last_activity)) oldest = &io->channels[i];
      if (!oldest) { ++io->status.capacity; *result = 0; return NULL; }
      close_udp (io, oldest, 0);
    }
  udp_socket_t *channel = NULL;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd < 0) { channel = &io->channels[i]; break; }
  if (!channel) { ++io->status.capacity; *result = 0; return NULL; }
  *channel = (udp_socket_t) {.fd = -1, .resolver = *resolver, .resolver_length = length, .last_activity = now};
  if (udp_default (io, channel)) io->status.udp_state = PRODUCT_ROOT_DNS_UDP_AUTHORIZING;
  channel->fd = new_socket (io, resolver->ss_family, SOCK_DGRAM, &channel->cookie);
  if (channel->fd < 0) { *result = channel->fd == -2 ? 0 : -1; channel->fd = -1; close_udp (io, channel, 1); return NULL; }
  channel->authorized = !io->callbacks.authorize;
  if (io->callbacks.authorize)
    {
      if (io->callbacks.authorize (io->context, channel->fd, channel->cookie))
        { close_udp (io, channel, 1); return NULL; }
      *result = 1; return channel;
    }
  if (connect (channel->fd, (const struct sockaddr *) resolver, length) ||
      !io->callbacks.watch (io->context, channel->fd, PRODUCT_ROOT_DNS_READ, channel->cookie))
    { close_udp (io, channel, 1); return NULL; }
  if (udp_default (io, channel)) io->status.udp_state = PRODUCT_ROOT_DNS_UDP_AUTHORIZED;
  *result = 1; return channel;
}

product_root_dns_io_t *product_root_dns_io_open (uint64_t generation,
  const product_dns_proxy_route_t *route, uint32_t mark, uint64_t *sequence,
  const product_root_dns_io_callbacks_t *callbacks, void *context, uint64_t now)
{
  if (!generation || !product_dns_route_valid (route) || !route->enabled || !sequence ||
      !callbacks || !callbacks->watch || !callbacks->answer || !callbacks->failed) return NULL;
  product_root_dns_io_t *io = calloc (1, sizeof (*io));
  if (!io) return NULL;
  io->generation = generation; io->mark = mark; io->sequence = sequence;
  io->route = *route;
  io->callbacks = *callbacks; io->context = context;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i) io->channels[i].fd = -1;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i) io->tcp[i].fd = -1;
  product_dns_proxy_key_t key = {.resolver_family = route->family, .resolver_port = route->port};
  memcpy (key.resolver_address, route->address, 16);
  if (!selected_address (io, &key, &io->resolver, &io->resolver_length)) { free (io); return NULL; }
  allocation (io, sizeof (*io));
  int result;
  int first_dot=route->endpoint_count&&encrypted_transport(route->endpoints[route->routes[0].candidates[0]].transport);
  for(unsigned i=0;i<route->endpoint_count;++i)
    if(encrypted_transport(route->endpoints[i].transport)){
      io->tls=product_dns_tls_owner_open(callbacks->trust_directory);break;
    }
  if (!first_dot&&!open_udp (io, &io->resolver, io->resolver_length, now, &result) && !route->endpoint_count)
    { product_root_dns_io_close (io); return NULL; }
  return io;
}

void product_root_dns_io_cancel (product_root_dns_io_t *io, const product_dns_proxy_key_t *key)
{
  if (!io || !key) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active && same_key (&io->udp[i].key, key))
      { io->status.allocated_bytes -= io->udp[i].length; io->pending_bytes -= io->udp[i].length; free (io->udp[i].pending);
        memset (&io->udp[i], 0, sizeof (io->udp[i])); --io->status.requests; }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd >= 0 && same_key (&io->tcp[i].key, key)) close_tcp (io, &io->tcp[i]);
}

void product_root_dns_io_close (product_root_dns_io_t *io)
{
  if (!io) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i) free (io->udp[i].pending);
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i) close_tcp (io, &io->tcp[i]);
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    close_socket (io, &io->channels[i].fd, io->channels[i].cookie);
  product_dns_tls_owner_close(io->tls);
  free (io);
}

static int send_udp (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  const uint8_t *wire, size_t length, uint64_t deadline, uint64_t now)
{
  struct sockaddr_storage resolver; socklen_t resolver_length;
  if (!selected_address (io, key, &resolver, &resolver_length)) return -1;
  int opened;
  udp_socket_t *channel = open_udp (io, &resolver, resolver_length, now, &opened);
  if (!channel) return opened;
  unsigned index = channel - io->channels;
  uint16_t id = ((uint16_t) wire[0] << 8) | wire[1];
  udp_request_t *request = NULL;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
    if (io->udp[i].active)
      {
        if (same_key (&io->udp[i].key, key)) request = &io->udp[i];
        else if (io->udp[i].channel == index && io->udp[i].id == id) return -1;
      }
  if (!request)
    for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
      if (!io->udp[i].active) { request = &io->udp[i]; break; }
  if (!request) { ++io->status.capacity; return 0; }
  if (!channel->authorized)
    {
      if (request->pending) return 1;
      if (length > PRODUCT_DNS_MESSAGE_MAX - io->pending_bytes) { ++io->status.capacity; return 0; }
      uint8_t *copy = malloc (length); if (!copy) return -1;
      memcpy (copy, wire, length); allocation (io, length); io->pending_bytes += length;
      if (!request->active) ++io->status.requests;
      *request = (udp_request_t) {.key = *key, .id = id, .active = 1, .channel = index,
        .pending = copy, .length = length, .deadline = deadline};
      return 1;
    }
  ssize_t sent = send (channel->fd, wire, length, MSG_DONTWAIT | MSG_NOSIGNAL);
  if (sent != (ssize_t) length) { ++io->status.errors; return -1; }
  if (!request->active) ++io->status.requests;
  *request = (udp_request_t) {.key = *key, .id = id, .active = 1, .channel = index};
  ++io->status.udp_sent; channel->last_activity = now;
  return 1;
}

int product_root_dns_io_send (product_root_dns_io_t *io, const product_dns_proxy_key_t *key,
  unsigned transport, const uint8_t *wire, size_t length, uint64_t deadline, uint64_t now)
{
  if (!io || !key || key->generation != io->generation || !wire || length < 2 ||
      length > PRODUCT_DNS_MESSAGE_MAX || deadline <= now) return -1;
  if (transport == PRODUCT_DNS_PROXY_UDP) return send_udp (io, key, wire, length, deadline, now);
  if (transport != PRODUCT_DNS_PROXY_TCP && !encrypted_transport (transport)) return -1;
  const sakamoto_product_dns_endpoint_t *endpoint=NULL;
  if(encrypted_transport(transport)){
    if(!key->resolver_id||key->resolver_id>io->route.endpoint_count)return -1;
    endpoint=&io->route.endpoints[key->resolver_id-1];
    if(endpoint->transport!=transport||endpoint->family!=key->resolver_family||endpoint->port!=key->resolver_port||
       memcmp(endpoint->address,key->resolver_address,16))return -1;
    if(!io->tls){
      product_dns_proxy_io_event_t state={.tls=PRODUCT_DNS_TLS_FAILED,.error=-ENOKEY,
        .trust_source=io->callbacks.trust_directory?2:1};
      if(io->callbacks.progress)io->callbacks.progress(io->context,key,&state);
      return -1;
    }
  }
  tcp_socket_t *tcp = NULL;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd >= 0 && same_key (&io->tcp[i].key, key)) return 1;
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd < 0) { tcp = &io->tcp[i]; break; }
  if (!tcp) { ++io->status.capacity; return 0; }
  if (transport == PRODUCT_DNS_PROXY_DOH)
    {
      /* HTTP request replaces the 2-byte DNS TCP framing; the target is the
       * configured "host NUL path" identity and one exchange owns the connection. */
      const char *host = (const char *) endpoint->identity;
      const char *path = host + strlen (host) + 1;
      size_t capacity = length + 2048;
      tcp->output = malloc (capacity);
      if (!tcp->output) return -1;
      size_t built = product_dns_http_build_request (tcp->output, capacity, host, endpoint->port, path, wire, length);
      if (!built) { free (tcp->output); tcp->output = NULL; return -1; }
      tcp->output_length = built; allocation (io, built);
    }
  else
    {
      tcp->output = malloc (length + 2);
      if (!tcp->output) return -1;
      tcp->output_length = length + 2; allocation (io, length + 2);
      tcp->output[0] = length >> 8; tcp->output[1] = length;
      memcpy (tcp->output + 2, wire, length);
    }
  tcp->key = *key; tcp->deadline = deadline;
  tcp->transport=transport;
  if(endpoint){
    tcp->progress.trust_source=io->callbacks.trust_directory?2:1;
    if(!endpoint->family){
      int result=start_bootstrap(io,tcp,1);
      if(result<=0){progress(io,tcp);close_tcp(io,tcp);}return result;
    }
    tcp->progress.connection_family=endpoint->family;tcp->progress.connection_port=endpoint->port;
    memcpy(tcp->progress.connection_address,endpoint->address,16);
  }
  if (!selected_address (io, key, &tcp->resolver, &tcp->resolver_length)) { close_tcp (io, tcp); return -1; }
  int result=open_tcp_socket(io,tcp,SOCK_STREAM);
  if(result<=0){progress(io,tcp);close_tcp(io,tcp);}return result;
}

int product_root_dns_io_authorized (product_root_dns_io_t *io, uint64_t generation,
  uint64_t cookie, int success, uint64_t now)
{
  if (!io || generation != io->generation) return -1;
  for (unsigned index = 0; index < ROOT_DNS_UPSTREAM_SOCKETS; ++index)
    {
      udp_socket_t *channel = &io->channels[index];
      if (channel->fd < 0 || channel->cookie != cookie || channel->authorized) continue;
      if (success && !connect (channel->fd, (struct sockaddr *) &channel->resolver, channel->resolver_length) &&
          io->callbacks.watch (io->context, channel->fd, PRODUCT_ROOT_DNS_READ, cookie))
        {
          channel->authorized = 1;
          if (udp_default (io, channel)) io->status.udp_state = PRODUCT_ROOT_DNS_UDP_AUTHORIZED;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].pending && io->udp[i].channel == index)
              {
                udp_request_t *r = &io->udp[i]; product_dns_proxy_key_t key = r->key;
                int sent = r->deadline > now && send (channel->fd, r->pending, r->length,
                  MSG_DONTWAIT | MSG_NOSIGNAL) == (ssize_t) r->length;
                io->status.allocated_bytes -= r->length; io->pending_bytes -= r->length;
                free (r->pending); r->pending = NULL; r->length = 0;
                if (sent) { ++io->status.udp_sent; channel->last_activity = now; }
                else { ++io->status.errors; io->callbacks.failed (io->context, &key, now); }
              }
          return 0;
        }
      product_dns_proxy_key_t keys[PRODUCT_DNS_PROXY_TRANSACTIONS]; unsigned count = 0;
      for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
        if (io->udp[i].active && io->udp[i].channel == index) keys[count++] = io->udp[i].key;
      close_udp (io, channel, 1); ++io->status.errors;
      for (unsigned i = 0; i < count; ++i) io->callbacks.failed (io->context, &keys[i], now);
      return 0;
    }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    {
      tcp_socket_t *tcp = &io->tcp[i];
      if (tcp->fd < 0 || tcp->cookie != cookie || tcp->authorized) continue;
      success = success && tcp->deadline > now;
      int result = success ? connect (tcp->fd, (struct sockaddr *) &tcp->resolver, tcp->resolver_length) : -1;
      if (success && (!result || errno == EINPROGRESS))
        {
          tcp->authorized = 1; tcp->connecting = result != 0;
          tcp->progress.authorization=PRODUCT_DNS_AUTHORIZATION_GRANTED;progress(io,tcp);
          if (io->callbacks.watch (io->context, tcp->fd, PRODUCT_ROOT_DNS_READ | PRODUCT_ROOT_DNS_WRITE, cookie)) return 0;
        }
      product_dns_proxy_key_t key = tcp->key;
      tcp->progress.authorization=PRODUCT_DNS_AUTHORIZATION_FAILED;tcp->progress.error=-EACCES;progress(io,tcp);
      close_tcp (io, tcp); ++io->status.errors; io->callbacks.failed (io->context, &key, now); return 0;
    }
  ++io->status.stale; return -1;
}

static void reset_input(product_root_dns_io_t *,tcp_socket_t *);
static int next_bootstrap_address(product_root_dns_io_t *io,tcp_socket_t *tcp)
{
  product_dns_tls_close(tcp->tls);tcp->tls=NULL;
  close_socket(io,&tcp->fd,tcp->cookie);reset_input(io,tcp);
  tcp->authorized=tcp->connecting=tcp->verified=0;tcp->progress_due=0;
  tcp->progress.tls=PRODUCT_DNS_TLS_NONE;tcp->progress.error=0;
  while(tcp->bootstrap_address_at<tcp->bootstrap_address_count){
    const product_dns_bootstrap_address_t *address=&tcp->bootstrap_addresses[tcp->bootstrap_address_at++];
    product_dns_proxy_key_t selected={.resolver_family=address->family,
      .resolver_port=io->route.endpoints[tcp->key.resolver_id-1].port};
    memcpy(selected.resolver_address,address->address,16);
    tcp->progress.connection_family=selected.resolver_family;tcp->progress.connection_port=selected.resolver_port;
    memcpy(tcp->progress.connection_address,selected.resolver_address,16);
    if(selected_address(io,&selected,&tcp->resolver,&tcp->resolver_length)&&
       open_tcp_socket(io,tcp,SOCK_STREAM)>0)return 1;
    product_dns_tls_close(tcp->tls);tcp->tls=NULL;close_socket(io,&tcp->fd,tcp->cookie);
  }
  return 0;
}

static void tcp_failed (product_root_dns_io_t *io, tcp_socket_t *tcp, uint64_t now)
{
  product_dns_proxy_key_t key = tcp->key;
  if(encrypted_transport(tcp->transport)&&!tcp->bootstrap&&!tcp->verified&&tcp->deadline>now&&
     tcp->bootstrap_address_count){
    int certificate_failed=tcp->progress.tls==PRODUCT_DNS_TLS_FAILED;
    if(tcp->bootstrap_address_at<tcp->bootstrap_address_count&&next_bootstrap_address(io,tcp))return;
    /* A usable A answer need not imply IPv4 reachability. Continue AAAA only
     * after connection failure, within this same attempt's original deadline. */
    if(!certificate_failed&&tcp->bootstrap_type==1){
      product_dns_tls_close(tcp->tls);tcp->tls=NULL;close_socket(io,&tcp->fd,tcp->cookie);
      reset_input(io,tcp);tcp->authorized=tcp->connecting=0;
      tcp->bootstrap_address_count=tcp->bootstrap_address_at=0;
      if(start_bootstrap(io,tcp,28)>0)return;
    }
  }
  if(encrypted_transport(tcp->transport)){
    ++io->status.tls_failed;
    if(tcp->tls&&tcp->transport==PRODUCT_DNS_PROXY_DOH){
      tcp->progress.alpn=(uint8_t)product_dns_tls_alpn_state(tcp->tls);
      if(tcp->progress.alpn==PRODUCT_DNS_ALPN_REFUSED&&!tcp->progress.http_error)
        tcp->progress.http_error=PRODUCT_DNS_HTTP_ERROR_ALPN;
    }
    /* An HTTP failure after authentication does not unwind the TLS facts: the peer was
     * authenticated and the failure class travels in http_error with a zero tls_error. */
    int http_level=tcp->transport==PRODUCT_DNS_PROXY_DOH&&tcp->verified&&tcp->progress.http_error;
    if(tcp->bootstrap){tcp->progress.bootstrap=PRODUCT_DNS_BOOTSTRAP_FAILED;++io->status.bootstrap_failed;}
    else if(!http_level)tcp->progress.tls=PRODUCT_DNS_TLS_FAILED;
    if(!tcp->progress.error&&!http_level)tcp->progress.error=-EIO;
    progress(io,tcp);
  }
  ++io->status.errors; close_tcp (io, tcp);
  io->callbacks.failed (io->context, &key, now);
}

static void reset_input(product_root_dns_io_t *io,tcp_socket_t *tcp)
{
  io->status.allocated_bytes-=tcp->input_length;free(tcp->input);tcp->input=NULL;
  tcp->input_length=tcp->input_at=tcp->header_at=0;
}
static void bootstrap_answer(product_root_dns_io_t *io,tcp_socket_t *tcp,
  const uint8_t *wire,size_t length,uint64_t now)
{
  product_dns_bootstrap_address_t addresses[PRODUCT_DNS_BOOTSTRAP_ADDRESSES];unsigned count=0;
  int result=product_dns_bootstrap_answer(tcp->bootstrap_wire+2,tcp->bootstrap_length-2,
    wire,length,addresses,&count);
  ++io->status.bootstrap_received;
  if(result==2&&tcp->bootstrap==1){
    close_socket(io,&tcp->fd,tcp->cookie);tcp->authorized=tcp->connecting=0;
    tcp->bootstrap=2;tcp->bootstrap_at=0;tcp->bootstrap_retry=0;
    if(open_tcp_socket(io,tcp,SOCK_STREAM)<=0)tcp_failed(io,tcp,now);
    return;
  }
  if(!result&&tcp->bootstrap_type==1){
    reset_input(io,tcp);
    if(!bootstrap_question(io,tcp,28)||
      !io->callbacks.watch(io->context,tcp->fd,PRODUCT_ROOT_DNS_READ|PRODUCT_ROOT_DNS_WRITE,tcp->cookie))
      tcp_failed(io,tcp,now);
    return;
  }
  if(result!=1||!count){tcp->progress.error=-EPROTO;tcp_failed(io,tcp,now);return;}
  /* Discovery selects an address, never a different TLS identity. The old
   * original-network fd closes before a new protected TLS fd is created. */
  memcpy(tcp->bootstrap_addresses,addresses,count*sizeof(*addresses));
  tcp->bootstrap_address_count=count;tcp->bootstrap_address_at=0;
  tcp->bootstrap=0;tcp->bootstrap_retry=0;
  tcp->progress.bootstrap=PRODUCT_DNS_BOOTSTRAP_RESOLVED;
  if(!next_bootstrap_address(io,tcp))tcp_failed(io,tcp,now);
}
static void bootstrap_ready(product_root_dns_io_t *io,tcp_socket_t *tcp,unsigned events,uint64_t now)
{
  if((events&PRODUCT_ROOT_DNS_WRITE)&&tcp->bootstrap_at<tcp->bootstrap_length){
    size_t at=tcp->bootstrap==1?2:tcp->bootstrap_at;
    ssize_t sent=send(tcp->fd,tcp->bootstrap_wire+at,tcp->bootstrap_length-at,MSG_DONTWAIT|MSG_NOSIGNAL);
    if(sent<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
    if(sent<=0||(tcp->bootstrap==1&&sent!=(ssize_t)(tcp->bootstrap_length-2))){tcp_failed(io,tcp,now);return;}
    tcp->bootstrap_at=tcp->bootstrap==1?tcp->bootstrap_length:tcp->bootstrap_at+(size_t)sent;
    if(tcp->bootstrap_at==tcp->bootstrap_length){
      if(tcp->bootstrap==1&&!tcp->bootstrap_retried)tcp->bootstrap_retry=now+PRODUCT_DNS_PROXY_RETRY_US;
      if(!io->callbacks.watch(io->context,tcp->fd,PRODUCT_ROOT_DNS_READ,tcp->cookie)){tcp_failed(io,tcp,now);return;}
    }
  }
  if(!(events&PRODUCT_ROOT_DNS_READ))return;
  if(tcp->bootstrap==1){
    for(unsigned budget=0;budget<16;++budget){
      ssize_t got=recv(tcp->fd,io->received,sizeof(io->received),MSG_DONTWAIT|MSG_TRUNC);
      if(got<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
      if(got<0){tcp_failed(io,tcp,now);return;}
      if(got<2||got>(ssize_t)sizeof(io->received)||memcmp(io->received,tcp->bootstrap_wire+2,2))continue;
      bootstrap_answer(io,tcp,io->received,got,now);return;
    }
    return;
  }
  for(unsigned budget=0;budget<16;++budget){
    uint8_t *destination=tcp->header_at<2?tcp->header+tcp->header_at:tcp->input+tcp->input_at;
    size_t remaining=tcp->header_at<2?2-tcp->header_at:tcp->input_length-tcp->input_at;
    ssize_t got=recv(tcp->fd,destination,remaining,MSG_DONTWAIT);
    if(got<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))return;
    if(got<=0){tcp_failed(io,tcp,now);return;}
    if(tcp->header_at<2){
      tcp->header_at+=got;if(tcp->header_at<2)continue;
      tcp->input_length=((size_t)tcp->header[0]<<8)|tcp->header[1];
      if(tcp->input_length<12){tcp->input_length=0;tcp_failed(io,tcp,now);return;}
      tcp->input=malloc(tcp->input_length);
      if(!tcp->input){tcp->input_length=0;tcp_failed(io,tcp,now);return;}
      allocation(io,tcp->input_length);
    }else{
      tcp->input_at+=got;
      if(tcp->input_at==tcp->input_length){bootstrap_answer(io,tcp,tcp->input,tcp->input_length,now);return;}
    }
  }
}

static int tls_watch(product_root_dns_io_t *io,tcp_socket_t *tcp,unsigned events,uint64_t now)
{
  if(io->callbacks.watch(io->context,tcp->fd,events,tcp->cookie))return 1;
  tcp_failed(io,tcp,now);return 0;
}
static void doh_failed(product_root_dns_io_t *io,tcp_socket_t *tcp,int http_result,int tls_error,uint64_t now)
{
  if(http_result<0)tcp->progress.http_error=(uint8_t)-http_result;
  if(tcp->http)tcp->progress.http_status=tcp->http->status;
  tcp->progress.error=http_result<0?0:tls_error;
  tcp_failed(io,tcp,now);
}
static void doh_deliver(product_root_dns_io_t *io,tcp_socket_t *tcp,uint64_t now)
{
  tcp->progress.http_status=tcp->http->status;tcp->progress.http_age=tcp->http->age;
  progress(io,tcp);
  ++io->status.tcp_received;
  io->callbacks.answer(io->context,&tcp->key,PRODUCT_DNS_PROXY_DOH,tcp->input,tcp->http->body_at,now);
}
/* HTTP/1.1 response read: the first complete response is the only exchange on this
 * connection. A connection-delimited body is complete only after TLS close_notify;
 * a bare TCP end or any parser failure is a failed attempt, never a partial answer. */
static void doh_read(product_root_dns_io_t *io,tcp_socket_t *tcp,uint64_t now)
{
  unsigned wanted=0;
  if(!tcp->http){
    tcp->http=malloc(sizeof(*tcp->http));
    tcp->input=malloc(PRODUCT_DNS_MESSAGE_MAX);
    if(tcp->http)allocation(io,sizeof(*tcp->http));
    if(tcp->input){tcp->input_length=PRODUCT_DNS_MESSAGE_MAX;allocation(io,PRODUCT_DNS_MESSAGE_MAX);}
    if(!tcp->http||!tcp->input){doh_failed(io,tcp,0,-ENOMEM,now);return;}
    product_dns_http_init(tcp->http,tcp->input,PRODUCT_DNS_MESSAGE_MAX);
  }
  for(unsigned budget=0;budget<16;++budget){
    uint8_t buffer[4096];
    ssize_t received=product_dns_tls_read(tcp->tls,buffer,sizeof(buffer),&wanted);
    if(received==-2){(void)tls_watch(io,tcp,wanted,now);return;}
    if(received<=0){
      int error=product_dns_tls_error(tcp->tls);
      int result=product_dns_tls_peer_closed(tcp->tls)?product_dns_http_eof(tcp->http):PRODUCT_DNS_HTTP_CLOSED;
      if(result==PRODUCT_DNS_HTTP_DONE){doh_deliver(io,tcp,now);return;}
      doh_failed(io,tcp,result,error,now);return;
    }
    io->status.tcp_read_bytes+=received;
    size_t consumed=0;
    int result=product_dns_http_feed(tcp->http,buffer,(size_t)received,&consumed);
    if(result==PRODUCT_DNS_HTTP_DONE){doh_deliver(io,tcp,now);return;}
    if(result<0){doh_failed(io,tcp,result,0,now);return;}
  }
  if(product_dns_tls_pending(tcp->tls))tcp->progress_due=now+1;
  (void)tls_watch(io,tcp,PRODUCT_ROOT_DNS_READ,now);
}
static void tls_ready(product_root_dns_io_t *io,tcp_socket_t *tcp,uint64_t now)
{
  unsigned wanted=0;tcp->progress_due=0;
  if(!tcp->verified){
    tcp->progress.tls=PRODUCT_DNS_TLS_HANDSHAKING;progress(io,tcp);
    int result=product_dns_tls_handshake(tcp->tls,&wanted);
    if(result<0){tcp->progress.tls=PRODUCT_DNS_TLS_FAILED;tcp->progress.error=product_dns_tls_error(tcp->tls);tcp_failed(io,tcp,now);return;}
    if(!result){(void)tls_watch(io,tcp,wanted,now);return;}
    tcp->verified=1;++io->status.tls_verified;tcp->progress.tls=PRODUCT_DNS_TLS_AUTHENTICATED;
    if(tcp->transport==PRODUCT_DNS_PROXY_DOH)tcp->progress.alpn=(uint8_t)product_dns_tls_alpn_state(tcp->tls);
    progress(io,tcp);
  }
  /* The output buffer and exact remaining span survive WANT_READ/WRITE.
   * Application DNS is first offered only after peer authentication. */
  for(unsigned budget=0;tcp->output_at<tcp->output_length&&budget<16;++budget){
    ssize_t sent=product_dns_tls_write(tcp->tls,tcp->output+tcp->output_at,
      tcp->output_length-tcp->output_at,&wanted);
    if(sent==-2){(void)tls_watch(io,tcp,wanted,now);return;}
    if(sent<=0){tcp->progress.error=product_dns_tls_error(tcp->tls);tcp_failed(io,tcp,now);return;}
    tcp->output_at+=sent;io->status.tcp_write_bytes+=sent;
    if(tcp->output_at==tcp->output_length)++io->status.tcp_sent;
  }
  if(tcp->output_at<tcp->output_length){(void)tls_watch(io,tcp,PRODUCT_ROOT_DNS_WRITE,now);return;}
  if(tcp->transport==PRODUCT_DNS_PROXY_DOH){doh_read(io,tcp,now);return;}
  for(unsigned budget=0;budget<16;++budget){
    uint8_t *destination=tcp->header_at<2?tcp->header+tcp->header_at:tcp->input+tcp->input_at;
    size_t remaining=tcp->header_at<2?2-tcp->header_at:tcp->input_length-tcp->input_at;
    ssize_t received=product_dns_tls_read(tcp->tls,destination,remaining,&wanted);
    if(received==-2){(void)tls_watch(io,tcp,wanted,now);return;}
    if(received<=0){tcp->progress.error=product_dns_tls_error(tcp->tls);tcp_failed(io,tcp,now);return;}
    io->status.tcp_read_bytes+=received;
    if(tcp->header_at<2){
      tcp->header_at+=received;
      if(tcp->header_at<2)continue;
      tcp->input_length=((size_t)tcp->header[0]<<8)|tcp->header[1];
      if(tcp->input_length<12){tcp->input_length=0;tcp_failed(io,tcp,now);return;}
      tcp->input=malloc(tcp->input_length);
      if(!tcp->input){tcp->input_length=0;tcp_failed(io,tcp,now);return;}
      allocation(io,tcp->input_length);
    }else{
      tcp->input_at+=received;
      if(tcp->input_at==tcp->input_length){
        ++io->status.tcp_received;
        io->callbacks.answer(io->context,&tcp->key,PRODUCT_DNS_PROXY_DOT,tcp->input,tcp->input_length,now);
        return; /* The callback may cancel this exact socket. */
      }
    }
  }
  /* Decrypted bytes can remain after the fd was drained. Request an owner
   * continuation only for this real runnable work, through its existing timer. */
  if(product_dns_tls_pending(tcp->tls))tcp->progress_due=now+1;
  (void)tls_watch(io,tcp,PRODUCT_ROOT_DNS_READ,now);
}

static void tcp_ready (product_root_dns_io_t *io, tcp_socket_t *tcp, unsigned events, uint64_t now)
{
  if (tcp->deadline <= now || (events & PRODUCT_ROOT_DNS_ERROR))
    { tcp->progress.error=tcp->deadline<=now?-ETIMEDOUT:-EIO;tcp_failed (io, tcp, now); return; }
  if(!tcp->authorized)return;
  if (tcp->connecting)
    {
      int error = 0; socklen_t length = sizeof (error);
      if (getsockopt (tcp->fd, SOL_SOCKET, SO_ERROR, &error, &length) || error)
        { tcp->progress.error=error?-error:-errno;tcp_failed (io, tcp, now); return; }
      tcp->connecting = 0;
    }
  if(tcp->bootstrap){bootstrap_ready(io,tcp,events,now);return;}
  if(tcp->tls){tls_ready(io,tcp,now);return;}
  if (events & PRODUCT_ROOT_DNS_WRITE)
    {
      ssize_t sent = send (tcp->fd, tcp->output + tcp->output_at,
        tcp->output_length - tcp->output_at, MSG_DONTWAIT | MSG_NOSIGNAL);
      if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
      if (sent <= 0) { tcp_failed (io, tcp, now); return; }
      io->status.tcp_write_bytes += sent;
      tcp->output_at += sent;
      if (tcp->output_at == tcp->output_length)
        {
          ++io->status.tcp_sent;
          if (!io->callbacks.watch (io->context, tcp->fd, PRODUCT_ROOT_DNS_READ, tcp->cookie))
            { tcp_failed (io, tcp, now); return; }
        }
    }
  if (!(events & PRODUCT_ROOT_DNS_READ)) return;
  for (unsigned budget = 0; budget < 16; ++budget)
    {
      uint8_t *destination = tcp->header_at < 2 ? tcp->header + tcp->header_at : tcp->input + tcp->input_at;
      size_t remaining = tcp->header_at < 2 ? 2 - tcp->header_at : tcp->input_length - tcp->input_at;
      ssize_t received = recv (tcp->fd, destination, remaining, MSG_DONTWAIT);
      if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
      if (received <= 0) { tcp_failed (io, tcp, now); return; }
      io->status.tcp_read_bytes += received;
      if (tcp->header_at < 2)
        {
          tcp->header_at += received;
          if (tcp->header_at < 2) continue;
          tcp->input_length = ((size_t) tcp->header[0] << 8) | tcp->header[1];
          if (tcp->input_length < 12) { tcp_failed (io, tcp, now); return; }
          tcp->input = malloc (tcp->input_length);
          if (!tcp->input) { tcp->input_length = 0; tcp_failed (io, tcp, now); return; }
          allocation (io, tcp->input_length);
        }
      else
        {
          tcp->input_at += received;
          if (tcp->input_at == tcp->input_length)
            {
              ++io->status.tcp_received;
              io->callbacks.answer (io->context, &tcp->key, PRODUCT_DNS_PROXY_TCP,
                tcp->input, tcp->input_length, now);
              return; /* The callback may cancel and free this exact socket. */
            }
        }
    }
}

void product_root_dns_io_ready (product_root_dns_io_t *io, uint64_t generation,
  uint64_t cookie, int fd, unsigned events, uint64_t now)
{
  if (!io) return;
  if (generation != io->generation) { ++io->status.stale; return; }
  for (unsigned index = 0; index < ROOT_DNS_UPSTREAM_SOCKETS; ++index)
    {
      udp_socket_t *channel = &io->channels[index];
      if (channel->fd < 0 || channel->cookie != cookie || channel->fd != fd) continue;
      if (events & PRODUCT_ROOT_DNS_ERROR)
        {
          product_dns_proxy_key_t keys[PRODUCT_DNS_PROXY_TRANSACTIONS]; unsigned count = 0;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].active && io->udp[i].channel == index) keys[count++] = io->udp[i].key;
          close_udp (io, channel, 1); ++io->status.errors;
          for (unsigned i = 0; i < count; ++i) io->callbacks.failed (io->context, &keys[i], now);
          return;
        }
      for (unsigned budget = 0; budget < 16; ++budget)
        {
          if (channel->fd != fd || channel->cookie != cookie) return;
          ssize_t received = recv (fd, io->received, sizeof (io->received), MSG_DONTWAIT | MSG_TRUNC);
          if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
          if (received < 0)
            { product_root_dns_io_ready (io, generation, cookie, fd, PRODUCT_ROOT_DNS_ERROR, now); return; }
          if (received < 2 || received > (ssize_t) sizeof (io->received)) continue;
          uint16_t id = ((uint16_t) io->received[0] << 8) | io->received[1];
          ++io->status.udp_received; channel->last_activity = now;
          for (unsigned i = 0; i < PRODUCT_DNS_PROXY_TRANSACTIONS; ++i)
            if (io->udp[i].active && io->udp[i].channel == index && io->udp[i].id == id)
              {
                product_dns_proxy_key_t key = io->udp[i].key;
                io->callbacks.answer (io->context, &key, PRODUCT_DNS_PROXY_UDP, io->received, received, now);
                break;
              }
        }
      return;
    }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    if (io->tcp[i].fd >= 0 && io->tcp[i].cookie == cookie && io->tcp[i].fd == fd)
      { tcp_ready (io, &io->tcp[i], events, now); return; }
  ++io->status.stale;
}

uint64_t product_root_dns_io_deadline (const product_root_dns_io_t *io)
{
  uint64_t due = UINT64_MAX;
  if (io) for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd >= 0 && !udp_busy (io, i) &&
        io->channels[i].last_activity + PRODUCT_ROOT_DNS_IDLE_US < due)
      due = io->channels[i].last_activity + PRODUCT_ROOT_DNS_IDLE_US;
  if(io)for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_SOCKETS;++i)
    if(io->tcp[i].fd>=0){
      if(io->tcp[i].deadline<due)due=io->tcp[i].deadline;
      if(io->tcp[i].progress_due&&io->tcp[i].progress_due<due)due=io->tcp[i].progress_due;
      if(io->tcp[i].bootstrap_retry&&io->tcp[i].bootstrap_retry<due)due=io->tcp[i].bootstrap_retry;
    }
  return due;
}
void product_root_dns_io_expire (product_root_dns_io_t *io, uint64_t now)
{
  if (!io) return;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    if (io->channels[i].fd >= 0 && !udp_busy (io, i) &&
        io->channels[i].last_activity + PRODUCT_ROOT_DNS_IDLE_US <= now)
      close_udp (io, &io->channels[i], !io->channels[i].authorized);
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_SOCKETS;++i)
    if(io->tcp[i].fd>=0){
      int retry=io->tcp[i].bootstrap_retry&&io->tcp[i].bootstrap_retry<=now;
      if(retry){io->tcp[i].bootstrap_retry=0;io->tcp[i].bootstrap_retried=1;io->tcp[i].bootstrap_at=0;}
      if(retry||io->tcp[i].deadline<=now||
        (io->tcp[i].progress_due&&io->tcp[i].progress_due<=now))
        tcp_ready(io,&io->tcp[i],PRODUCT_ROOT_DNS_READ|PRODUCT_ROOT_DNS_WRITE,now);
    }
}
product_root_dns_io_status_t product_root_dns_io_status (const product_root_dns_io_t *io)
{
  if (!io) return (product_root_dns_io_status_t) {0};
  product_root_dns_io_status_t status = io->status;
  product_dns_tls_resources_t tls=product_dns_tls_resources(io->tls);
  status.tls_bytes=tls.bytes;status.tls_high_water_bytes=tls.high_water_bytes;
  status.tls_rejected=tls.rejected;status.tls_authenticated=tls.authenticated;
  status.trust_certificates=tls.trust_certificates;
  status.allocated_bytes+=tls.bytes;status.high_water_bytes+=tls.high_water_bytes;
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_SOCKETS;++i)status.tls_connections+=!!io->tcp[i].tls;
  for (unsigned i = 0; i < ROOT_DNS_UPSTREAM_SOCKETS; ++i)
    {
      status.authorizing += io->channels[i].fd >= 0 && !io->channels[i].authorized;
      if (udp_default (io, &io->channels[i]))
        status.udp_ready |= io->channels[i].fd >= 0 && io->channels[i].authorized;
    }
  for (unsigned i = 0; i < PRODUCT_ROOT_DNS_TCP_SOCKETS; ++i)
    status.authorizing += io->tcp[i].fd >= 0 && !io->tcp[i].authorized;
  return status;
}
