/* SPDX-License-Identifier: Apache-2.0 */
#include "adapter.h"
#include "libprotoident.h"
#include <cstdlib>
#include <new>
extern "C" int sakamoto_lpi_init (void)
{
  static bool initialized = false;
  if (initialized) return 0;
  try {
    if (lpi_init_library () || std::atexit (lpi_free_library)) return -1;
    initialized = true;
    return 0;
  } catch (const std::bad_alloc &) { return -1; }
}
extern "C" const char *sakamoto_lpi_guess (const uint32_t payload[2], const uint32_t lengths[2],
  const uint32_t observed[2], const uint32_t ips[2], uint16_t client, uint16_t server, uint8_t transport)
{
  lpi_data_t data;
  lpi_init_data (&data);
  for (unsigned i = 0; i < 2; ++i) {
    data.payload[i] = payload[i]; data.payload_len[i] = lengths[i];
    data.observed[i] = observed[i]; data.ips[i] = ips[i];
  }
  data.client_port = client; data.server_port = server; data.trans_proto = transport;
  const lpi_module_t *module = lpi_guess_protocol (&data);
  if (!module) return nullptr;
  switch (module->protocol) {
    case LPI_PROTO_HTTP: case LPI_PROTO_NONSTANDARD_HTTP: return "lpi:http";
    case LPI_PROTO_HTTPS: case LPI_PROTO_SSL: return "lpi:tls";
    case LPI_PROTO_SSH: return "lpi:ssh";
    case LPI_PROTO_DNS: case LPI_PROTO_UDP_DNS: return "lpi:dns";
    case LPI_PROTO_UDP_QUIC: return "lpi:quic";
    case LPI_PROTO_UNKNOWN: case LPI_PROTO_NO_PAYLOAD: case LPI_PROTO_NO_FIRSTPKT:
      return nullptr;
    default: return module->name;
  }
}
