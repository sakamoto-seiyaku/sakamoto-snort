/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_rule_config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <unistd.h>

struct product_rule_config {
  char *path;
  sakamoto_product_rule_config_status_t state;
};

static int rule_valid (const sakamoto_product_config_rule_t *);

/* The first encoding is bounded, canonical ASCII, independent of C padding
 * and machine byte order. This is source data, never a compiled snapshot. */
static int
encode (const sakamoto_product_rule_config_status_t *s, char *text, size_t size)
{
  const sakamoto_product_config_rule_t *r = &s->rule;
  return snprintf (text, size,
    "sakamoto-rule-config/1\n%llu %llu\n%u %u %u %u %u %u %u\n"
    "%02x%02x%02x%02x %02x%02x%02x%02x\n",
    (unsigned long long) s->saved_revision,
    (unsigned long long) s->saved_rule_version,
    r->present, r->uid, r->protocol, r->direction, r->action,
    r->source_port, r->destination_port,
    r->source_address[0], r->source_address[1], r->source_address[2], r->source_address[3],
    r->destination_address[0], r->destination_address[1], r->destination_address[2], r->destination_address[3]);
}

static uint32_t
save_source (product_rule_config_t *config,
             const sakamoto_product_rule_config_status_t *candidate)
{
  char bytes[512];
  int length = encode (candidate, bytes, sizeof (bytes));
  if (length < 0 || (size_t) length >= sizeof (bytes))
    return SAKAMOTO_RULE_CONFIG_IO;
  size_t path_size = strlen (config->path) + 16;
  char *temporary = malloc (path_size);
  char *parent = strdup (config->path);
  if (!temporary || !parent) { free (temporary); free (parent); return SAKAMOTO_RULE_CONFIG_IO; }
  snprintf (temporary, path_size, "%s.tmp.XXXXXX", config->path);
  char *slash = strrchr (parent, '/');
  if (!slash) { free (temporary); free (parent); return SAKAMOTO_RULE_CONFIG_IO; }
  if (slash == parent) slash[1] = '\0'; else *slash = '\0';
  int directory = open (parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  free (parent);
  int fd = -1;
  uint32_t result = SAKAMOTO_RULE_CONFIG_IO;
  struct stat owner;
  if (directory < 0 || fstat (directory, &owner) != 0) goto done;
  fd = mkstemp (temporary);
  if (fd < 0) goto done;
  /* Root and VPN use one app-owned source; never leave a root-only file. */
  if (geteuid () == 0 && fchown (fd, owner.st_uid, owner.st_gid) != 0) goto done;
  size_t written = 0;
  while (written < (size_t) length)
    {
      ssize_t count = write (fd, bytes + written, (size_t) length - written);
      if (count < 0 && errno == EINTR) continue;
      if (count <= 0) goto done;
      written += (size_t) count;
    }
  if (fsync (fd) != 0) goto done;
  if (close (fd) != 0) { fd = -1; goto done; }
  fd = -1;
  if (rename (temporary, config->path) != 0) goto done;
  /* After rename the complete new source exists even if durability fails.
   * Keep that saved identity truthful, but do not compile on the error. */
  config->state.saved_revision = candidate->saved_revision;
  config->state.saved_rule_version = candidate->saved_rule_version;
  config->state.rule = candidate->rule;
  if (fsync (directory) != 0) goto done;
  result = SAKAMOTO_RULE_CONFIG_OK;
done:
  if (fd >= 0) close (fd);
  if (directory >= 0) close (directory);
  unlink (temporary);
  free (temporary);
  return result;
}

static uint32_t
load_source (product_rule_config_t *config)
{
  int fd = open (config->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return SAKAMOTO_RULE_CONFIG_IO;
  struct stat st;
  char bytes[512], canonical[512];
  size_t length = 0;
  int valid = fstat (fd, &st) == 0 && S_ISREG (st.st_mode)
    && st.st_size > 0 && st.st_size < (off_t) sizeof (bytes);
  while (valid && length < sizeof (bytes) - 1)
    {
      ssize_t count = read (fd, bytes + length, sizeof (bytes) - 1 - length);
      if (count < 0 && errno == EINTR) continue;
      if (count < 0) { valid = 0; break; }
      if (count == 0) break;
      length += (size_t) count;
    }
  close (fd);
  if (!valid || length != (size_t) st.st_size) return SAKAMOTO_RULE_CONFIG_IO;
  bytes[length] = '\0';
  sakamoto_product_rule_config_status_t loaded = {0};
  sakamoto_product_config_rule_t *r = &loaded.rule;
  unsigned long long revision, version;
  unsigned addresses[8];
  int end = 0;
  int fields = sscanf (bytes,
    "sakamoto-rule-config/1\n%llu %llu\n%u %u %u %u %u %u %u\n"
    "%2x%2x%2x%2x %2x%2x%2x%2x\n%n",
    &revision, &version, &r->present, &r->uid, &r->protocol, &r->direction,
    &r->action, &r->source_port, &r->destination_port,
    &addresses[0], &addresses[1], &addresses[2], &addresses[3],
    &addresses[4], &addresses[5], &addresses[6], &addresses[7], &end);
  if (fields != 17 || end != (int) length) return SAKAMOTO_RULE_CONFIG_INVALID;
  loaded.saved_revision = (uint64_t) revision;
  loaded.saved_rule_version = (uint64_t) version;
  for (unsigned i = 0; i < 4; ++i)
    { r->source_address[i] = addresses[i]; r->destination_address[i] = addresses[i+4]; }
  if (!revision || !rule_valid (r)
      || (version && (!(version >> 16) || !(version & UINT16_MAX)))
      || (r->present && !version)) return SAKAMOTO_RULE_CONFIG_INVALID;
  int encoded = encode (&loaded, canonical, sizeof (canonical));
  if (encoded != (int) length || memcmp (bytes, canonical, length) != 0)
    return SAKAMOTO_RULE_CONFIG_INVALID;
  config->state = loaded;
  return 0;
}

product_rule_config_t *
product_rule_config_open (const char *path)
{
  if (!path || path[0] != '/') return NULL;
  product_rule_config_t *config = calloc (1, sizeof (*config));
  if (!config) return NULL;
  config->path = strdup (path);
  if (!config->path) { free (config); return NULL; }
  struct stat existing;
  if (lstat (path, &existing) != 0 && errno == ENOENT)
    {
      sakamoto_product_rule_config_status_t empty = { .saved_revision = 1 };
      config->state.save_error = save_source (config, &empty);
    }
  else config->state.save_error = load_source (config);
  return config;
}

void product_rule_config_close (product_rule_config_t *config)
{
  if (config) { free (config->path); free (config); }
}

void product_rule_config_query (const product_rule_config_t *config,
                               sakamoto_product_rule_config_status_t *out)
{
  if (out) *out = config->state;
}

uint32_t product_rule_config_activate (product_rule_config_t *config,
                                     product_rule_config_publish_t publish,
                                     void *opaque)
{
  if (!config || !publish) return SAKAMOTO_RULE_CONFIG_INVALID;
  if (config->state.save_error) return config->state.save_error;
  const sakamoto_product_config_rule_t *source = &config->state.rule;
  product_l4_policy_rule_t rule = {0};
  if (source->present)
    {
      if (source->protocol != PRODUCT_L4_POLICY_PROTOCOL_UDP)
        return config->state.compile_error = SAKAMOTO_RULE_CONFIG_UNSUPPORTED;
      rule.rule_id = config->state.saved_rule_version;
      rule.uid = source->uid;
      rule.network_context_id = PRODUCT_L4_POLICY_NETWORK_CONTEXT_ANY;
      rule.ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
      rule.reason_id = 1;
      rule.family = PRODUCT_L4_POLICY_FAMILY_IPV4;
      rule.protocol = (uint8_t) source->protocol;
      rule.direction = (uint8_t) source->direction;
      rule.action = (uint8_t) source->action;
      rule.source_prefix_length = rule.destination_prefix_length = 32;
      rule.source_port_first = rule.source_port_last = (uint16_t) source->source_port;
      rule.destination_port_first = rule.destination_port_last = (uint16_t) source->destination_port;
      memcpy (rule.source_address, source->source_address, 4);
      memcpy (rule.destination_address, source->destination_address, 4);
    }
  product_l4_policy_view_t compiled;
  product_l4_policy_init (&compiled);
  if (product_l4_policy_compile (&compiled, &rule, source->present)
      != PRODUCT_L4_POLICY_STATUS_OK)
    return config->state.compile_error = SAKAMOTO_RULE_CONFIG_COMPILE;
  /* Hash the canonical complete source, not native struct padding. */
  char bytes[512];
  int length = encode (&config->state, bytes, sizeof (bytes));
  uint64_t hash = UINT64_C(14695981039346656037);
  for (int i = 0; i < length; ++i)
    { hash ^= (uint8_t) bytes[i]; hash *= UINT64_C(1099511628211); }
  if (!hash) hash = 1;
  uint32_t result = publish (opaque, config->state.saved_revision, hash,
                             &rule, source->present);
  config->state.compile_error = result ? SAKAMOTO_RULE_CONFIG_PUBLISH : 0;
  if (!result)
    {
      config->state.active_revision = config->state.saved_revision;
      config->state.active_rule_version = source->present ? config->state.saved_rule_version : 0;
    }
  return config->state.compile_error;
}

static int
rule_valid (const sakamoto_product_config_rule_t *rule)
{
  if (rule->reserved || rule->present > 1) return 0;
  if (!rule->present)
    {
      const sakamoto_product_config_rule_t empty = {0};
      return memcmp (rule, &empty, sizeof (empty)) == 0;
    }
  return rule->uid != UINT32_MAX && rule->protocol > 0 && rule->protocol <= 255
    && (rule->direction == 1 || rule->direction == 3)
    && (rule->action == 1 || rule->action == 2)
    && rule->source_port <= UINT16_MAX && rule->destination_port <= UINT16_MAX;
}

uint32_t product_rule_config_replace (
  product_rule_config_t *config, const sakamoto_product_rule_config_request_t *request,
  product_rule_config_publish_t publish, void *opaque)
{
  if (!config || !request || !publish || request->schema != SAKAMOTO_RULE_CONFIG_SCHEMA
      || request->operation != SAKAMOTO_RULE_CONFIG_REPLACE || !rule_valid (&request->rule))
    return SAKAMOTO_RULE_CONFIG_INVALID;
  if (request->expected_saved_revision != config->state.saved_revision)
    return SAKAMOTO_RULE_CONFIG_CONFLICT;
  if (config->state.saved_revision == UINT64_MAX) return SAKAMOTO_RULE_CONFIG_EXHAUSTED;
  sakamoto_product_rule_config_status_t next = config->state;
  next.saved_revision++;
  if (request->rule.present)
    {
      if (!next.saved_rule_version)
        {
          uint64_t identity = 0;
          for (unsigned attempt = 0; attempt < 16 && !identity; ++attempt)
            {
              ssize_t count;
              do { count = getrandom (&identity, sizeof (identity), 0); }
              while (count < 0 && errno == EINTR);
              if (count != sizeof (identity)) return SAKAMOTO_RULE_CONFIG_IO;
              identity &= UINT64_C(0xffffffffffff0000);
            }
          if (!identity) return SAKAMOTO_RULE_CONFIG_IO;
          next.saved_rule_version = identity | 1;
        }
      else if (memcmp (&next.rule, &request->rule, sizeof (next.rule)) != 0)
        {
          if ((next.saved_rule_version & UINT16_MAX) == UINT16_MAX)
            return SAKAMOTO_RULE_CONFIG_EXHAUSTED;
          next.saved_rule_version++;
        }
    }
  next.rule = request->rule;
  config->state.save_error = save_source (config, &next);
  if (config->state.save_error) return config->state.save_error;
  return product_rule_config_activate (config, publish, opaque);
}
