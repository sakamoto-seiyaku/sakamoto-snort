#!/usr/bin/env python3
"""S247 only: extend the sealed S245/S246 experiment in a separate work tree."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
POC = HERE.parent
WORK = POC / "work/s247"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    base = load("s247_base_prepare", POC / "s245-s246/prepare.py")
    base.WORK = WORK
    base.main()
    change = base.replace
    pool = WORK / "hev/src/core/owner_context.c"
    change(pool, "  struct owner_memp_slot *slot = pool->free_list;", r'''  struct owner_memp_slot *slot = pool->free_list;
  if (id == OWNER_MEMP_PBUF || id == OWNER_MEMP_PBUF_POOL) {
    const char *value = getenv("S247_PBUF_LIMIT");
    unsigned limit = value ? (unsigned)atoi(value) : 0;
    size_t used = context->memp_pools[OWNER_MEMP_PBUF].used_count +
                  context->memp_pools[OWNER_MEMP_PBUF_POOL].used_count;
    if (limit && used >= limit) {
      fprintf(stderr, "s247 event=pbuf_limit_reject pool=%d used=%zu limit=%u thread=%lu\n",
        id, used, limit, (unsigned long)pthread_self());
      return NULL;
    }
  }''')

    oi3 = WORK / "plugin/owner_inline_oi3.c"
    change(oi3, "static unsigned s246_callback_active;", r'''static unsigned s246_callback_active;
static unsigned s247_stop_requested;
static unsigned s247_setting(const char *name, unsigned fallback)
{
  const char *value = getenv(name);
  return value ? (unsigned)atoi(value) : fallback;
}
''')
    change(oi3, "tm->owner_config.inflight_pbuf_credit_limit = 8;",
           'tm->owner_config.inflight_pbuf_credit_limit = s247_setting("S247_CREDIT_LIMIT", 4);')
    change(oi3, "  tm->owner_config.identity = 0x13000001U + tm->family + tm->protocol;", r'''  tm->owner_config.identity = 0x13000001U + tm->family + tm->protocol;
  fprintf(stderr, "s247 event=config pbuf_limit=%u credit_limit=%u burst=%u stop_overlap=%u generation=%llu owner=%u\n",
    s247_setting("S247_PBUF_LIMIT", 4), s247_setting("S247_CREDIT_LIMIT", 4),
    s247_setting("S247_BURST", 1), s247_setting("S247_STOP_OVERLAP", 0),
    (unsigned long long)tm->generation, vlib_get_thread_index());''')
    change(oi3, "  tm->return_rewritten++;\n  rc = 0;", r'''  tm->return_rewritten++;
  if (meta->controlled_sync && s247_setting("S247_STOP_OVERLAP", 0)) {
    s247_stop_requested = 1;
    fprintf(stderr, "s247 event=stop_overlap_request input_seq=%u output_seq=%u native_buffer=%u generation=%llu owner=%u\n",
      s245_inputs, seq, index, (unsigned long long)tm->generation, vlib_get_thread_index());
  }
  rc = 0;''')
    # Preserve the existing single-owner queue and return without waiting until
    # the registered small burst of real app packets has arrived.
    change(oi3, "    if (tm->multi_mode && tm->protocol == 17) {\n      /* UDP remains", r'''    if (!s245_inputs && s247_setting("S247_BURST", 1) > 1 &&
        tm->tun_pending_count < s247_setting("S247_BURST", 1)) {
      fprintf(stderr, "s247 event=batch_wait depth=%u required=%u owner=%u\n",
        tm->tun_pending_count, s247_setting("S247_BURST", 1), vlib_get_thread_index());
      return;
    }
    if (tm->multi_mode && tm->protocol == 17) {
      /* UDP remains''')
    change(oi3, "    tm->phase = OI3_DRIVE;\n  }\n  if (!tm->tun_mode", r'''    if (s247_stop_requested) {
      tm->normal_stop_requested = 1;
      tm->phase = OI3_STOPPING;
      tm->finish_requested = 1;
      fprintf(stderr, "s247 event=stop_overlap_deferred native_residue=%u owner=%u\n",
        tm->vpp_buffer_residue, vlib_get_thread_index());
      return;
    }
    tm->phase = OI3_DRIVE;
  }
  if (!tm->tun_mode''')
    change(oi3, "  (void)node;\n  return frame->n_vectors;\n}\n\nVLIB_REGISTER_NODE(s246_return_node)", r'''  if (s247_stop_requested && tm->active && tm->finish_requested &&
      tm->vpp_buffer_residue == 0 && !tm->worker_token_pending) {
    if (oi3_enqueue_owner_for(tm, vm, 0) < 0)
      snprintf(tm->error, sizeof(tm->error), "s247-stop-owner-enqueue");
  }
  (void)node;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(s246_return_node)''')
    # Every pbuf carries a real allocator lifetime. Snapshot pool totals at
    # the synchronous stop request via the independent allocation ledger.
    source = WORK / "hev/src/hev-flow-stack-owner-context.c"
    change(source, "      lwip_owner_context_pbuf_free(context->lwip, sync_packet);\n    }\n  }", r'''      lwip_owner_context_pbuf_free(context->lwip, sync_packet);
    } else {
      fprintf(stderr, "s247 event=sync_payload_reject input_seq=%u\n", probe_seq);
    }
  }''')

    owner_header = WORK / "hev/src/hev-socks5-tunnel-owner.h"
    change(owner_header, "void hev_socks5_tunnel_owner_stop (HevSocks5TunnelOwnerRuntime *owner);",
           "void hev_socks5_tunnel_owner_stop (HevSocks5TunnelOwnerRuntime *owner);\nint s247_owner_accepts_forward (HevSocks5TunnelOwnerRuntime *owner);")
    runtime = WORK / "hev/src/hev-socks5-tunnel.c"
    change(runtime, "void\nhev_socks5_tunnel_owner_stop (", "int\ns247_owner_accepts_forward (HevSocks5TunnelOwnerRuntime *owner)\n{\n    return owner && owner->started;\n}\n\nvoid\nhev_socks5_tunnel_owner_stop (")
    udp = WORK / "hev/src/hev-socks5-session-udp.c"
    change(udp, "        if (res_f >= 0)\n", "        if (!s247_owner_accepts_forward (self->data.owner))\n            break;\n        if (res_f >= 0)\n")

    native = WORK / "app/native/vpn_fd_probe.c"
    change(native, '        setenv("SAKAMOTO_S245_MODE", probe_mode, 1);', r'''        setenv("SAKAMOTO_S245_MODE", probe_mode, 1);
        unsigned pool_limit=4, credit_limit=4, burst=1, stop_overlap=0;
        snprintf(probe_path, sizeof(probe_path), "%s/s247-config", app_files);
        probe_file = fopen(probe_path, "r");
        if (probe_file) {
            if (fscanf(probe_file, "%u %u %u %u", &pool_limit, &credit_limit, &burst, &stop_overlap) != 4)
                _exit(72);
            fclose(probe_file);
        }
        snprintf(probe_mode, sizeof(probe_mode), "%u", pool_limit); setenv("S247_PBUF_LIMIT", probe_mode, 1);
        snprintf(probe_mode, sizeof(probe_mode), "%u", credit_limit); setenv("S247_CREDIT_LIMIT", probe_mode, 1);
        snprintf(probe_mode, sizeof(probe_mode), "%u", burst); setenv("S247_BURST", probe_mode, 1);
        snprintf(probe_mode, sizeof(probe_mode), "%u", stop_overlap); setenv("S247_STOP_OVERLAP", probe_mode, 1);''')
    java = WORK / "app/src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java"
    text = java.read_text()
    start = text.index("                    try (DatagramSocket socket = new DatagramSocket()) {", text.index("private void startControlledOi3AppPacket"))
    end = text.index("                }\n                appendProbeLog", start)
    java.write_text(text[:start] + (HERE / "app-probe.java.inc").read_text() + text[end:])
    manifest = json.loads((WORK / "source-manifest.json").read_text())
    manifest["task"] = "SAKAMOTO-247"
    manifest["base_experiment"] = "S245/S246 source recipe; S246 ERR_MEM/ERR_IF correction retained"
    (WORK / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print("Prepared S247", WORK)


if __name__ == "__main__":
    main()
