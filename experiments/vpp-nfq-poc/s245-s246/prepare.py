#!/usr/bin/env python3
"""Make an isolated, reproducible experimental source variant; never edit bases."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
POC = HERE.parent
REPO = POC.parent.parent
WORK = POC / "work/s245-s246"
HEV_BASE = Path("/tmp/hev-3911f79")


def replace(path, old, new, count=1):
    text = path.read_text()
    assert text.count(old) == count, (path, old[:100], text.count(old), count)
    path.write_text(text.replace(old, new))


def copy_source(src, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns(
        ".git", "build", "bin", "obj", "libs", "__pycache__"))


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    hev = WORK / "hev"
    app = WORK / "app"
    plugin = WORK / "plugin"
    copy_source(HEV_BASE, hev)
    copy_source(POC / "android/vpn-lite", app)
    copy_source(POC / "overlay/src/plugins/hev_external_driver_poc", plugin)
    # Reuse the existing test signing identity, without regenerating or exposing it.
    (app / "build").mkdir()
    shutil.copy2(POC / "android/vpn-lite/build/debug.keystore", app / "build/debug.keystore")
    baseline = {}
    for root in (hev, app, plugin):
        for p in sorted(root.rglob("*")):
            if p.is_file() and "build" not in p.relative_to(root).parts:
                baseline[str(p.relative_to(WORK))] = hashlib.sha256(p.read_bytes()).hexdigest()
    (WORK / "baseline-files.json").write_text(json.dumps(baseline, indent=2) + "\n")

    source = hev / "src/hev-flow-stack-owner-context.c"
    replace(source, "#include <time.h>", "#include <time.h>\n#include <sys/uio.h>")
    replace(source, "  flow_stack_owner_perf_metrics_t perf;", """  flow_stack_owner_perf_metrics_t perf;
  int (*probe_outputv)(void *, const struct iovec *, size_t, size_t);
  void *probe_data;
  unsigned probe_mode, probe_inputs, probe_outputs;
""")
    insert = r'''
/* Experiment-only registration: spans are borrowed for this call only. */
void s245_probe_configure(FlowStackOwnerContext *context, unsigned mode,
    int (*outputv)(void *, const struct iovec *, size_t, size_t), void *data)
{
  context->probe_mode = mode;
  context->probe_outputv = outputv;
  context->probe_data = data;
}

static err_t s245_probe_output(FlowStackOwnerContext *context, struct pbuf *p)
{
  struct iovec spans[16];
  struct pbuf *part;
  struct pbuf *tail = NULL, saved = *p;
  size_t count = 0, bytes = 0;
  unsigned seq = ++context->probe_outputs;
  int split = context->probe_mode == 9 && seq == 2 && !p->next && p->len > 28;
  if (split) {
    tail = lwip_owner_context_pbuf_alloc_ram_no_headroom(context->lwip, p->len - 23);
    if (!tail) return ERR_MEM;
    memcpy(tail->payload, (char *)p->payload + 23, p->len - 23);
    /* Make a wrong contiguous read fail: the tail lives in a distinct pool slot. */
    memset((char *)p->payload + 23, 0xa5, p->len - 23);
    p->len = 23;
    p->next = tail;
  }
  fprintf(stderr, "s246 event=lwip_output_enter seq=%u pbuf=%p len=%u tot_len=%u controlled_chain=%d ns=%llu\n",
    seq, (void *)p, p->len, p->tot_len, split, (unsigned long long)flow_stack_owner_now_ns());
  for (part = p; part && count < 16; part = part->next) {
    spans[count].iov_base = part->payload;
    spans[count].iov_len = part->len;
    fprintf(stderr, "s246 event=pbuf_span seq=%u part=%zu pbuf=%p len=%u tot_len=%u\n",
      seq, count, (void *)part, part->len, part->tot_len);
    bytes += part->len;
    count++;
  }
  int rc = part || bytes != p->tot_len ? -2 :
    context->probe_outputv(context->probe_data, spans, count, bytes);
  if (split) {
    memcpy((char *)saved.payload + 23, tail->payload, tail->len);
    *p = saved;
    lwip_owner_context_pbuf_free(context->lwip, tail);
  }
  err_t result = rc == 0 ? ERR_OK : rc == -1 ? ERR_MEM : ERR_IF;
  fprintf(stderr, "s246 event=lwip_output_return seq=%u pbuf=%p rc=%d err=%d ns=%llu\n",
    seq, (void *)p, rc, result, (unsigned long long)flow_stack_owner_now_ns());
  return result;
}

'''
    replace(source, "static err_t\nflow_stack_owner_netif_output(", insert + "static err_t\nflow_stack_owner_netif_output(")
    replace(source, "  if (context->callbacks.output)\n", "  if (context->probe_outputv)\n    return s245_probe_output(context, p);\n  if (context->callbacks.output)\n")
    marker = "  if (hev_socks5_tunnel_owner_credit_reserve(\n          context->hev_runtime, HEV_SOCKS5_OWNER_CREDIT_PACKET) < 0)"
    replace(source, marker, """  unsigned probe_seq = ++context->probe_inputs;
  int probe_fault = probe_seq == 2 ? context->probe_mode : 0;
  fprintf(stderr, "s245 event=lwip_input_enter seq=%u original=%p bytes=%zu mode=%u ns=%llu\\n",
    probe_seq, packet, length, context->probe_mode, (unsigned long long)flow_stack_owner_now_ns());
  if (probe_fault >= 2 && probe_fault <= 4)
    fprintf(stderr, "s245 event=input_fault seq=%u point=%d\\n", probe_seq, probe_fault);
  if (probe_fault == 2 || hev_socks5_tunnel_owner_credit_reserve(
          context->hev_runtime, HEV_SOCKS5_OWNER_CREDIT_PACKET) < 0)""")
    replace(source, "  pbuf = lwip_owner_context_pbuf_alloc(context->lwip, (uint16_t)length);", "  pbuf = probe_fault == 3 ? NULL : lwip_owner_context_pbuf_alloc(context->lwip, (uint16_t)length);")
    replace(source, "  if (lwip_owner_context_pbuf_set_release(\n", "  if (probe_fault == 4 || lwip_owner_context_pbuf_set_release(\n")
    replace(source, "  context->perf.submit_copy_bytes += length;", """  context->perf.submit_copy_bytes += length;
  fprintf(stderr, "s245 event=input_copy seq=%u original=%p pbuf=%p payload=%p bytes=%zu ns=%llu\\n",
    probe_seq, packet, (void *)pbuf, pbuf->payload, length, (unsigned long long)flow_stack_owner_now_ns());""")
    replace(source, "  if ((bytes[0] >> 4) == 4) {", r'''  if (context->probe_mode == 10 && probe_seq == 2 && length >= 28) {
    ip_addr_t sync_destination;
    memset(&sync_destination, 0, sizeof(sync_destination));
    sync_destination.type = IPADDR_TYPE_V4;
    memcpy(&ip_2_ip4(&sync_destination)->addr, bytes + 12, 4);
    struct pbuf *sync_packet = lwip_owner_context_pbuf_alloc_ram_no_headroom(context->lwip, 9);
    if (sync_packet) {
      memcpy(sync_packet->payload, "s245-sync", 9);
      fprintf(stderr, "s246 event=sync_injection input_seq=%u source=controlled-lwip-udp-send\n", probe_seq);
      err_t sync_result = udp_sendto_ctx(context->lwip, context->udp_listener, sync_packet,
          &sync_destination, ((uint16_t)bytes[20] << 8) | bytes[21]);
      fprintf(stderr, "s246 event=sync_result input_seq=%u err=%d\n", probe_seq, sync_result);
      lwip_owner_context_pbuf_free(context->lwip, sync_packet);
    }
  }
  if ((bytes[0] >> 4) == 4) {''')
    # The allocator's exact alloc/free ledger covers all owner-local pbuf pools,
    # including return-header allocations and the input rejection before its hook.
    pool = hev / "src/core/owner_context.c"
    pool.write_text('#include <stdio.h>\n#include <pthread.h>\n#include <time.h>\n' + pool.read_text())
    replace(pool, "  memset(&slot->object, 0, sizeof(slot->object));", """  memset(&slot->object, 0, sizeof(slot->object));
  fprintf(stderr, "s245 event=pool_alloc context=%p pool=%d object=%p used=%zu thread=%lu\\n",
    (void *)context, id, (void *)&slot->object, pool->used_count, (unsigned long)pthread_self());""")
    replace(pool, "  pool->used_count--;\n  return 0;", """  pool->used_count--;
  /* Only after the allocator has reclaimed this object; no borrower may read it. */
  memset(&slot->object, 0xa5, sizeof(slot->object));
  struct timespec probe_time;
  clock_gettime(CLOCK_MONOTONIC, &probe_time);
  fprintf(stderr, "s245 event=pool_free context=%p pool=%d object=%p used=%zu poison=165 thread=%lu ns=%llu\\n",
    (void *)context, id, object, pool->used_count, (unsigned long)pthread_self(),
    (unsigned long long)probe_time.tv_sec * 1000000000ULL + probe_time.tv_nsec);
  return 0;""")
    udp = hev / "src/hev-socks5-session-udp.c"
    replace(udp, "        if (err != ERR_OK) {\n            lwip_owner_context_pbuf_free", """        fprintf(stderr, "s246 event=udp_sendto_result session=%p pbuf=%p err=%d\\n", (void *)self, (void *)p, err);
        if (err != ERR_OK) {
            lwip_owner_context_pbuf_free""")
    replace(udp, """        if (err != ERR_OK) {
            lwip_owner_context_pbuf_free (self->data.lwip, p);
            return -1;
        }""", """        if (err != ERR_OK) {
            lwip_owner_context_pbuf_free (self->data.lwip, p);
            /* S246: this datagram was consumed from the socket. A rejected
             * output handoff must not permanently disable the receive half
             * of this otherwise-live UDP session. Other errors retain their
             * pinned behavior. This correction is experimental, not a port. */
            if (err == ERR_MEM || err == ERR_IF) {
                fprintf(stderr, "s246 event=output_datagram_discard session=%p err=%d keep_receive=1\\n", (void *)self, err);
                return 1;
            }
            return -1;
        }""")
    replace(udp, "static void\nudp_frame_free (HevSocks5UDPFrame *frame)\n{", """static void
udp_frame_free (HevSocks5UDPFrame *frame)
{
    fprintf(stderr, "s245 event=udp_frame_free frame=%p pbuf=%p\\n", (void *)frame, (void *)frame->data);""")
    replace(udp, "    frame->data = p;", "    fprintf(stderr, \"s245 event=udp_frame_alloc session=%p frame=%p pbuf=%p\\n\", (void *)self, (void *)frame, (void *)p);\n    frame->data = p;")

    oi3 = plugin / "owner_inline_oi3.c"
    replace(oi3, "#define OI3_TUN_FLOW_TIMEOUT_NS 5000000000ULL", "#define OI3_TUN_FLOW_TIMEOUT_NS 25000000000ULL /* registered experiment bound */")
    replace(oi3, "static int\noi3_submit_pending_tun (", (HERE / "probe.inc").read_text() + "\nstatic int\noi3_submit_pending_tun (")
    replace(oi3, "tm->api.submit (tm->context, entry->packet, length)", "s245_submit (tm, entry->packet, length)")
    replace(oi3, "  tm->packet_submitted++;\n  if (tm->tun_mode && tm->multi_mode)", "  tm->packet_submitted++;\n  oi3_refresh_tun_flow_deadline(tm);\n  if (tm->tun_mode && tm->multi_mode)")
    replace(oi3, "  memset (&tm->runtime_identity, 0, sizeof (tm->runtime_identity));", """  void (*configure_probe)(FlowStackOwnerContext *, unsigned,
      int (*)(void *, const struct iovec *, size_t, size_t), void *) =
      dlsym(tm->api.handle, "s245_probe_configure");
  if (!configure_probe) return -1;
  configure_probe(tm->context, s245_mode(), s246_outputv, tm);
  memset (&tm->runtime_identity, 0, sizeof (tm->runtime_identity));""")
    replace(oi3, "    tm->api.destroy (tm->context); tm->context = NULL;\n    tm->lwip_context = NULL;", """    s245_credits(tm, "after-stop");
    fprintf(stderr, "s245 event=final_buffers input_alloc=%u input_free=%u output_alloc=%u output_free=%u owner=%u generation=%llu\\n",
      s245_allocs, s245_frees, s246_allocs, s246_frees, vlib_get_thread_index(), (unsigned long long)tm->generation);
    tm->api.destroy (tm->context); tm->context = NULL;
    tm->lwip_context = NULL;""")
    replace(oi3, "        if (reply) (void) sendto (fd, buf, (size_t)n, 0, (struct sockaddr *)&peer, plen);", """        fprintf(stderr, "s245 event=endpoint_receive bytes=%zd payload=%.*s\\n", n, (int)n, buf);
        if (getenv("SAKAMOTO_S245_MODE") && atoi(getenv("SAKAMOTO_S245_MODE")) == 1) usleep(250000);
        ssize_t sent = reply ? sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&peer, plen) : -1;
        fprintf(stderr, "s245 event=endpoint_reply bytes=%zd result=%zd\\n", n, sent);""")

    native = app / "native/vpn_fd_probe.c"
    replace(native, "../../../overlay/src/plugins/hev_external_driver_poc/oi2_broker_contract.h", "../../plugin/oi2_broker_contract.h")
    replace(native, '        setenv("LD_LIBRARY_PATH", native_dir, 1);', '''        setenv("LD_LIBRARY_PATH", native_dir, 1);
        char probe_path[PATH_BUF_SIZE], probe_mode[16] = "0";
        snprintf(probe_path, sizeof(probe_path), "%s/s245-mode", app_files);
        FILE *probe_file = fopen(probe_path, "r");
        if (probe_file) { if (!fgets(probe_mode, sizeof(probe_mode), probe_file)) strcpy(probe_mode, "0"); fclose(probe_file); }
        setenv("SAKAMOTO_S245_MODE", probe_mode, 1);''')
    java = app / "src/main/java/com/sakamoto/snort/vpnlite/SnortVpnService.java"
    original = java.read_text()
    begin = original.index("                    try (DatagramSocket socket = new DatagramSocket()) {", original.index("private void startControlledOi3AppPacket"))
    end = original.index("                }\n                appendProbeLog", begin)
    java.write_text(original[:begin] + '''                    try (DatagramSocket socket = new DatagramSocket()) {
                        socket.setSoTimeout(4000);
                        for (int sequence = 1; sequence <= 3; sequence++) {
                            byte[] expected = ("s245-payload-" + sequence).getBytes(StandardCharsets.US_ASCII);
                            socket.send(new DatagramPacket(expected, expected.length, destination, port));
                            String packetResult = "TIMEOUT";
                            int replyBytes = 0;
                            String replyText = "";
                            try {
                                byte[] reply = new byte[256];
                                DatagramPacket response = new DatagramPacket(reply, reply.length);
                                socket.receive(response);
                                replyBytes = response.getLength();
                                replyText = new String(reply, 0, replyBytes, StandardCharsets.US_ASCII);
                                packetResult = java.util.Arrays.equals(expected, java.util.Arrays.copyOf(reply, replyBytes)) ? "EXACT" : "MISMATCH";
                            } catch (java.net.SocketTimeoutException timeout) { }
                            appendProbeLog(new File(getFilesDir(), "logs/s245-app.log"),
                                "s245 event=app_result seq=" + sequence + " result=" + packetResult +
                                " sent=" + expected.length + " received=" + replyBytes +
                                " local_port=" + socket.getLocalPort() + " payload=" + replyText);
                            Thread.sleep(250L);
                        }
                        result = "S245_RECORDED";
                    }
''' + original[end:])
    build = app / "scripts/build-debug-apk.sh"
    replace(build, 'poc_dir="$(cd -- "${app_dir}/../.." && pwd)"', f'poc_dir="{POC}"')
    replace(build, 'repo_root="$(cd -- "${poc_dir}/../.." && pwd)"', f'repo_root="{REPO}"')
    # Do not invoke historical host signatures or alter any shared stage.
    manifest = {"repo_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
                "hev_base": str(HEV_BASE), "hev_upstream_revision": "3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70",
                "hev_base_is_unversioned_patched_fixture": True,
                "baseline_manifest": "baseline-files.json", "scope": "experiment-only"}
    (WORK / "source-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(WORK)


if __name__ == "__main__":
    main()
