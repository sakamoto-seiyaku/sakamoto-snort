/* S245/S246 experiment only. Included in the isolated OI3 translation unit. */
#include <sys/uio.h>

extern vlib_node_registration_t s246_return_node;
static unsigned s245_inputs, s246_outputs;
static unsigned s245_allocs, s245_frees, s246_allocs, s246_frees;
static unsigned s246_callback_active;

static int s245_mode(void)
{
  const char *mode = getenv("SAKAMOTO_S245_MODE");
  return mode ? atoi(mode) : 0;
}

static u32 s245_hash(const void *bytes, size_t length)
{
  const u8 *p = bytes;
  u32 h = 2166136261U;
  for (size_t i = 0; i < length; ++i) h = (h ^ p[i]) * 16777619U;
  return h;
}

/* One pure, bounded UDP4 parser used at both directions of this test seam.
 * This is not the product policy parser or a claim of S237 completion. */
static int s245_parse(const u8 *p, size_t n)
{
  return n >= 28 && p[0] == 0x45 && p[9] == 17 &&
    (((size_t)p[2] << 8) | p[3]) == n &&
    (((size_t)p[24] << 8) | p[25]) == n - 20 &&
    oi3_checksum(p, 20) == 0;
}

static void s245_credits(oi3_main_t *tm, const char *phase)
{
  oi3_runtime_identity_t id;
  memset(&id, 0, sizeof(id));
  tm->api.runtime_identity(tm->context, &id);
  for (unsigned i = 0; i < OI3_HEV_CREDIT_COUNT; ++i)
    fprintf(stderr, "s245 event=credit phase=%s category=%u used=%zu peak=%zu alloc=%zu free=%zu reject=%zu generation=%llu owner=%u\n",
      phase, i, id.credit_used[i], id.credit_high_water[i],
      id.credit_reserves[i], id.credit_releases[i], id.credit_rejects[i],
      (unsigned long long)tm->generation, vlib_get_thread_index());
}

static int s245_submit(oi3_main_t *tm, const void *packet, size_t length)
{
  vlib_main_t *vm = vlib_get_main();
  u32 index;
  unsigned seq = ++s245_inputs;
  if (length > vlib_buffer_get_default_data_size(vm) ||
      vlib_buffer_alloc(vm, &index, 1) != 1) return -1;
  s245_allocs++;
  vlib_buffer_t *b = vlib_get_buffer(vm, index);
  b->current_data = 0;
  b->current_length = length;
  memcpy(b->data, packet, length);
  fprintf(stderr, "s245 event=input_enter seq=%u buffer=%u ptr=%p bytes=%zu hash=%u parser=%d owner=%u generation=%llu ns=%llu\n",
    seq, index, b->data, length, s245_hash(b->data, length),
    s245_parse(b->data, length), vlib_get_thread_index(),
    (unsigned long long)tm->generation, (unsigned long long)oi3_now_ns());
  int rc = tm->api.submit(tm->context, b->data, length);
  fprintf(stderr, "s245 event=input_return seq=%u buffer=%u rc=%d ns=%llu\n",
    seq, index, rc, (unsigned long long)oi3_now_ns());
  fprintf(stderr, "s245 event=adapter_completion seq=%u buffer=%u policy=ALLOW transport=%s\n",
    seq, index, rc == 0 ? "ACCEPTED" : "REJECTED");
  vlib_buffer_free_one(vm, index);
  s245_frees++;
  fprintf(stderr, "s245 event=input_free seq=%u buffer=%u alloc=%u free=%u ns=%llu\n",
    seq, index, s245_allocs, s245_frees, (unsigned long long)oi3_now_ns());
  /* Allocate before accessing: never poison a freed allocation directly. */
  u32 reused[64], count = 0, matched = 0;
  for (; count < 64; ++count) {
    if (vlib_buffer_alloc(vm, &reused[count], 1) != 1) break;
    s245_allocs++;
    vlib_buffer_t *owned = vlib_get_buffer(vm, reused[count]);
    memset(owned->data, 0xa5, length);
    if (reused[count] == index) { matched = 1; ++count; break; }
  }
  fprintf(stderr, "s245 event=input_reuse seq=%u buffer=%u matched=%u allocations=%u poison=165 ns=%llu\n",
    seq, index, matched, count, (unsigned long long)oi3_now_ns());
  vlib_buffer_free(vm, reused, count);
  s245_frees += count;
  s245_credits(tm, "after-submit");
  return rc;
}

typedef struct {
  u64 generation;
  u32 seq, owner, hash, provenance, direction, controlled_sync;
} s246_metadata_t;
STATIC_ASSERT(sizeof(s246_metadata_t) <= sizeof(((vlib_buffer_t *)0)->opaque),
              "test metadata fits the isolated graph overlay");

/* Borrowed spans only during this callback; no pbuf ownership crosses it. */
static int s246_outputv(void *data, const struct iovec *parts,
                        size_t count, size_t length)
{
  oi3_main_t *tm = data;
  vlib_main_t *vm = vlib_get_main();
  unsigned seq = ++s246_outputs;
  int mode = s245_mode();
  int rc = -1;
  u32 index;
  s246_callback_active = 1;
  fprintf(stderr, "s246 event=callback_enter seq=%u spans=%zu bytes=%zu owner=%u generation=%llu ns=%llu\n",
    seq, count, length, vlib_get_thread_index(),
    (unsigned long long)tm->generation, (unsigned long long)oi3_now_ns());
  if (length > vlib_buffer_get_default_data_size(vm) ||
      (mode == 6 && seq == 2) || vlib_buffer_alloc(vm, &index, 1) != 1) {
    fprintf(stderr, "s246 event=allocation_reject seq=%u injected=%d\n", seq, mode == 6 && seq == 2);
    goto done;
  }
  s246_allocs++;
  tm->vpp_buffers_allocated++;
  tm->vpp_buffer_residue++;
  vlib_buffer_t *b = vlib_get_buffer(vm, index);
  b->current_data = 0;
  b->current_length = length;
  size_t offset = 0;
  for (size_t i = 0; i < count; ++i) {
    if (parts[i].iov_len > length - offset) goto reject;
    memcpy(b->data + offset, parts[i].iov_base, parts[i].iov_len);
    offset += parts[i].iov_len;
  }
  if (offset != length || !s245_parse(b->data, length)) goto reject;
  fprintf(stderr, "s246 event=copy seq=%u buffer=%u bytes=%zu calls=%zu hash=%u\n",
    seq, index, length, count, s245_hash(b->data, length));
  /* Reverse only the historical fixture's address projection, in place. */
  const struct sockaddr_in *src = (const void *)&tm->source_address;
  const struct sockaddr_in *dst = (const void *)&tm->target_address;
  memcpy(b->data + 12, &dst->sin_addr, 4);
  memcpy(b->data + 16, &src->sin_addr, 4);
  b->data[10] = b->data[11] = 0;
  u16 checksum = oi3_checksum(b->data, 20);
  b->data[10] = checksum >> 8; b->data[11] = checksum;
  b->data[26] = b->data[27] = 0;
  checksum = oi3_l4_checksum(b->data, length, 4, 17, 20);
  b->data[26] = checksum >> 8; b->data[27] = checksum;
  s246_metadata_t *meta = (void *)b->opaque;
  *meta = (s246_metadata_t){ .generation = tm->generation, .seq = seq,
    .owner = vlib_get_thread_index(), .hash = s245_hash(b->data, length),
    .provenance = 1, .direction = 1,
    .controlled_sync = length == 37 && !memcmp(b->data + 28, "s245-sync", 9) };
  if (mode == 7 && seq == 2) {
    rc = -2;
    fprintf(stderr, "s246 event=submit_reject seq=%u buffer=%u injected=1 point=before-native-frame-accept\n", seq, index);
    goto reject;
  }
  vlib_frame_t *frame = vlib_get_frame_to_node(vm, s246_return_node.index);
  u32 *to = vlib_frame_vector_args(frame);
  to[0] = index;
  frame->n_vectors = 1;
  vlib_put_frame_to_node(vm, s246_return_node.index, frame);
  fprintf(stderr, "s246 event=frame_accept seq=%u buffer=%u provenance=FLOW_STACK_RETURN direction=INPUT ns=%llu\n",
    seq, index, (unsigned long long)oi3_now_ns());
  tm->output_packets++;
  tm->output_direct++;
  tm->return_rewritten++;
  rc = 0;
  goto done;
reject:
  vlib_buffer_free_one(vm, index);
  s246_frees++;
  tm->vpp_buffers_freed++;
  tm->vpp_buffer_residue--;
  fprintf(stderr, "s246 event=output_free seq=%u buffer=%u holder=callback alloc=%u free=%u\n",
    seq, index, s246_allocs, s246_frees);
done:
  s246_callback_active = 0;
  fprintf(stderr, "s246 event=callback_return seq=%u rc=%d ns=%llu\n",
    seq, rc, (unsigned long long)oi3_now_ns());
  return rc;
}

VLIB_NODE_FN(s246_return_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  oi3_main_t *tm = &oi3_main;
  u32 *from = vlib_frame_vector_args(frame);
  for (u32 i = 0; i < frame->n_vectors; ++i) {
    vlib_buffer_t *b = vlib_get_buffer(vm, from[i]);
    s246_metadata_t meta = *(s246_metadata_t *)(void *)b->opaque;
    int valid = !s246_callback_active && meta.owner == vlib_get_thread_index() &&
      meta.generation == tm->generation && meta.provenance == 1 && meta.direction == 1 &&
      meta.hash == s245_hash(b->data, b->current_length) && s245_parse(b->data, b->current_length);
    fprintf(stderr, "s246 event=graph_enter seq=%u buffer=%u valid=%d owner=%u generation=%llu ns=%llu\n",
      meta.seq, from[i], valid, vlib_get_thread_index(),
      (unsigned long long)tm->generation, (unsigned long long)oi3_now_ns());
    if (!valid) snprintf(tm->error, sizeof(tm->error), "s246-graph-invariant");
    else if (meta.controlled_sync)
      fprintf(stderr, "s246 event=controlled_sync_completion seq=%u tun_writes=0\n", meta.seq);
    else if (s245_mode() == 5 && meta.seq == 2)
      fprintf(stderr, "s246 event=policy seq=%u verdict=DROP tun_writes=0\n", meta.seq);
    else {
      fprintf(stderr, "s246 event=policy seq=%u verdict=ALLOW\n", meta.seq);
      int fd = s245_mode() == 8 && meta.seq == 2 ? -1 : tm->tun_fd;
      ssize_t n = write(fd, b->data, b->current_length);
      int saved_errno = n < 0 ? errno : 0;
      if (n == b->current_length) tm->tun_output_packets++;
      fprintf(stderr, "s246 event=tun_completion seq=%u bytes=%u result=%zd errno=%d injected=%d\n",
        meta.seq, b->current_length, n, saved_errno, fd == -1);
    }
    vlib_buffer_free_one(vm, from[i]);
    s246_frees++;
    tm->vpp_buffers_freed++;
    tm->vpp_buffer_residue--;
    fprintf(stderr, "s246 event=output_free seq=%u buffer=%u holder=graph alloc=%u free=%u\n",
      meta.seq, from[i], s246_allocs, s246_frees);
  }
  (void)node;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE(s246_return_node) = {
  .name = "s245-s246-return-parser-policy-completion",
  .function = s246_return_node_fn,
  .type = VLIB_NODE_TYPE_INTERNAL, .vector_size = sizeof(u32),
};
