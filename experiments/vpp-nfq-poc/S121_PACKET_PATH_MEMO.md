# SAKAMOTO-121 Packet-Path Memo

## Validated

- A VPP worker buffer reached a real `flow_stack_owner_submit()` call and
  entered the owner-local lwIP UDP listener.
- The receive callback and lwIP netif-output callback both ran on the same
  pthread as the target VPP worker.
- The output was a valid UDP echo (33 bytes); a new VPP egress buffer received
  the pbuf contents and was freed by the worker.
- The measured bounded copy ledger for this path is:

  ```text
  VPP ingress buffer -> lwIP pbuf: 33 bytes
  lwIP output pbuf -> VPP egress buffer: 33 bytes
  ```

- Ingress and egress VPP buffers both balanced at `1/1`; no queue error or
  owner residue was reported.

## Important constraint

The default owner credit policy allows one in-flight pbuf. A synchronous
receive-callback echo needs two pbuf credits because the ingress pbuf is still
held when the output pbuf is allocated. The POC made this explicit with a
bounded credit limit of two. This is a resource/lifecycle rule to carry into
the packet-path API; it is not evidence for zero-copy.

## Design decision

POC-121 is a GO for a worker-local packet-path seam with explicit ownership and
copy accounting. Keep the first implementation copy-based and make ownership
transfer/release observable. Do not infer zero-copy, multi-worker replication,
or production lwIP changes from this one-packet proof. The next packet-path
work should test asynchronous scheduling and multiple buffers under the same
credit ledger.
