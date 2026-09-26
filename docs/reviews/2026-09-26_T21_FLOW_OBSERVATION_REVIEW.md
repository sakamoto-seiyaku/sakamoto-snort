# T21 review closure

Fixed point: `9fa98afc6e9d9a0ae34070595f9f1bdf64c80dbe`.
Review scope: the explicitly owned T21 working-tree files, excluding all 34
pre-existing dirty files recorded in the evidence baseline. The originating
spec is SAKAMOTO-272 under SAKAMOTO-251 and the current unified rule-engine
specification. Two independent reviewers applied the code-review skill's
Standards and Spec axes; later passes reviewed the fixes and evidence.

## Standards

Closed findings:

- JNI status queries originally attempted to start ingestion. Startup now
  belongs to RuntimeService's explicit post-policy-readiness lifecycle.
- An authenticated but silent peer could hold the pending negotiation slot.
  A main-thread timerfd now expires it after two seconds without consuming the
  generation's successful claim. The actual Linux socket test verifies expiry
  and subsequent successful claim.
- The first evidence verifier counted identities independently but did not
  compare identities between boundaries. Two rehashed substitutions reproduced
  this weakness. The final verifier compares cross-stage token/metadata maps
  and native/endpoint/capture payload maps and rejects all eleven mutations.

The final reviewer confirmed no outstanding documented-standard findings or
material baseline smell. Ownership ordering, barrier-protected adoption,
join-before-unmap teardown, API harness updates and bounded report claims were
reviewed. Both retained PASS results bind the final verifier
`f1f241530cb080de5b09dc173b7d9600ed5a5323f422f44e46cece73fabc3421`.

## Spec

Closed finding: policy-node basic accounting omitted valid primary-handoff
capacity bypasses. Terminal accounting now covers the final logical IP packet
exactly once, before fragment fanout. Invalid envelopes lack valid IP facts.
The actual zero-credit Linux regression proves continued echo delivery and
exact accounting while primary rejection counters increase.

The final reviewer independently reran Linux verification and Android
verification with all then-current semantic mutations. Both passed the same
Product source closure `861e3ba14230f1505518ef9d6e080089746b8e98e0a0e68ec60a6d0f3eb5a1a9`.
Platform-separated coverage satisfies the ticket: Linux proves full queues and
consumer death; Android proves representative Root/VPN traffic, quiet flush,
END, reuse and process/fd/notification wiring. No concrete scope creep or
remaining spec finding was identified.

The later identity-verifier strengthening was reviewed under Standards; it did
not change Product source or weaken coverage. Longer Android UDP pressure
remains HOLD, prior failures remain retained, and no Android queue-saturation
or persistent-history claim is made.

Final counts: Standards 0 open (3 closed); Spec 0 open (1 closed).
