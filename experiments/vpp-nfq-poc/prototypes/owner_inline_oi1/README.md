# Owner-inline OI-1 state-model prototype

This is throwaway logic code for one question:

> Can an owner-inline Flow Stack move between `RUNNABLE`, `WAITING`,
> `STOPPED`, and `FAULT` without unconditional self-requeue, while rejecting
> stale or duplicate wake tokens?

It deliberately models only the module seam. It does not model HEV, lwIP,
VPP buffers, file descriptors, or Android. The real POC must prove those
properties separately.

Run it with:

```text
rtk python3 experiments/vpp-nfq-poc/prototypes/owner_inline_oi1/state_machine.py
```

Commands: `drive`, `wake <generation> <sequence> <cause>`, `stop`, `fault`,
`reset`, and `quit`. The complete state is rendered after each command.
