# Vendored Netfilter Userspace Libraries

This directory vendors fixed upstream netfilter userspace source releases for
the Android NDK daemon build.

| Library | Version | Source |
| --- | --- | --- |
| libmnl | 1.0.5 | https://www.netfilter.org/projects/libmnl/files/libmnl-1.0.5.tar.bz2 |
| libnetfilter_queue | 1.0.5 | https://www.netfilter.org/projects/libnetfilter_queue/files/libnetfilter_queue-1.0.5.tar.bz2 |
| libnfnetlink | 1.0.2 | https://www.netfilter.org/projects/libnfnetlink/files/libnfnetlink-1.0.2.tar.bz2 |

Imported archive checksums:

```text
274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525  libmnl-1.0.5.tar.bz2
f9ff3c11305d6e03d81405957bdc11aea18e0d315c3e3f48da53a24ba251b9f5  libnetfilter_queue-1.0.5.tar.bz2
b064c7c3d426efb4786e60a8e6859b82ee2f2c5e49ffeea640cfe4fe33cbc376  libnfnetlink-1.0.2.tar.bz2
```

The upstream `COPYING` files are preserved inside each library directory. The
NDK build links these libraries statically into `sucre-snort-ndk`.
