FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    curl \
    iproute2 \
    iptables \
    iputils-ping \
    libmnl-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    netcat-openbsd \
    nftables \
    pkg-config \
    procps \
    tcpdump \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work/sakamoto-snort/experiments/vpp-nfq-poc

CMD ["/bin/bash"]
