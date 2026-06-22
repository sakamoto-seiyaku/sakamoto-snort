FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    ccache \
    clang \
    cmake \
    curl \
    git \
    iproute2 \
    iptables \
    iputils-ping \
    libmnl-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    libunwind8 \
    netcat-openbsd \
    ninja-build \
    nftables \
    pkg-config \
    procps \
    python3 \
    sudo \
    tcpdump \
  && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /usr/lib/ccache \
  && ln -sf /usr/bin/ccache /usr/lib/ccache/c++

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    python3-ply \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    libunwind-dev \
  && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    libiberty-dev \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /work/sakamoto-snort/experiments/vpp-nfq-poc

CMD ["/bin/bash"]
