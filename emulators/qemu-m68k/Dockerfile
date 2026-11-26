# vmctl emulator image: qemu-system-m68k (q800) + qemu-img, QEMU built from source with the
# vmctl q800 patches (research/70g). One image per emulator version; a golden pins the image id
# (sha256 config digest) it was built and verified on, so old goldens keep their own QEMU.
#
#   docker build -t vmctl-emu/qemu-m68k:$(cat VERSION) emulators/qemu-m68k
# QEMU's m68k qtests run in the build stage, against the tree that was just compiled: a failing
# qtest fails the image build (kaniko keeps no build tree for a separate test stage).
#
# Audio: built with the PipeWire audiodev (zkm2): `-audiodev pipewire,out.name=<sink>` plays the
# Apple Sound Chip into a host null sink through the bind-mounted PipeWire socket (rvmc capture).
# pipewire-bin carries client.conf + the client modules; without them QEMU dies at start with
# "Could not create PipeWire context".
#
# Contents: /usr/local/bin/qemu-system-m68k, /usr/local/bin/qemu-img, socat (agent bridge),
# /usr/local/share/qemu/ (firmware/keymaps), /usr/local/share/vmctl/classicvirtio-declrom.
# No Apple ROM, no guest disk: those stay host-side (ROM = host prerequisite, by checksum).

ARG DEBIAN=debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
# Debian packages come from snapshot.debian.org at the base image's own build timestamp: the
# official images record it as a comment above each URIs line in debian.sources, for debian and
# debian-security alike. The digest pin is therefore the only pin: a rebuild years later resolves
# the same build deps and runtime libraries, and a Renovate digest bump moves the snapshot with
# it. (A separate SNAPSHOT arg lagged the digest on 2026-10-11: the new base shipped
# libpcre2-8-0 from trixie-security, the old snapshot's libpcre2-dev wanted the older one, apt
# refused the downgrade.) apt still verifies the archive signatures.

FROM ${DEBIAN} AS build
ARG QEMU_VERSION=11.1.1
ARG QEMU_SHA256=079ffbff8a7111bbc89022107cbabf3bbfd614d5fc9d7cc675991196aca12482
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -E '/^# http:\/\/snapshot\.debian\.org\/archive\//{s/^# /URIs: /;n;d}' /etc/apt/sources.list.d/debian.sources \
    && sed -i '/^URIs: http:\/\/snapshot\.debian\.org\//a Check-Valid-Until: no' /etc/apt/sources.list.d/debian.sources \
    && ! grep -q '^URIs: http://deb\.debian\.org' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
      build-essential ninja-build pkg-config python3 python3-venv bzip2 xz-utils patch \
      libglib2.0-dev libpixman-1-dev libslirp-dev zlib1g-dev libpng-dev libfdt-dev \
      libpipewire-0.3-dev \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:${QEMU_SHA256} https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz /src/
COPY patches/ /src/patches/
WORKDIR /src
RUN tar xf qemu-${QEMU_VERSION}.tar.xz && cd qemu-${QEMU_VERSION} \
    && for p in /src/patches/*.patch; do patch -p1 < "$p"; done
WORKDIR /src/qemu-${QEMU_VERSION}/build
RUN ../configure --prefix=/usr/local --target-list=m68k-softmmu \
      --enable-slirp --enable-vnc --enable-png --enable-tools --enable-pipewire \
      --disable-docs --disable-user --disable-guest-agent --disable-werror \
    && ninja qemu-system-m68k qemu-img \
    && ninja install
RUN make check-qtest-m68k > /tmp/qtest.log 2>&1; rc=$?; tail -40 /tmp/qtest.log; exit $rc

FROM ${DEBIAN}
ARG QEMU_VERSION=11.1.1
ARG IMAGE_VERSION=11.1.1-zkm2
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i -E '/^# http:\/\/snapshot\.debian\.org\/archive\//{s/^# /URIs: /;n;d}' /etc/apt/sources.list.d/debian.sources \
    && sed -i '/^URIs: http:\/\/snapshot\.debian\.org\//a Check-Valid-Until: no' /etc/apt/sources.list.d/debian.sources \
    && ! grep -q '^URIs: http://deb\.debian\.org' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
      libglib2.0-0t64 libpixman-1-0 libslirp0 zlib1g libpng16-16t64 libfdt1 socat \
      libpipewire-0.3-0t64 pipewire-bin \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/qemu-system-m68k /usr/local/bin/qemu-img /usr/local/bin/
COPY --from=build /usr/local/share/qemu/ /usr/local/share/qemu/
# classicvirtio declaration ROM (MIT, Elliot Nunn, release "latest" 2025-02-04): absolute tablet
# for System 7 via -device nubus-virtio-mmio,romfile=... -device virtio-tablet-device (slot C,
# needs 32-bit addressing in PRAM, research/70g §3)
COPY classicvirtio/declrom /usr/local/share/vmctl/classicvirtio-declrom
COPY classicvirtio/LICENSE /usr/local/share/vmctl/classicvirtio-LICENSE
COPY patches/ /usr/local/share/vmctl/qemu-patches/
RUN ldd /usr/local/bin/qemu-system-m68k /usr/local/bin/qemu-img | (! grep "not found") \
    && qemu-system-m68k --version && qemu-img --version
LABEL org.opencontainers.image.title="vmctl-emu/qemu-m68k" \
      org.opencontainers.image.version="${IMAGE_VERSION}" \
      org.opencontainers.image.source="https://git.zkm.de/MuTech/conservation/vmctl/vmctl-core" \
      org.opencontainers.image.licenses="GPL-2.0-only AND MIT" \
      vmctl.emulator="qemu-m68k" vmctl.qemu.version="${QEMU_VERSION}" \
      vmctl.qemu.patches="0001 scsi-disk READ TOC CONTROL/BCD (q800); 0002 quirk_mode_page_truncated test; 0003 q800 CPU-ID sub-word read"
USER 65534:65534
ENTRYPOINT []
CMD ["qemu-system-m68k", "--version"]
