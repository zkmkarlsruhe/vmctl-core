# vmctl emulator build: qemu-system-ppc (mac99/g3beige) with the Screamer (AWACS) onboard audio
# codec, on current upstream QEMU. Screamer is not upstream; the device comes from Mark
# Cave-Ayland's fork (github.com/mcayland/qemu, branch screamer-v10.2.0 @ a3a5fd79, patches
# 0001-0011, unchanged) and is ported to QEMU 11.1 (0012). 0013 undoes the TB-lookup slowdown of
# upstream 088caf3de4 (TCGTBCPUState passed by value), 0014 lets ppc skip the get_tb_cpu_state hook
# call on every TB lookup. Tiger CPU loop: 12.2 s -> 12.0 s; the 7.1.94 fork does 9.5 s.
# 0015 keeps the screamer playing across sample rate changes (silent Tiger after a work ran)
# 0016 skips clean mmu indexes on a page flush (Mac OS 9 idle: host CPU 65 % -> 30 %)
# 0017 reads guest audio at the sample rate (Mac OS X lost a quarter of the audible sound), 0018 limits the
# DBDMA register index, 0019 fixes the Screamer codec readback and register order
# (vmctl notes 2026-11-01-qemu-screamer-upgrade, section Bisect 10.0 -> 10.1). OpenBIOS gets
# the matching AWACS node from mcayland/openbios (branch screamer-v9.1.0 @ 3d3c61d2, net patch of
# that branch), applied to the OpenBIOS tree the QEMU tarball ships, and is rebuilt from source:
# the fork's prebuilt openbios-ppc blob is not used.
#
# PPC guests run under host libvirt, not in a container, so this image only BUILDS. The last
# stage holds nothing but the install prefix, extract it on the host:
#
#   V=$(cat VERSION)
#   docker build --build-arg IMAGE_VERSION=$V --output type=local,dest=/tmp/qemu-ppc-$V .
#   sudo cp -a /tmp/qemu-ppc-$V/opt/qemu-screamer-$V /opt/
#
# The binary is linked against Debian 13 libraries (the host OS): runtime needs libglib2.0-0t64
# libpixman-1-0 libslirp0 zlib1g libpng16-16t64 libfdt1 libpulse0 libpipewire-0.3-0t64 libsdl2-2.0-0 (SDL: local
# display for exhibition, the process backend of evmctl runs qemu without libvirt).
# Side by side with older prefixes; a base selects its prefix with hw.emulator in the catalog.
# Since QEMU 8.2 an onboard audio device no longer falls back to the first -audiodev: the domain
# must pass -global screamer.audiodev=audio1 (accepted by the 7.1.94 fork too), or QEMU exits
# with "no default audio driver available".

ARG DEBIAN=debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0

FROM ${DEBIAN} AS build
ARG QEMU_VERSION=11.1.3
ARG QEMU_SHA256=5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22
ARG IMAGE_VERSION=11.1.3-zkm5
# JOBS + nice: the build shares the host with running emulated guests
ARG JOBS=4
ENV DEBIAN_FRONTEND=noninteractive
# snapshot.debian.org at the base image's build timestamp, same scheme as emulators/qemu-m68k
RUN sed -i -E '/^# http:\/\/snapshot\.debian\.org\/archive\//{s/^# /URIs: /;n;d}' /etc/apt/sources.list.d/debian.sources \
    && sed -i '/^URIs: http:\/\/snapshot\.debian\.org\//a Check-Valid-Until: no' /etc/apt/sources.list.d/debian.sources \
    && ! grep -q '^URIs: http://deb\.debian\.org' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
      build-essential ninja-build pkg-config python3 python3-venv bzip2 xz-utils patch \
      libglib2.0-dev libpixman-1-dev libslirp-dev zlib1g-dev libpng-dev libfdt-dev \
      libpulse-dev libpipewire-0.3-dev libsdl2-dev \
      gcc-powerpc-linux-gnu binutils-powerpc-linux-gnu fcode-utils xsltproc \
    && rm -rf /var/lib/apt/lists/*
ADD --checksum=sha256:${QEMU_SHA256} https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz /src/
COPY patches/ /src/patches/
WORKDIR /src
RUN tar xf qemu-${QEMU_VERSION}.tar.xz && cd qemu-${QEMU_VERSION} \
    && for p in /src/patches/qemu/*.patch; do patch -p1 < "$p"; done \
    && cd roms/openbios && for p in /src/patches/openbios/*.patch; do patch -p1 < "$p"; done
# OpenBIOS release build for ppc (as openbios' own release workflow), replaces the shipped blob
WORKDIR /src/qemu-${QEMU_VERSION}/roms/openbios
RUN ./config/scripts/switch-arch ppc && nice -n 19 make -j${JOBS} V=1 \
    && cp obj-ppc/openbios-qemu.elf /src/qemu-${QEMU_VERSION}/pc-bios/openbios-ppc
WORKDIR /src/qemu-${QEMU_VERSION}/build
RUN ../configure --prefix=/opt/qemu-screamer-${IMAGE_VERSION} --target-list=ppc-softmmu \
      --audio-drv-list=pa,pipewire --enable-slirp --enable-vnc --enable-sdl --enable-png --enable-tools \
      --disable-docs --disable-user --disable-guest-agent --disable-werror \
    && nice -n 19 ninja -j${JOBS} qemu-system-ppc qemu-img \
    && nice -n 19 ninja -j${JOBS} install
# smoke: the mac99 machine instantiates the screamer codec and binds it to the given audiodev
RUN P=/opt/qemu-screamer-${IMAGE_VERSION}; $P/bin/qemu-system-ppc --version \
    && printf 'info qtree\nquit\n' | $P/bin/qemu-system-ppc -M mac99,via=pmu -cpu g4 -nodefaults \
         -display none -S -audiodev none,id=audio1 -global screamer.audiodev=audio1 \
         -monitor stdio > /tmp/qtree.txt \
    && grep -q 'dev: screamer' /tmp/qtree.txt && grep -q 'audiodev = "audio1"' /tmp/qtree.txt \
    && cp -a /src/patches $P/share/qemu-screamer-patches

FROM scratch
ARG IMAGE_VERSION=11.1.3-zkm5
COPY --from=build /opt/qemu-screamer-${IMAGE_VERSION} /opt/qemu-screamer-${IMAGE_VERSION}
