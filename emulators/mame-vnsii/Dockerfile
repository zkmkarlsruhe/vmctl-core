# vmctl emulator image: MAME with the VNS-II SCSI video-analyser device and a MIDI bridge.
# One image per emulator version, as with qemu-m68k.
#
#   docker build -t vmctl-emu/mame-vnsii:$(cat VERSION) emulators/mame-vnsii
#
# Contents: /usr/local/bin/vnsii. No Apple ROM, no VNS-II EPROM, no work disk: those stay host-side.

FROM ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b AS build
ARG MAME_TAG=mame0289
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git python3 libsdl2-dev libsdl2-ttf-dev libfontconfig1-dev libpulse-dev \
    libasound2-dev libxinerama-dev libxi-dev libgl-dev ca-certificates
COPY patches/ /patches/
RUN git clone --depth 1 --branch ${MAME_TAG} https://github.com/mamedev/mame /src
WORKDIR /src
RUN git apply /patches/*.patch \
 && make SUBTARGET=vnsii SOURCES=src/mame/apple/macquadra605.cpp USE_QTDEBUG=0 NO_USE_MIDI=1 \
    NO_USE_PORTAUDIO=1 REGENIE=1 -j"$(nproc)"

FROM ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libsdl2-2.0-0 libsdl2-ttf-2.0-0 libfontconfig1 libpulse0 libasound2t64 libxinerama1 libxi6 \
    libgl1 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/vnsii /usr/local/bin/vnsii
ENTRYPOINT ["/usr/local/bin/vnsii"]
