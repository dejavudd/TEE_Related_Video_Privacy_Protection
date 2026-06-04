#!/bin/bash
set -e

export PATH=~/phytium-pi-os/output/host/bin:$PATH

make -C optee_os O=out \
    HOST_CROSS_COMPILE=~/phytium-pi-os/output/host/bin/arm-linux-gnueabihf- \
    TA_CROSS_COMPILE=~/phytium-pi-os/output/host/bin/arm-linux-gnueabihf- \
    CFG_ARM64_core=n \
    CFG_TA_TARGETS="arm32" \
    -j$(nproc)