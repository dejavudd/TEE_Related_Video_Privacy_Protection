#!/bin/bash
set -e

# Path to the TA-DEV-KIT
export TA_DEV_KIT_DIR="/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/out/data/link/export-ta_arm64"

# Path to the client library (GP Client API)
export TEEC_EXPORT="/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/out/data/link/export/usr"

export PLATFORM=phytium
# ---------------------------------------
# Paths
# ---------------------------------------
BASE_DIR=$(pwd)   # media_crypto Ä¿Â¼
HOST_DIR="$BASE_DIR/host"
TA_DIR="$BASE_DIR/ta"
OPTEE_OS_DIR="/home/hfut/phytium-pi-os/output/build/phytium-optee-v4.6.0/optee_os"
KEY_DIR="$OPTEE_OS_DIR/keys"

# ½»²æ±àÒëÆ÷
HOST_CROSS_COMPILE="/home/hfut/phytium-pi-os/output/host/opt/ext-toolchain/bin/aarch64-none-linux-gnu-"
TA_CROSS_COMPILE="$HOST_CROSS_COMPILE"

# Êä³öÄ¿Â¼
OUT_BIN="$BASE_DIR/../../out/data/bin"
OUT_TA="$BASE_DIR/../../out/data/optee_armtz"

mkdir -p "$KEY_DIR" "$OUT_BIN" "$OUT_TA"

# -----------------------------
# Step 0: Generate TA keys
# -----------------------------
echo "=== Step 0: Generating TA keys ==="
python3 "$OPTEE_OS_DIR/scripts/pem_to_pub_c.py" \
    --prefix "$KEY_DIR/ta" \
    --out "$KEY_DIR/ta_pub.c" \
    --key "$KEY_DIR/ta_private_key.pem"

echo "TA keys generated:"
echo "  private key: $KEY_DIR/ta_private_key.pem"
echo "  public key : $KEY_DIR/ta_pub.c"

# -----------------------------
# Step 1: Build host
# -----------------------------
echo "=== Step 1: Build OP-TEE host client ==="
cd "$HOST_DIR"
make CROSS_COMPILE="$HOST_CROSS_COMPILE" all
cd "$BASE_DIR"

# -----------------------------
# Step 2: Build TAs
# -----------------------------
echo "=== Step 2: Build TAs ==="
cd "$TA_DIR"
make CROSS_COMPILE="$TA_CROSS_COMPILE" all
cd "$BASE_DIR"

# -----------------------------
# Step 3: Copy output
# -----------------------------
cp -a "$HOST_DIR"/* "$OUT_BIN/"
cp -a "$TA_DIR"/*.ta "$OUT_TA/"

echo "=== Build finished successfully ==="