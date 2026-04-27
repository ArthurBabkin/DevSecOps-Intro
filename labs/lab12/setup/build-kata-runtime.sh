#!/usr/bin/env bash
set -euo pipefail

# Build Kata shim in a Rust container.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
WORK_DIR="${ROOT_DIR}/lab12/setup/kata-build"
OUT_DIR="${ROOT_DIR}/lab12/setup/kata-out"

mkdir -p "${WORK_DIR}" "${OUT_DIR}"

echo "Building Kata runtime in Docker..." >&2
docker run --rm \
  -e CARGO_NET_GIT_FETCH_WITH_CLI=true \
  -v "${WORK_DIR}":/work \
  -v "${OUT_DIR}":/out \
  rust:1.75-bookworm bash -lc '
    set -euo pipefail
    apt-get update && apt-get install -y --no-install-recommends \
      git make gcc pkg-config ca-certificates musl-tools libseccomp-dev && \
      update-ca-certificates || true

    # Check Rust tools.
    export PATH=/usr/local/cargo/bin:$PATH
    rustc --version; cargo --version; rustup --version || true

    cd /work
    if [ ! -d kata-containers ]; then
      git clone --depth 1 https://github.com/kata-containers/kata-containers.git
    fi
    cd kata-containers/src/runtime-rs

    # Add MUSL target for static build.
    rustup target add x86_64-unknown-linux-musl || true

    # Build shim.
    make

    # Copy built binary.
    f=$(find target -type f -name containerd-shim-kata-v2 | head -n1)
    if [ -z "$f" ]; then
      echo "ERROR: built binary not found" >&2; exit 1
    fi
    install -m 0755 "$f" /out/containerd-shim-kata-v2
    strip /out/containerd-shim-kata-v2 || true
    /out/containerd-shim-kata-v2 --version || true
  '

echo "Done. Binary saved to: ${OUT_DIR}/containerd-shim-kata-v2" >&2
