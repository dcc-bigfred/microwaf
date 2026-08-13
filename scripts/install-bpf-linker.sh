#!/usr/bin/env bash
# Install the official prebuilt bpf-linker (no system LLVM required).
# See https://github.com/aya-rs/bpf-linker#installation
set -euo pipefail

VERSION="${BPF_LINKER_VERSION:-v0.11.0}"
DEST="${BPF_LINKER_DEST:-${HOME}/.cargo/bin}"

arch="$(uname -m)"
case "${arch}" in
  x86_64) triple=x86_64-unknown-linux-musl ;;
  aarch64|arm64) triple=aarch64-unknown-linux-musl ;;
  *)
    echo "error: unsupported arch ${arch}; install bpf-linker from https://github.com/aya-rs/bpf-linker/releases" >&2
    exit 1
    ;;
esac

url="https://github.com/aya-rs/bpf-linker/releases/download/${VERSION}/bpf-linker-${triple}.tar.zst"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

echo "downloading ${url}"
curl -fsSL "${url}" -o "${tmp}/bpf-linker.tar.zst"
mkdir -p "${DEST}"
tar -I zstd -xf "${tmp}/bpf-linker.tar.zst" -C "${DEST}"
chmod +x "${DEST}/bpf-linker"
"${DEST}/bpf-linker" --version
echo "installed ${DEST}/bpf-linker"
