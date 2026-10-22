#!/usr/bin/env bash
set -euo pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PINNED_IMAGE=$(sed -nE 's/^[[:space:]]*pinned_reference[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "${REPO_DIR}/toolchain.lock")
[[ -n "${PINNED_IMAGE}" ]] || { echo 'Missing pinned toolchain reference' >&2; exit 1; }
docker run --rm -v "${REPO_DIR}:/workspace" -w /workspace "${PINNED_IMAGE}" bash scripts/container_build_verify.sh
cd "${REPO_DIR}"
python3 -m unittest tests.test_step2_loader_harness
DURAK_INVENTORY_NATIVE_LIB="$REPO_DIR/build-obj/test_inventory_native.so" python3 -m unittest tests.test_cosmetics_inventory
echo '[verified] durak_nx.nro (build and host checks; hardware gate pending)'
