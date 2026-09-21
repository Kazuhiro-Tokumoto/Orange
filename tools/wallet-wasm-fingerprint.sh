#!/bin/sh
# A fingerprint of the source the wasm is built from.
#
# **The bytes themselves differ per machine.** The registry path is baked in,
# so `/root/.cargo/...` and `/home/runner/.cargo/...` give different bytes for
# identical source. "Rebuild and compare" therefore proves nothing.
#
# So the source side is watched instead. **If this moved while the wasm stayed
# old, what you thought you fixed never reached the browser.**
set -eu

cd "$(dirname "$0")/.."

# Only these four, plus the Cargo.lock that pins versions, go into the wasm.
find \
  crates/oag-wallet-wasm/src \
  crates/oag-wallet/src \
  crates/oag-consensus/src \
  crates/oag-primitives/src \
  -type f \
  | sort \
  | xargs sha256sum \
  | sha256sum \
  | cut -d' ' -f1 \
  | sed 's/^/sources /'

sha256sum Cargo.lock | cut -d' ' -f1 | sed 's/^/lock /'
