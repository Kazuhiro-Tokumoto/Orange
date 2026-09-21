#!/bin/sh
# Rebuild the wasm served to the browser and record the source fingerprint with it.
#
# Change `crates/oag-wallet-wasm`, or any crate it reads, then run this and
# commit the result alongside.
set -eu

cd "$(dirname "$0")/.."

RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build -p oag-wallet-wasm --target wasm32-unknown-unknown --release

cp target/wasm32-unknown-unknown/release/oag_wallet_wasm.wasm \
  crates/oag-node/assets/wallet.wasm

sh tools/wallet-wasm-fingerprint.sh > crates/oag-node/assets/wallet.wasm.sources

echo "rebuilt:"
ls -l crates/oag-node/assets/wallet.wasm
cat crates/oag-node/assets/wallet.wasm.sources
