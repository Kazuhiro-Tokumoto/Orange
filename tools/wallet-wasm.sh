#!/bin/sh
# ブラウザに配る wasm を組み直して、原稿の指紋を一緒に残す。
#
# `crates/oag-wallet-wasm` か、そこから読んでいるクレートを変えたら
# これを走らせて、出来たものを一緒にコミットすること。
set -eu

cd "$(dirname "$0")/.."

RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build -p oag-wallet-wasm --target wasm32-unknown-unknown --release

cp target/wasm32-unknown-unknown/release/oag_wallet_wasm.wasm \
  crates/oag-node/assets/wallet.wasm

sh tools/wallet-wasm-fingerprint.sh > crates/oag-node/assets/wallet.wasm.sources

echo "組み直した:"
ls -l crates/oag-node/assets/wallet.wasm
cat crates/oag-node/assets/wallet.wasm.sources
