#!/bin/sh
# wasm の元になっている原稿の指紋。
#
# **バイト列そのものは機械ごとに変わる。** 登録簿の置き場が埋め込まれる
# ためで、`/root/.cargo/...` と `/home/runner/.cargo/...` は同じ原稿でも
# 違うバイト列になる。だから「組み直して突き合わせる」では確かめられない。
#
# 代わりに原稿の側を見る。**これが変わっているのに wasm が古いままなら、
# 直したはずのものがブラウザに届いていない。**
set -eu

cd "$(dirname "$0")/.."

# wasm に入るのはこの 4 つと、版を決める Cargo.lock だけである。
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
