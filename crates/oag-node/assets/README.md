# ブラウザのウォレットに配るもの

`oag-node` は、この 3 つを埋め込んで `--wallet` の口から配る。

| ファイル | 中身 |
|---|---|
| `wallet.html` | 画面。`/*CSS*/` のところにエクスプローラと同じ様式が入る |
| `wallet.js` | 画面の出し入れと、ノードへの問い合わせ。**鍵に触らない** |
| `wallet.wasm` | 鍵を扱う部分。`oag-wallet-wasm` を組んだもの |

## `wallet.wasm` の作り直し方

`crates/oag-wallet-wasm` を変えたら、**必ず作り直して一緒に置き換える**。

```sh
rustup target add wasm32-unknown-unknown       # 一度だけ
RUSTFLAGS='--cfg getrandom_backend="custom"' \
  cargo build -p oag-wallet-wasm --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/oag_wallet_wasm.wasm \
  crates/oag-node/assets/wallet.wasm
```

`wasm-bindgen` は要らない。出来上がりは**取り込み (import) を 1 つも
持たない**ので、ブラウザ側は `WebAssembly.instantiate(bytes, {})` だけで
動かせる。外の道具に頼らないぶん、誰でも同じものを作り直せる。

乱数だけは wasm 側に源が無いので、`crypto.getRandomValues` が出した
32 バイトを起動時に渡している (`cmd: "seed"`)。`getrandom` の既定の
裏側を選ぶと `wasm-bindgen` の外部道具が要るようになるため、
`getrandom_backend="custom"` で自前の裏側に差し替えてある。

**置いてあるものが古いままになっていないかは CI が見る。** 作り直した
結果と中身が違えば落ちる。
