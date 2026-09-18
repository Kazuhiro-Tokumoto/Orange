# ブラウザのウォレットに配るもの

`oag-node` は、この 3 つを埋め込んで `--wallet` の口から配る。

| ファイル | 中身 |
|---|---|
| `wallet.html` | 画面。`/*CSS*/` のところにエクスプローラと同じ様式が入る |
| `wallet.js` | 画面の出し入れと、ノードへの問い合わせ。**鍵に触らない** |
| `wallet.wasm` | 鍵を扱う部分。`oag-wallet-wasm` を組んだもの |

## `wallet.wasm` の作り直し方

`crates/oag-wallet-wasm` か、そこから読んでいるクレート (`oag-wallet`
`oag-consensus` `oag-primitives`) を変えたら、**必ず作り直して一緒に
コミットする**。

```sh
rustup target add wasm32-unknown-unknown   # 一度だけ
sh tools/wallet-wasm.sh
```

`wallet.wasm` と、隣の `wallet.wasm.sources` の両方が書き換わる。

## `wallet.wasm.sources` は何か

wasm の元になっている原稿の指紋である。

**バイト列そのものを突き合わせても確かめられない。** 登録簿の置き場が
wasm に埋め込まれるため、同じ原稿でも機械が違えば違うバイト列になる
(`/root/.cargo/...` と `/home/runner/.cargo/...`)。

だから原稿の側を見る。指紋が動いているのに `wallet.wasm` が古いままなら、
直したはずのものがブラウザに届いていない。**CI がそれを見る。**

中身が壊れていないことは別に確かめる。

```sh
node tools/wallet-wasm-smoke.mjs
```

`crates/oag-node/assets/wallet.js` の `call()` を写してあるので、ブラウザが
通るのと同じ道筋を通る。

## なぜ `wasm-bindgen` を使わないのか

出来上がりは**取り込み (import) を 1 つも持たない**ので、ブラウザ側は
`WebAssembly.instantiate(bytes, {})` だけで動かせる。外部の道具に頼らない
ぶん、`cargo build` だけで誰でも同じものを作り直せる。

道具の版数が crate の版数と一致していなければ組めない、という状態は、
**誰も作り直せないものを配ること**に繋がる。

乱数だけは wasm 側に源が無いので、`crypto.getRandomValues` が出した
32 バイトを起動時に渡している (`cmd: "seed"`)。`getrandom` の既定の裏側を
選ぶと `wasm-bindgen` が要るようになるため、`getrandom_backend="custom"`
で自前の裏側に差し替えてある。

取り込みが増えていないかも CI が見る。

```sh
python3 tools/wasm-imports.py crates/oag-node/assets/wallet.wasm
```
