# What is served to the browser wallet

[English](README.md) · [日本語](README.jp.md)

`oag-node` embeds these three files and serves them from the `--wallet`
interface.

| File | Contents |
|---|---|
| `wallet.html` | the page. The same stylesheet as the explorer goes where `/*CSS*/` is |
| `wallet.js` | moving things on and off the screen, and querying the node. **It never touches keys** |
| `wallet.wasm` | the part that handles keys. `oag-wallet-wasm` compiled |

## Rebuilding `wallet.wasm`

Change `crates/oag-wallet-wasm`, or any crate it reads (`oag-wallet`,
`oag-consensus`, `oag-primitives`), and you **must rebuild it and commit the
result alongside**.

```sh
rustup target add wasm32-unknown-unknown   # once
sh tools/wallet-wasm.sh
```

Both `wallet.wasm` and the `wallet.wasm.sources` next to it are rewritten.

## What `wallet.wasm.sources` is

A fingerprint of the source the wasm was built from.

**Comparing the bytes themselves proves nothing.** The registry path is baked
into the wasm, so the same source produces different bytes on different machines
(`/root/.cargo/...` versus `/home/runner/.cargo/...`).

So the source side is what gets checked. If the fingerprint moved while
`wallet.wasm` stayed old, then what you thought you fixed never reached the
browser. **CI watches for that.**

That the contents are not broken is checked separately.

```sh
node tools/wallet-wasm-smoke.mjs
```

It copies `call()` from `crates/oag-node/assets/wallet.js`, so it takes the same
path the browser does.

## Why `wasm-bindgen` is not used

The result **has no imports at all**, so the browser side can run it with
`WebAssembly.instantiate(bytes, {})` alone. Depending on no external tooling
means anyone can rebuild the identical artifact with `cargo build`.

A state where the tool's version must match the crate's version to build at all
leads to **shipping something nobody can rebuild**.

Randomness is the one exception, since the wasm has no source of its own: 32
bytes from `crypto.getRandomValues` are handed in at startup (`cmd: "seed"`).
Choosing `getrandom`'s default backend would pull in `wasm-bindgen`, so
`getrandom_backend="custom"` swaps in our own.

CI also watches that the imports have not grown.

```sh
python3 tools/wasm-imports.py crates/oag-node/assets/wallet.wasm
```
