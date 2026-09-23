# How to get in touch

[English](CONTRIBUTING.md) · [日本語](CONTRIBUTING.jp.md)

**"I ran it" is the report we most want to hear.**

This chain has only a handful of nodes right now. The moment you connect, you
are part of the network. Whether it worked or not, one line in an
[Issue](https://github.com/Kazuhiro-Tokumoto/Orange/issues) shows us something
we cannot see from here.

Email is fine too: `contact@oagcoin.org`

**Write in English or Japanese — either is read.** The project's own documents
include Japanese-only parts (see
[the note on language](README.md#a-note-on-language)), but you do not have to
write in it.

## Connecting

```sh
cargo build --release
./target/release/oag-node run --network mainnet
```

It queries the DNS seed and connects on its own. **Leave `--mine` off until you
have caught up** — validation and mining compete for the CPU.

If your machine can accept inbound connections, pass
`--external-addr <host:9444>`. **Only the address you pass there is propagated
to other nodes.** Without it, your node never appears in anyone's address book.

## Anything is worth sending

| | |
|---|---|
| Questions | the intent of a rule is unclear, or you cannot tell why something is the way it is |
| Reports | it ran, it crashed, sync stalled, the display looks wrong |
| Corrections | this is wrong, this case is missing |
| Fixes | pull requests |
| Ports | an implementation in another language. **Tell us when the answers disagree** |

That last one is the most valuable. Consensus bugs come in a shape where "the
spec is right but the implementations disagree", and that shape is **invisible
forever while only one implementation exists.**

For vulnerabilities, see [`SECURITY.md`](SECURITY.md).

## What a change has to pass

CI runs four jobs. **Run the same things locally before sending.**

```sh
export RUSTFLAGS="-D warnings"             # CI sets this; a warning fails the build

cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo test --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
cargo check --workspace --all-targets      # must build without RandomX too
```

**Do not skip the `cargo doc` line.** A doc comment that links to something
rustdoc cannot resolve — a crate this one does not depend on, for instance —
compiles and tests perfectly well, and then fails CI. It has happened.

If you touch any of `crates/oag-wallet-wasm`, `crates/oag-wallet`,
`crates/oag-consensus` or `crates/oag-primitives`, **rebuild the browser
wallet.**

```sh
sh tools/wallet-wasm.sh
```

Commit the resulting `wallet.wasm` and `wallet.wasm.sources` along with your
change. Forgetting breaks CI (it has happened).

## The specification is normative

If [`docs/SPEC.md`](docs/SPEC.md) and the code disagree, **the bug is in the
code, not in the spec.** The spec is written in Japanese and that version is
normative; an English translation is at
[`docs/SPEC.en.md`](docs/SPEC.en.md), with identical section numbering.

Conversely, if you find a place where the implementation decides something the
spec does not mention, that is a hole in the spec. **Tell us about those too.**
On a network with more than one node, an unwritten rule is where the chain
splits.

Sometimes changing the spec is the right answer. When it is, say why.

## Commit messages

They are written in Japanese. **Write why, not what.**

```
シードを、アクティブチェーンではなくヘッダ自身の枝から引く

新しいノードが mainnet に追いつけない。高さ 2112 のヘッダで必ず止まり、
相手を切って繋ぎ直し、また同じ所で止まる。
...
```

The diff already shows what you did. What it cannot show is why it was needed,
and why you did not do it some other way.

**If you cannot write Japanese, write the message in English.** A clear English
explanation is worth more than an unclear Japanese one.

## About tests

**If you changed a behaviour, write the test that fails first.**

Confirm it fails before you fix it. Otherwise you cannot tell whether the test
is holding anything down. A test that passes while guarding nothing is worse
than no test.

## Send it even if you do not understand it

"I could not read this" and "I cannot tell why it is like this" are Issues too.
**If it did not read clearly, that is usually the writer's fault, not yours.**
