# Orange (OAG)

[English](README.md) · [日本語](README.jp.md)

A CPU-mined UTXO blockchain that uses RandomX for proof of work.
Based on [chroma](https://github.com/kusogakiller/chroma).

> **Status: mainnet is live.** The genesis block was fixed in September 2026
> and mining has continued since. Payments, the browser wallet and the block
> explorer all work.
>
> That said, **there are still very few participants**, and **testnet is not
> public yet** (its DNS seed record is not set up). It is not listed on any
> exchange, so **there is no price.** This is still the stage where you mine
> it yourself and try it yourself.

| | |
| --- | --- |
| Consensus | Proof of Work (RandomX) |
| Accounting model | UTXO |
| Signatures | Schnorr / BIP340 (secp256k1) |
| Block interval | 60 seconds |
| Total supply | 1,000,000,000 OAG |
| Emission | 10 OAG per block, flat, no halving, complete in roughly 190 years |
| Initial distribution | **None** (all mined; the 10 OAG in block 0 is burned) |
| Privacy | None (transparent ledger) |
| Implementation | Rust |

## A note on language

Everything you see while using this is in English: the node's log output, the
CLI help and error messages, the block explorer, the browser wallet, this
README, [`CONTRIBUTING.md`](CONTRIBUTING.md), [`SECURITY.md`](SECURITY.md) and
the specification ([`docs/SPEC.en.md`](docs/SPEC.en.md)).

Two things are still Japanese. The normative specification is
[`docs/SPEC.md`](docs/SPEC.md), and the English one is a translation of it. And
the comments in the source are written in Japanese — roughly 5,700 lines of
them. Reading the code means meeting those.

Issues and pull requests are read in either language.

## Design goals

1. **Fair distribution** — no premine, no ICO, no developer reward
2. **Simplicity** — no script language, no virtual machine; keep the attack surface small
3. **Long-term distribution** — linear emission with no halving

Explicit non-goals: privacy, smart contracts, high throughput.

## Specification

**[`docs/SPEC.md`](docs/SPEC.md) is normative.** It records every parameter,
every consensus rule, and the reasoning behind each design decision. Where the
implementation disagrees with the spec, the spec wins and the implementation is
corrected.

An English translation is at [`docs/SPEC.en.md`](docs/SPEC.en.md). Section
numbering is identical, so "§10.2" points to the same rule in both. **The
Japanese remains normative** — if the two disagree, that is a bug in the
translation, and reporting it is welcome.

For what the commands do rather than why, see
[`docs/COMMANDS.md`](docs/COMMANDS.md): every `oag-node` and `oag-wallet`
subcommand and flag on one page, plus the RPC methods and the port numbers.

## Progress

| Phase | Item | Status |
| ---: | --- | --- |
| 0 | Workspace, CI, specification | done |
| 1 | Primitive types (amount, hash, address, keys) | done |
| 2 | Transactions, blocks, serialization, sighash | done |
| 3 | Validation logic, UTXO set | done |
| 4 | RandomX, difficulty adjustment (LWMA) | done |
| 5 | Chain state, reorgs | done |
| 5b | Persistence (redb), wiring it to the chain | done |
| 6 | Mempool, fee policy | done |
| 7a | P2P protocol (framing, messages, handshake) | done |
| 7b | Block locators, download scheduling | done |
| 7c | Compact blocks | done |
| 7d | TCP transport | done |
| 8 | Miner | done |
| 9a | Node (oag-node) — storage, chain, mining, CLI | done |
| 9b | P2P wired into the node (two nodes syncing) | done |
| 10a | JSON-RPC (node side) | done |
| 10b | CLI wallet (keys, balance, payments) | done |
| 10c | Hardening (key encryption, seed derivation) | done |
| 11a | Incremental candidate search for chain selection | done |
| 11b | Genesis fixed (all three networks) | done |
| 11c | RandomX fast mode (mining) | done |
| 11d | Peer discovery (address book, `addr`, seed nodes) | done |
| 11e | BIP39 / BIP32 / BIP44 (recovery phrase) | done |
| 11f | Public testnet | not started |
| 12a | Transaction index, address index (optional) | done |
| 12b | Block explorer | done |

Phase numbering stops here. Everything after this was added as it became
necessary, so it is not numbered.

| Item | Status |
| --- | --- |
| Partially signed transactions (PST) | done |
| UTXO consolidation (`consolidate`) | done |
| Browser wallet (wasm) | done |
| **mainnet launched and running** | **done** |

## Crate layout

```
crates/
├── oag-primitives/   amounts (u128), BLAKE3, merkle, varint, keys, addresses
├── oag-consensus/    encoding, parameters, transactions, blocks,
│                     sighash, UTXO set, validation
├── oag-pow/          difficulty, target, LWMA, seed epochs, RandomX
├── oag-chain/        block index, best-chain selection, reorgs, genesis,
│                     storage abstraction (ChainStore) and in-memory impl
├── oag-store/        persistence (redb)
├── oag-mempool/      mempool, relay policy
├── oag-net/          P2P protocol (framing, messages, handshake,
│                     locators, download scheduling, compact blocks, TCP)
├── oag-miner/        block template assembly and nonce search
├── oag-rpc/          JSON-RPC 2.0, minimal HTTP, cookie auth, client
├── oag-node/         the node itself, dedicated threads, peer handling, binary
├── oag-wallet/       key storage, payment construction and signing, binary
└── oag-wallet-wasm/  the shell that runs the above in a browser (wasm)
```

RandomX in `oag-pow` sits behind the `randomx` feature. Building the C++
implementation needs cmake and a C++ compiler, so it is off by default.

```sh
cargo test -p oag-pow --features randomx
```

Likewise, the TCP layer in `oag-net` sits behind the `tokio` feature. The
protocol rules themselves are usable without any feature.

```sh
cargo test -p oag-net --features tokio
```

## Getting the binaries

Prebuilt binaries are on the [latest release](https://github.com/Kazuhiro-Tokumoto/Orange/releases/latest).
Unpack one and run it. **You do not need Rust or a compiler.**

| Machine | File |
| --- | --- |
| Linux (x86_64) | `orange-linux-x86_64.tar.gz` |
| Raspberry Pi, ARM VPS | `orange-linux-aarch64.tar.gz` |
| Windows | `orange-windows-x86_64.zip` |

Each archive holds `oag-node`, `oag-wallet`, this README and `COMMANDS.md`.

**Check what you downloaded before you run it.** A `.sha256` sits next to every
archive.

```sh
sha256sum -c orange-linux-x86_64.tar.gz.sha256
```

That tells you the file arrived intact. It does not tell you who built it — the
checksum comes from the same page as the archive, so anyone who could replace
one could replace the other.

### macOS, or anything else

**No macOS build is published.** Nobody leaves a node running on a Mac, and the
macOS runners GitHub offers are retired on a rolling schedule — a label that has
expired does not fail the build, it queues forever and the release never
appears. Carrying that for a handful of users is not worth it.

Build from source instead. This is also the path for any machine not in the
table above.

```sh
cargo build --release -p oag-node -p oag-wallet
```

You need a Rust toolchain and `cmake` (RandomX is C++ and is built by
`randomx-rs`). The version of Rust is pinned in `rust-toolchain.toml`, so
`rustup` will fetch the right one on its own.

## Running a node

mainnet, testnet and regtest all start. **If you want to try things locally,
use regtest** — difficulty is 1, so a single machine stacks up blocks
immediately.

| Network | Genesis difficulty |
| --- | ---: |
| mainnet | 1,000 |
| testnet | 10 |
| regtest | 1 |

The first 90 blocks stay at that difficulty (LWMA does not act until its window
is full).

### Running without mining

**Mining is optional and off by default.** Without `--mine`, the node simply
validates and relays blocks.

```sh
./target/release/oag-node run --network mainnet --datadir ./oag-data
```

Validation only needs RandomX light mode (256 MB). **You can run a full node on
a machine that does not have 2 GB to spare** (SPEC §11.2). Being able to mine
and being able to validate are separate questions.

### Mining

The node mines only when you pass `--mine`, which requires a `--payout` address
for the reward. Adding `--fast` uses RandomX fast mode (2 GB); without it,
mining stays in light mode (256 MB).

```sh
./target/release/oag-node run --network mainnet --datadir ./oag-data \
    --mine --fast --payout <address> --blocks 5
```

You can measure your local hashrate with:

```sh
cargo run --release -p oag-pow --features randomx --example hashrate
```

#### How many threads

The default is 1. `--mining-threads` raises it; passing `0` matches your core
count.

```sh
./target/release/oag-node run --network mainnet --datadir ./oag-data \
    --mine --payout <address> --mining-threads 4
```

**More threads means more memory.** A RandomX miner cannot share its dataset
across threads, so each thread builds its own.

| Mode | Per thread | With 4 threads |
| --- | ---: | ---: |
| light | 256 MB | 1 GB |
| fast | 2 GB | 8 GB |

Passing `--fast` together with `--mining-threads 0` still gives you one thread.
The node will not go allocating 2 GB per core when it does not know how much
memory the machine has. If you do want several fast threads, say how many.

Several light threads and one fast thread both land around 2 GB. **Which is
faster depends on the machine.** Measure one light thread with `hashrate` above
and multiply by the thread count to compare.

```sh
cargo build --release -p oag-node

# create a payout address
./target/release/oag-node keygen --network regtest --out regtest.key

# mine 5 blocks (omit --blocks and it does not stop)
./target/release/oag-node run --network regtest --datadir ./oag-data \
    --mine --payout <the address printed above> --blocks 5

# look at the current state
./target/release/oag-node info --network regtest --datadir ./oag-data

# dump blocks as block/<height>/<block hash>.dat
./target/release/oag-node export-blocks --network regtest \
    --datadir ./oag-data --out ./block
```

### Reading the log

Each line is tagged with what it is about. **"Carried it here" and "checked it
myself" are different claims**, so when things stall you can tell which one
stalled.

```text
[peer] connected to 127.0.0.1:19444 (/oag-node:0.1.0/, height 303)
[sync] headers +303 (303 total)  chain known to height 303
[sync] bodies 169/303 (56%)  26.4 blk/s  134 left
[sync] caught up  height 287
[check] connected height 288  1 tx  203 B  mempool 0
[check] reorg  -3 +4  height 4
[tx] 1 announced  requested 1
[tx] received 9aa5bac0  fee 5 OAG  151 B  mempool 1
```

| Tag | What it is about |
| --- | --- |
| `[peer]` | connections coming and going, seed results |
| `[sync]` | what is being carried from a peer. **It says nothing about whether the contents are valid** |
| `[check]` | what the node verified for itself |
| `[tx]` | mempool traffic |
| `[mining]` | blocks found, how mining is configured |
| `[warn]` | trouble. **This tag alone goes to stderr** |

During initial sync, lines are batched every 2 seconds; once caught up, one
line per block. **If the node is behind and no block body arrives for 30
seconds, it says so once** — so there is never a stretch of silent waiting.

Progress goes to stdout and trouble goes to stderr, so `2> node-warn.log`
keeps just the trouble in its own file.

### Connecting to the public network

On mainnet and testnet, a node finds peers by itself unless you name them. It
queries the DNS seed (`seed.oagcoin.org`) only when its address book is empty;
after that, nodes tell each other about addresses. It keeps 8 outbound
connections.

A node that wants inbound connections (a seed node, for instance) has to
announce its own address. **There is no reliable way for a node to determine
its own external address, so state it explicitly.**

```sh
./target/release/oag-node run --network testnet \
    --listen 0.0.0.0:19444 --external-addr <public IP>:19444
```

`--no-discovery` skips both the address book and the seed, connecting only to
the peers named with `--connect`.

### Leaving it running

The network is worth something only if nodes stay up, and a node stays up only
if the person whose machine it is stops noticing it. `contrib/systemd/` has a
unit that runs the node in the background at low priority, brings it back after
a reboot, and stops it cleanly.

```sh
sudo cp target/release/oag-node /usr/local/bin/
sudo cp contrib/systemd/oag-node.service /etc/systemd/system/
sudo cp contrib/systemd/oag-node.env /etc/default/oag-node   # pick your flags here
sudo systemctl enable --now oag-node
journalctl -u oag-node -f
```

It runs as a throwaway user with no privileges and keeps its data in
`/var/lib/oag-node`. Port 9444 is above 1024, so **nothing needs to run as
root.**

Three kinds of node, costing different things:

| | Disk | Validates | Can serve |
| --- | --- | --- | --- |
| full | grows forever | everything | every block |
| `--prune` | bounded by the window | everything, identically | recent blocks only |
| `--light --watch` | headers only (100 bytes each, ~53 MB a year) | headers, and that bodies match them | nothing |

**`--prune` gives up nothing in validation.** It keeps the whole UTXO set and
checks each new block exactly as a full node does; what it gives up is being
able to hand old blocks to somebody else, and being able to reorganise deeper
than the window. If disk is the reason you were not going to run a node, run
this one.

`--light` is a different trade: it never builds a UTXO set, so it cannot check
anyone else's transactions, only that its own coins are on a chain with real
work behind it. It is for watching your own money on a small machine, not for
supporting the network.

#### What it costs no matter which you pick

**256 MB, for RandomX.** Checking that a header carries the work it claims
means running the RandomX program, and the smallest way to do that needs a
256 MB cache. There is no configuration that makes it smaller; the only way
down from there is to stop checking proof-of-work and take somebody's word for
it, which is the one thing none of these nodes do.

Beyond that a node is cheap. The node thread blocks until something asks it for
something; it does not spin waiting for work. Each open connection wakes on a
two-second timer to do its housekeeping, and a block arrives about once a
minute. On an idle chain that is close to nothing.

### Two nodes on one machine

Have one listen and the other `--connect` to it.

```sh
# node A: listen and mine
./target/release/oag-node run --network regtest --datadir ./node-a \
    --listen 127.0.0.1:19444 --mine --payout <address>

# node B: don't mine, just connect and sync
./target/release/oag-node run --network regtest --datadir ./node-b \
    --no-listen --connect 127.0.0.1:19444
```

Sync is headers-first: collect headers, confirm the shape of the chain, then
fetch bodies. **Every block received is validated locally**, and the UTXO set is
built by the node itself rather than accepted from a peer.

## The block explorer

`--explorer` serves a browsable view of the chain, by default at
`http://127.0.0.1:8080/`.

```sh
./target/release/oag-node run --network mainnet --datadir ./nodedata --explorer
```

You can search by height, block hash, transaction ID or address. A transaction
page shows the amounts and counterparties on the input side too. **It is
read-only** — you cannot send coins or change settings from it.

Pass an address to move it: `--explorer 127.0.0.1:9000`. Binding to anything
other than loopback makes it reachable from outside.

### What keeps it cheap as blocks fill up

The front page **does not read the bodies** of the 25 blocks it lists. Time and
difficulty come from the header in the block index, size from the length of the
stored record, and transaction count from the single varint right after the
header. Decoding the bodies would mean constructing every transaction,
including the ones never displayed: 25 full blocks (about 670 transactions
each) would allocate and discard over 16,000 of them. Worse, that happens
inside the node's own work queue, so blocks and peers stall while it runs.

The list is built from one read. Querying row by row would show rows from
different points in time, because blocks can arrive mid-render.

The transaction table inside a block is paged 50 at a time. The numbering is the
index within the block, so it lines up directly with what the index points at.

### About the indexes

Lookups by transaction ID or address **need an index**. `--explorer` builds one
automatically; if you only want it over RPC, pass `--index`.

```sh
./target/release/oag-node run --network mainnet --datadir ./nodedata --index
```

The first run scans the whole chain. After that it updates as blocks arrive, so
there is no rebuild. `--drop-index` throws it away.

**It is off by default.** Consensus does not need an index, and a year of full
blocks would add 37 GB (`docs/SPEC.md` §19). Real usage is far smaller — at 10
transactions per block it is about 0.5 GB a year.

With an index, these methods become available:

| Method | Returns |
| --- | --- |
| `getaddresshistory` | transactions touching that address |
| `getrawtransaction` | confirmed transactions (mempool only, without an index) |
| `getindexinfo` | whether an index is present |

## The browser wallet

`--wallet` serves a wallet you can use from a browser, by default at
`http://127.0.0.1:25565/`. **Opening it shows the wallet directly.**

```sh
./target/release/oag-node run --network mainnet --datadir ./nodedata --wallet
```

You can create a wallet, restore from a phrase, check a balance, send, and
consolidate.

### Keys never pass through the node

Signing finishes **inside the browser**. Only signed transactions reach the
node. Neither the seed nor any private key is exposed to the node or to the
network at any point.

The node offers exactly four endpoints:

| Endpoint | What it does |
| --- | --- |
| `/api/info` | report height and network |
| `/api/scan` | count unspent outputs for the addresses you hand it |
| `/api/history` | read history for the addresses you hand it |
| `/api/send` | pass a signed transaction to the mempool |

Every one of these is something anyone can already do over P2P. The right to
broadcast belongs to everyone, and the chain's contents are public. Opening
these endpoints does not widen what the node can do.

### The same code as the CLI

The wasm the browser loads is `oag-wallet` compiled for a different target. Key
derivation, record encryption and sighash computation run **the same code** as
the `oag-wallet` binary. None of the cryptography was rewritten in JavaScript.

The file format is identical too, so you can move between them.

```sh
# open a CLI-created wallet in the browser
cat wallet.json        # paste the contents into the "open" field

# open a browser-created wallet in the CLI
#   pass the oag-wallet.json you exported to --wallet
```

### It runs on a different port from the explorer

Browser storage is partitioned per origin. **They are deliberately on separate
ports, so that a hole in the explorer could not read the encrypted wallet
record.**

### Exposing it needs a certificate

Plaintext transport is not what protects a payment — the signature is. It covers
the recipient and the amount, so neither can be altered in transit.

What a signature cannot protect is **the channel that delivers the page.** The
signing code is sent to the browser every time, so anyone who can replace it
can lift the keys while the page looks unchanged.

For that reason the node **refuses to start** if you ask it to serve the wallet
on anything but loopback. Opening it from the same machine over plaintext is
fine.

### Write the recovery phrase down

The encrypted record lives in the browser's localStorage, which is **not a
backup**. Changing the port, or switching to `https`, changes the origin and it
is gone; some browsers clear it simply because you have not visited in a while.

If it disappears, the recovery phrase brings it back. **The phrase is the only
thing that is final.**

Restoring from a phrase asks the chain how far the wallet had been used, so
`--wallet` implies `--index`.

### Unlocking takes a few seconds

Argon2id runs at m=128 MiB, t=4. The cost of a brute-force attack is decided
right there, so it is slow on purpose — around 0.5 seconds on a desktop, several
times that on a phone.

## Sending coins

The wallet talks to the node **over JSON-RPC only**. Private keys never reach
the node; signing happens on the wallet side.

```sh
cargo build --release -p oag-wallet

# create a wallet (asks for a passphrase, prints a 12-word recovery phrase)
./target/release/oag-wallet --wallet ./alice.json new
./target/release/oag-wallet --wallet ./bob.json new

# mine to alice's address (coinbase is spendable after 120 blocks)
./target/release/oag-node run --network regtest --datadir ./oag-data \
    --mine --payout $(./target/release/oag-wallet --wallet ./alice.json address) \
    --blocks 130

# check the balance
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data balance

# send
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    send $(./target/release/oag-wallet --wallet ./bob.json address) 12.5
```

### If you keep mining, consolidate occasionally

Mining adds **one UTXO per block**, because a coinbase has a single output. Left
alone, you will hit the `scanutxos` ceiling (10,000 entries), and at that point
**neither balance nor send will work**. At 60-second blocks, 10,000 blocks is
**about 7 days**.

```sh
# look first
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    consolidate --dry-run

# fold them up
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    consolidate
```

This gathers small outputs into a single one paid back to yourself.

- **One pass is not enough.** The per-transaction limit (100,000 bytes) caps out
  around 980 inputs, so when there are many you wait for confirmation and repeat.
  It prints how many remain each time
- **Immature coinbases are left alone.** They are unspendable until 120 blocks
  have passed; that count is reported separately from the remainder
- **Running it twice costs nothing.** With nothing to fold, it exits having done
  nothing. Outputs used by an unconfirmed consolidation are excluded from your
  holdings, so you will not have a second attempt rejected as a duplicate
- `--max-inputs` limits how many are folded per pass
- **It still works after you have gone over the limit.** `balance` and `send`
  refuse a truncated scan (so as not to understate your balance), but
  `consolidate` proceeds — folding does not require seeing everything. What comes
  back is an arbitrary 10,000 of your outputs rather than "the most recent
  10,000", so repeating brings you under the ceiling

Fees are cheap. A near-full transaction (100,000 bytes) costs **0.5 OAG**, so
folding the 980 outputs that fit — 10 OAG each, 9,800 OAG in total — costs 0.5
OAG.

### How many confirmations to wait for

**Ten blocks (about 10 minutes) is the guideline.** Twenty or more for large
amounts, or for anything you cannot claw back. **Never accept 0 confirmations
(present in the mempool only) as payment.**

The probability of a reversal depends only on the attacker's hashrate share and
the confirmation count; **it does not depend on the block interval.** Bitcoin's
convention is 6; at 10, the probability for the same share is roughly an order
of magnitude lower. The reason 6 is not enough here is cost, not probability: a
young chain has a small total hashrate, so the same share is cheaper to buy.
Details and tables are in SPEC §10.7.

`balance --verbose` prints the confirmation count per UTXO. Anything under 10 is
marked with `!`. **The mark is informational and does not block a send.**

```sh
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    balance --verbose
```

Note that the wallet's balance looks only at the chain's UTXO set and never at
the mempool. **Zero-confirmation outputs do not appear in the balance and cannot
be spent.**

#### Confirmation counts can go down

When the chain forks and the branch you were watching loses, payments in it
return to unconfirmed. **Confirmation counts do not only increase.**

- If the new branch also contains the payment, the count comes back at that depth
  (9 → 2, say) and grows again
- If it does not, the count returns to 0 and the payment waits in the mempool to
  be mined
- If the new branch spends the same funds to a different recipient, **that
  payment will never confirm.** That is a double spend

The wallet re-reads the chain every time, so running `balance` again gives the
right answer. But **nothing notifies you that a count went down.** Check the
confirmations **immediately before handing over goods.**

### Keeping keys on a separate machine

To keep your keys on a machine that never touches the network, use **partially
signed transactions (PST)**. They are the equivalent of Bitcoin's PSBT: they
carry everything signing needs (the amount and spending condition of each input),
so the signing side never has to consult the chain.

```sh
# online side: build only, do not sign
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    pst create $(./target/release/oag-wallet --wallet ./bob.json address) 12.5 \
    --out ./payment.pst

# key-holding side: sign without touching a node
./target/release/oag-wallet --wallet ./alice.json pst sign ./payment.pst

# online side: finalize and broadcast
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    pst send ./payment.pst
```

When several owners each sign, `pst combine` merges the results. `pst show`
prints the contents at any point. **Look at the fee before you sign.**

RPC listens **on loopback only** and requires cookie authentication (the cookie
is regenerated at every start and written to `<datadir>/.cookie`). You can call
it from `curl`:

```sh
curl -s --user "$(cat ./oag-data/.cookie)" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":[]}' \
  http://127.0.0.1:9445/
```

The wallet stores **a single seed encrypted under your passphrase** (Argon2id +
ChaCha20-Poly1305, file mode 0600). Keys are derived from the seed, so **one
backup of one seed is enough** — however many addresses you add later, the same
phrase restores them.

```sh
# show the recovery phrase
./target/release/oag-wallet --wallet ./alice.json seed

# restore from a recovery phrase
./target/release/oag-wallet --wallet ./recovered.json restore
```

The phrase is **12 BIP39 words**. Key derivation follows BIP32 / BIP44.

```
m / 44' / <coin_type>' / 0' / 0 / <index>
```

> **Anyone who knows the recovery phrase can move the funds.** Copy it onto
> paper and keep it somewhere safe. Encryption will not save you if the
> passphrase is weak.

> **Do not put funds on a mainnet address yet.** mainnet's coin_type is 1033,
> but the SLIP-0044 registration is **still under review**. If a different
> number is accepted, the derivation path changes and so do the addresses
> produced from the same phrase. Test the wallet on testnet and regtest
> (reserved number 1) instead ([SPEC §6.6](docs/SPEC.md)).

To use a BIP39 passphrase, pass `--mnemonic-passphrase`. **A typo does not
surface as an error.** A different passphrase simply produces a different wallet
with a zero balance, and nothing anywhere reports a mistake.

`oag-node` always uses RandomX, so building it requires cmake and a C++
compiler.

## Building

```sh
cargo test                    # tests
cargo clippy --all-targets    # lint
cargo fmt --all -- --check    # formatting
```

The toolchain is **pinned to 1.98.0** in `rust-toolchain.toml`. rustup fetches
that version automatically, so there is nothing extra to do. It is pinned to
avoid the situation where a lint added in a newer rustc fails only in CI.

The MSRV is **1.90**, verified on every CI run. redb, used for persistence,
requires it.

## Talk to us

**"I ran it" is the report we most want to hear.**

There are only a handful of nodes on this network right now. The moment you
connect, you are one of them. Whether it worked or not, one line in an
[Issue](https://github.com/Kazuhiro-Tokumoto/Orange/issues) shows us something
we cannot see from here.

| | |
|---|---|
| Reports, questions, corrections | [Issues](https://github.com/Kazuhiro-Tokumoto/Orange/issues) |
| Anything else | `contact@oagcoin.org` |
| Vulnerabilities | [`SECURITY.md`](SECURITY.md) (**please do not open a public Issue**) |

[`CONTRIBUTING.md`](CONTRIBUTING.md) explains how to write things up. You are
welcome to send something in without having understood everything.
**If it did not read clearly, that is usually the writer's fault, not yours.**

English and Japanese are both fine — Issues in either language are read.

The most valuable thing anyone could do is implement this in another language.
Consensus bugs come in a shape where "the spec is right but the implementations
disagree", and that shape is **invisible forever while only one implementation
exists.**

## License

MIT. Full text in [`LICENSE`](LICENSE).
