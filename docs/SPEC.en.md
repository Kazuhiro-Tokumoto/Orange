# Orange (OAG) Protocol Specification

[English](SPEC.en.md) · [日本語](SPEC.md)

**Version**: 0.1 (draft)
**Status**: design stage / not implemented
**Last updated**: 2026-09-07

> **[`SPEC.md`](SPEC.md), the Japanese document, is normative.** This file is a
> translation kept for convenience. Section numbering is identical, so a
> reference such as "§10.2" points to the same rule in both. **Where the two
> disagree, the Japanese text wins** — and please report the discrepancy as a
> bug in this translation.

---

## Table of contents

1. [Overview](#1-overview)
2. [Notation and terminology](#2-notation-and-terminology)
3. [Currency units](#3-currency-units)
4. [Emission schedule](#4-emission-schedule)
5. [Cryptographic primitives](#5-cryptographic-primitives)
6. [Keys and addresses](#6-keys-and-addresses)
7. [Transactions](#7-transactions)
8. [Signature hash (sighash)](#8-signature-hash-sighash)
9. [Blocks](#9-blocks)
10. [Consensus rules](#10-consensus-rules)
11. [Proof of work](#11-proof-of-work)
12. [Difficulty adjustment (LWMA)](#12-difficulty-adjustment-lwma)
13. [Fee policy](#13-fee-policy)
14. [Network parameters](#14-network-parameters)
15. [RPC](#15-rpc)
16. [Wallet](#16-wallet)
17. [Interoperability and DEXs](#17-interoperability-and-dexs)
18. [Record of design decisions](#18-record-of-design-decisions)
19. [Open questions](#19-open-questions)

---

## 1. Overview

**Orange** (ticker: **OAG**) is a CPU-mined UTXO blockchain that uses RandomX
for proof of work.

| | |
| --- | --- |
| Consensus | Proof of work (RandomX) |
| Accounting model | UTXO |
| Privacy | none (transparent ledger) |
| Signatures | Schnorr / BIP340 (secp256k1) |
| Block interval | 60 seconds |
| Total supply | 1,000,000,000 OAG |
| Initial distribution | **none** (issued entirely by mining; the block 0 reward is burned) |
| Implementation language | Rust |

### Design goals

1. **Fair distribution** — no premine, no ICO, no developer reward. Because
   RandomX is optimised for CPUs, participants without specialised hardware can
   still mine.
2. **Simplicity** — no script language and no virtual machine. The only things
   to verify are signatures and that the amounts balance. The attack surface is
   kept as small as possible.
3. **Long-term distribution** — linear emission with no halving leaves mining
   opportunities open to new participants for 190 years.

### Explicit non-goals

- **Privacy** — this is a transparent ledger. Every amount and every link
  between transactions is public, and chain analysis is possible. It is not a
  privacy coin like Monero.
- **Smart contracts** — there is no execution environment for arbitrary
  computation. AMM-style DEXs, lending and derivatives cannot be built on this
  chain.
- **High throughput** — roughly 17 tx/s. Replacing a payment network is not the
  aim.

---

## 2. Notation and terminology

- `u8`, `u32`, `u64`, `u128`, `i64` — fixed-width unsigned / signed integers.
  All are serialised little-endian.
- `varint` — LEB128 variable-length integer. Seven bits per byte, with the top
  bit signalling continuation.
- `atomic` — the smallest unit of OAG. 1 OAG = 10^16 atomic.
- `[u8; N]` — a fixed-length byte string of length N.
- **MUST / MUST NOT / SHOULD** — as defined in RFC 2119.

Hashes, keys and signatures are written in hexadecimal big-endian (the first
byte of the string on the left).

### Checking count fields

A varint count at the head of a sequence **MUST be rejected unless enough bytes
remain to encode that many elements**. That is, a byte string for which

```
count × (minimum encoded length of one element) ≤ bytes remaining
```

does not hold is invalid.

The count is a value the peer chooses, yet the decoder allocates based on it.
An implementation that only compares "count ≤ bytes remaining" will accept a
count of one byte per element even for a type that really needs dozens of bytes.
A single input, for instance, requires at least 38 bytes; under the loose check
a 1 MiB message could declare a million inputs and **force tens of megabytes to
be allocated before decoding of the first one even fails.** Multiplying by the
minimum encoded length keeps the allocation in the same order of magnitude as
the bytes actually received.

Minimum encoded length of the main types, in bytes:

| Type | Minimum | Breakdown |
| --- | --- | --- |
| `OutPoint` | 33 | hash 32 + output index 1 |
| `TxInput` | 38 | reference 33 + signature length 1 + sequence 4 |
| `TxOutput` | 3 | amount 1 + lock 2 |
| `Transaction` | 7 | version 4 + input count 1 + output count 1 + locktime 1 |
| `BlockHeader` | 100 | fixed |

### Booleans

A boolean is one byte, and anything **other than `0x00` or `0x01` MUST be
rejected**. Accepting on `!= 0` gives 255 distinct bytes that mean true, which
lets the same value be expressed by more than one byte string — malleability.
The encoder always writes `0x00` or `0x01`, so anything else is a corrupt byte
string.

---

## 3. Currency units

```
1 OAG = 10,000,000,000,000,000 atomic   (10^16)
decimal places = 16
```

### The amount type

Amounts are represented as **`u128`**.

```
total supply (atomic) = 1,000,000,000 × 10^16 = 10^25
u128 maximum                                  ≈ 3.40 × 10^38
```

`u64` (maximum about 1.84 × 10^19) cannot represent this, hence `u128`.

### Mandatory implementation requirements

Amount arithmetic MUST observe the following on every consensus-relevant path.

1. **Define `Amount` as a newtype and do not expose the inner `u128`.**

   ```rust
   pub struct Amount(u128);
   ```

2. **Use `checked_*` for every addition, subtraction and multiplication.** On
   overflow, treat `None` as "invalid transaction".

3. **Never `panic!`.** It is a denial of service that lets an attacker stop any
   node. Overflow is always a validation error.

4. **Range-check every amount.**

   ```
   0 ≤ amount ≤ MAX_SUPPLY  (= 10^25)
   ```

   Given this constraint, the sum of amounts in a block mathematically cannot
   overflow `u128`: a 200,000-byte block holds at most about 4,700 outputs, and
   `4,700 × 10^25 ≈ 4.7 × 10^28 ≪ 3.4 × 10^38`.

5. **Enable `overflow-checks = true` in the release profile of `Cargo.toml`
   as well.** Aborting does less damage than silently producing a wrong amount.

6. **Amounts MUST be represented as strings in RPC and JSON.** JavaScript's
   `Number` is exact only up to 2^53, which amounts in atomic units exceed
   easily.

> **Background**: in August 2010, at block 74638, Bitcoin suffered an integer
> overflow that created 184.4 billion BTC (CVE-2010-5139). The sum of the output
> amounts overflowed `int64`, wrapped to a negative value, and thereby passed
> the "inputs ≥ outputs" check. Requirements 1–4 above exist to make that class
> of accident structurally impossible here.

---

## 4. Emission schedule

### Parameters

```
BLOCK_REWARD          = 10 OAG = 10^17 atomic     (fixed, never changes)
MAX_SUPPLY            = 1,000,000,000 OAG = 10^25 atomic
EMISSION_END_HEIGHT   = 100,000,000
PREMINE               = 0
```

### Reward function

```
block_subsidy(height) =
    10 OAG   if height < 100,000,000
    0        otherwise
```

There is no halving. The reward is constant until the emission end height.

### Time to complete emission

```
100,000,000 blocks × 60 seconds = 6,000,000,000 seconds
                                ≈ 190 years 3 months
```

### Supply curve

| Year | In circulation (OAG) | Share of total | Annual inflation |
| ---: | ---: | ---: | ---: |
| 1 | 5,256,000 | 0.53 % | — |
| 2 | 10,512,000 | 1.05 % | 100.0 % |
| 3 | 15,768,000 | 1.58 % | 50.0 % |
| 5 | 26,280,000 | 2.63 % | 25.0 % |
| 10 | 52,560,000 | 5.26 % | 11.1 % |
| 20 | 105,120,000 | 10.51 % | 5.3 % |
| 50 | 262,800,000 | 26.28 % | 2.0 % |
| 100 | 525,600,000 | 52.56 % | 1.0 % |
| 190.3 | 1,000,000,000 | 100.00 % | 0 |

Annual inflation decays as `1 / years elapsed` — a mathematical property of
linear emission.

### The coinbase transaction

Every block MUST contain exactly one coinbase transaction.

```
coinbase_output_total ≤ block_subsidy(height) + Σ(fees in that block)
```

Note the inequality. A miner may forgo part or all of the reward; anything
forgone is never issued.

Coinbase outputs cannot be spent until **120 blocks** have passed
([coinbase maturity](#10-consensus-rules)).

---
## 5. Cryptographic primitives

### 5.1 General-purpose hash: BLAKE3

Transaction IDs, the merkle tree, block hashes and every other general-purpose
hash in the protocol use **BLAKE3** with 256-bit output.

```
H(x) = BLAKE3(x)[0..32]
```

BLAKE3 is structurally resistant to length-extension attacks, so Bitcoin's
double hashing (`SHA256(SHA256(x))`) is unnecessary.

**Domain separation**: each use gets its own prefix.

```
txid          = H(0x00 || tx_serialized)
merkle_leaf   = H(0x01 || txid)
merkle_node   = H(0x02 || left || right)
block_hash    = H(0x03 || header_serialized)
```

Where the number of uses grows (sighash, for example), a string tag is used
instead of a one-byte identifier. See [§8.0](#80-tagged-hashes).

### 5.2 Elliptic curve: secp256k1

```
p = 2^256 - 2^32 - 977
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
```

A private key `d` MUST satisfy `1 ≤ d < n`.

### 5.3 Signatures: Schnorr (BIP340)

**Fully compliant with BIP340.**

- Public keys are **x-only, 32 bytes**. The Y coordinate is implicitly the even
  one.
- Signatures are **fixed at 64 bytes** (`r: 32 || s: 32`).
- The internal tagged hash uses **SHA-256** exactly as BIP340 specifies (not
  BLAKE3; this is BIP340's design and is not changed here).

  ```
  tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
  tags: "BIP0340/challenge", "BIP0340/aux", "BIP0340/nonce"
  ```

- Nonce generation SHOULD follow BIP340's deterministic scheme with auxiliary
  randomness.

**Batch verification**: implementations SHOULD batch-verify all signatures in a
block. It is roughly twice as fast as verifying individually, which matters at a
60-second block interval.

**Non-malleability**: BIP340 signatures are fixed-length and strictly encoded,
and this chain has no scripts. Therefore **a third party cannot alter a
transaction ID.** This property lets pre-signed transactions (the refund path of
an atomic swap, for instance) work safely without anything equivalent to SegWit.

### 5.4 Merkle tree

The **RFC 6962 (Certificate Transparency)** construction is used.

```
MTH([])        = H(0x01 || empty)     // unused: empty blocks do not exist
MTH([d0])      = merkle_leaf(d0)
MTH(D[0..n])   = merkle_node(MTH(D[0..k]), MTH(D[k..n]))
                 where k is the largest power of two less than n
```

Leaves and internal nodes use different domain-separation prefixes, and an odd
node is never duplicated.

> **Background**: Bitcoin's merkle tree pads an odd node by duplicating it, so
> different transaction lists can produce the same merkle root (CVE-2012-2459).
> Bitcoin handles this with a bolted-on "reject duplicate txids" rule; this
> specification avoids the problem structurally.

The block header additionally commits to the transaction count indirectly (it is
verified together with the height field in the coinbase).

---

## 6. Keys and addresses

### 6.1 Address format

**bech32m (BIP350)** is used. Bitcoin's split — bech32 for SegWit v0, bech32m
from v1 onwards — is a historical accident; this chain **uses bech32m for every
version**.

```
<HRP> "1" <version> <payload (converted to 5-bit)> <checksum (6 characters)>
```

### 6.2 HRP (network identifier)

| Network | HRP | Example | Length |
| --- | --- | --- | ---: |
| mainnet | `oag` | `oag1q...` | 63 characters |
| testnet | `toag` | `toag1q...` | 64 characters |
| regtest | `roag` | `roag1q...` | 64 characters |

An address whose HRP does not match MUST be rejected at decode time. This makes
cross-network misdelivery structurally impossible.

### 6.3 Address versions

| version | Character | Contents | Status |
| ---: | :---: | --- | --- |
| 0 | `q` | Schnorr x-only public key (32 bytes) | implemented in v1 |
| 1 | `p` | reserved (script hash, etc.) | undefined |
| 2–31 | | reserved | undefined |

**Forward compatibility**: a wallet SHOULD allow sending to an address with an
unknown version after displaying a warning. That way, when a version is added
later, older wallets can still pay the new addresses.

### 6.4 Derivation

```
private key d  (32 random bytes, 1 ≤ d < n)
    │
    │  P = d × G
    ▼
public key P = (x, y)
    │
    │  BIP340: keep only x (the even y is chosen implicitly)
    ▼
x-only public key (32 bytes)
    │
    │  bech32m(HRP, version=0, payload)
    ▼
address
```

No hash function is involved. The public key is the address payload as-is.

### 6.5 Test vectors

The following values have been generated and verified.

```
--- vector 1 ---
private key    3bea301b132570f53a193a6542940305ac1e6b343249425433febf3c01d3f8f8
x-only pubkey  0830053b6ac7f7b10243a8058fb5d9bc3ccdec622deadaa9da7f885f16dedc2e
mainnet        oag1qpqcq2wm2clmmzqjr4qzcldwehs7vmmrz9h4d42w607y979k7mshq9ve7jv
testnet        toag1qpqcq2wm2clmmzqjr4qzcldwehs7vmmrz9h4d42w607y979k7mshqwraqde

--- vector 2 ---
private key    5487aaeb0f711bf0dee2cf7b97ea24f28037617dc5ff2f45d095a14ebf231f22
x-only pubkey  5b528dd539132944eee4387dbf81aee1c65699d1154993a55d1c181c76b3e53e
mainnet        oag1qtdfgm4fezv55fmhy8p7mlqdwu8r9dxw3z4ye8f2arsvpca4nu5lq34qtxp
testnet        toag1qtdfgm4fezv55fmhy8p7mlqdwu8r9dxw3z4ye8f2arsvpca4nu5lq66y4e5

--- vector 3 ---
private key    01119d84272af17d8d957f160f3117bbcc769c2a95e9f8398c546ca24c6a52d8
x-only pubkey  1ed0a9a1dc8ab784f5f38a869d8479f0ce476eea093883f0e718c566cabe823e
mainnet        oag1qrmg2ngwu32mcfa0n32rfmpre7r8ywmh2pyug8u88rrzkdj47sglqc68mtx
testnet        toag1qrmg2ngwu32mcfa0n32rfmpre7r8ywmh2pyug8u88rrzkdj47sglqn4r95n
```

### 6.6 HD wallets

Compliant with **BIP39 (mnemonic) + BIP32 (derivation) + BIP44 (path)**.

#### Mnemonic

```
word count    12 words
entropy       128 bits
wordlist      BIP39 English (2048 words)
checksum      4 bits
```

**Why 12 words is enough.** 128 bits matches the strength secp256k1 actually
has. The best generic attack on a 256-bit curve (Pollard's rho) costs 2^128, so
even with a 256-bit (24-word) seed, the keys derived from it are still protected
at 2^128. **A longer seed does not make you stronger than the curve.** Past that
ceiling, extra length only adds transcription errors.

#### Optional passphrase (BIP39's optional field)

Supported. The default is the empty string.

**A typo does not surface as a failure.** A different passphrase simply creates
a different valid wallet. All the user sees is a wallet with a zero balance;
nothing anywhere reports an error. A wallet MUST state this plainly when the
option is configured.

#### Derivation path

```
m / 44' / <coin_type>' / <account>' / <change> / <index>

change = 0  receiving
change = 1  change
gap limit = 20
```

| Network | coin_type | Status |
| --- | ---: | --- |
| testnet | 1 | reserved by SLIP-0044 for every coin's testnet; no registration needed |
| regtest | 1 | as above |
| mainnet | 1033 | applied for in SLIP-0044, **awaiting review** (see below) |

**1033 is not final.** If `satoshilabs/slips` accepts a different number, this
value has to change, and **every mainnet key derived from the same recovery
phrase changes with it**. From the user's point of view that is indistinguishable
from the funds disappearing.

The operational boundary is therefore:

- A wallet may derive mainnet keys. The path is fixed at
  `m/44'/1033'/0'/0/<index>`
- **Until the number is final, funds MUST NOT be placed on a mainnet address.**
  The mainnet launch itself waits on the registration (§19)
- If the number changes, what is discarded is the derivation path, not the
  recovery phrase. The words stay valid and the funds move to addresses from the
  new path

#### Registering with SLIP-0044

`slip-0044.md` in the `satoshilabs/slips` repository is the only registry.

1. **Implement a BIP44-capable wallet first.** The registry states that a coin
   type is added only when a wallet implementing BIP-0044 for that coin exists.
   Implementation is a precondition of the application; the order cannot be
   reversed. **This is done.**
2. Pick an unused number. The numbers are not sequential and there are large
   gaps.
3. Open a pull request against `satoshilabs/slips` adding one row to the table in
   `slip-0044.md`. The table has three columns: `Coin type | Symbol | Coin`.
   **Submitted: `satoshilabs/slips` pull request #2061. Awaiting review.**

The number applied for is **1033**. It is a gap between 1032 and 1042, and
neither `OAG` nor `Orange` is registered.

```text
| 1032       | BTCR    | BTCR                              |
| 1033       | OAG     | Orange                            |   ← the row added
| 1042       | MFID    | Moonfish ID                       |
```

**When picking a number, look at the open pull requests as well as the registry
itself.** A number free in the registry still collides if someone applied
earlier. The first application used 1031 (the lowest gap in the registry), but
pull request #2059, filed six days earlier, claimed the same 1031 for NYEN, so
it was changed to 1033. The 1032 in between is taken by BTCR.

**This number is still not final.** The implementation puts 1033 in
`COIN_TYPE_MAINNET` in `crates/oag-wallet/src/seed.rs`, and
`coin_type(Network::Mainnet)` returns it. If the PR is merged, the constant
stands as is. If a different number is accepted, that single constant changes and
**every mainnet address created before that becomes invalid.** This is why the
mainnet launch waits for the registration.

Neither the formal application procedure nor the review criteria are documented.
**Since neither acceptance nor timing is guaranteed, this is built into the
mainnet launch schedule.** testnet uses number 1 and does not depend on the
registration at all.

Choosing secp256k1 makes BIP32 **non-hardened derivation** available. That means
an unlimited number of child addresses can be generated from an extended public
key (xpub) alone, so per-customer deposit addresses can be issued without any
private key on the server. (With Ed25519-family curves this is impossible in
principle.)

### 6.7 A note on address reuse

This chain is a transparent ledger. Reusing one address makes its entire history
and balance fully visible to anyone, and once an identity is linked to it even
once, every past and future transaction is identified.

A wallet MUST generate a new address for each receipt.

---
## 7. Transactions

### 7.1 Structure

```
Transaction {
    version:       u32
    input_count:   varint
    inputs:        TxInput[input_count]
    output_count:  varint
    outputs:       TxOutput[output_count]
    locktime:      varint          // interpreted as u64
}

TxInput {
    prev_txid:     [u8; 32]
    prev_index:    varint
    sig_len:       varint          // 64 or 65
    signature:     [u8; sig_len]
    sequence:      u32
}

TxOutput {
    amount:        varint          // u128 (atomic units)
    version:       u8              // address version
    payload_len:   varint          // 2–40
    payload:       [u8; payload_len]
}
```

#### Outputs are self-describing

`payload_len` cannot be omitted. In a design where the length is implied by the
version, **a node that meets an output with an unknown version cannot read past
it.** As a result, every use of the extension space reserved in
[§6.3](#63-address-versions) and [§17.3](#173-room-for-future-extension) would
need a hard fork.

Stating the length explicitly means that even after version 1 and beyond are
added, every old node can skip the output (it will not relay it as standard,
since it does not understand the meaning, but it can still read the structure of
the block). This is the same reason Bitcoin's outputs carry an explicit
`scriptPubKey` length.

The cost is one byte per output.

### 7.2 Size of a standard transaction

The **reference transaction** in this specification is a payment with one input
and two outputs whose amounts fit in a 9-byte varint. Capacity and fee estimates
are given in these units.

```
1 input:   prev_txid 32 + prev_index 1 + sig_len 1 + signature 64 + sequence 4
                                                           = 102 bytes
2 outputs: (amount 9 + version 1 + payload_len 1 + payload 32) × 2
                                                           =  86 bytes
other:     version 4 + input count 1 + output count 1 + locktime 1
                                                           =   7 bytes
──────────────────────────────────────────────────────
total                                                      = 195 bytes
```

Note that the input does not carry a public key. The UTXO being spent already
holds it.

| Metric | Value |
| --- | ---: |
| Reference transaction | **195 bytes** |
| Per 200,000-byte block | about 1,025 |
| Throughput | about 17.1 per second |

#### The encoded length of an amount depends on the amount

Because there are 16 decimal places, the varint length of an amount varies with
its size.

| Amount | atomic value | varint length |
| ---: | ---: | ---: |
| 0.001 OAG | 10^13 | 7 bytes |
| 1 OAG | 10^16 | 8 bytes |
| **7.2058 OAG** | **2^56** | **the 8 → 9 byte boundary** |
| 10 OAG | 10^17 | 9 bytes |
| 100 OAG | 10^18 | 9 bytes |
| 1,000 OAG | 10^19 | 10 bytes |

So even with the same one input and two outputs, a small payment (under
7.21 OAG) is **193 bytes**, the reference transaction is **195 bytes**, and a
large payment (1,000 OAG and up) is **197 bytes**. Estimates use the reference
transaction.

This follows directly from choosing 16 decimal places. At 8 places, amounts
would fit in 4–5 bytes.

### 7.3 How fees are expressed

There is no explicit fee field.

```
fee = Σ(amounts of the UTXOs the inputs reference) − Σ(output amounts)
```

The miner collects that difference through the coinbase. **Forgetting to write a
change output makes the entire difference a fee.** A wallet MUST detect this and
warn.

### 7.4 locktime

```
locktime < 500,000,000   → interpreted as a block height
locktime ≥ 500,000,000   → interpreted as Unix seconds
locktime = 0             → no constraint
```

When interpreted as a time, the comparison is against the previous block's
**median time past** (the median of the last 11 blocks' timestamps).

The conditions are as follows. `locktime` means "the earliest point at which
this transaction may be included".

```
as a height:  block height ≥ locktime
as a time:    median time past ≥ locktime
```

> **Difference from Bitcoin**: Bitcoin's condition is `locktime < height`, so a
> transaction with `locktime = 100` first becomes valid at height 101. That
> off-by-one semantics is a source of confusion and is not adopted here. Here,
> `locktime = 100` becomes valid at exactly height 100.

`locktime` is held as `u64`; `u32` breaks in 2106.

### 7.5 sequence (relative locktime)

The semantics follow BIP68.

```
bit 31 = 1  → relative locktime disabled
bit 31 = 0  → relative locktime enabled
    bit 22 = 0  → bits 0-15 interpreted as a block count
    bit 22 = 1  → bits 0-15 interpreted as units of 512 seconds
```

In v1 relative locktime is **not enforced**, but the semantics of the field are
fixed here so that enforcement can be turned on by a later soft fork.

**`sequence` MUST NOT be used to signal replaceability.** That is the usage in
BIP125 rule 1, and this chain does not adopt it
([§13.3.2](#1332-replacement-by-fee-rbf)). Loading one field with two unrelated
meanings — relative locktime and replaceability — means setting one silently
changes the other.

### 7.6 The coinbase transaction

The first transaction in a block MUST be the coinbase.

```
CoinbaseTransaction {
    version:       u32
    input_count:   varint = 1
    input: {
        prev_txid:  [u8; 32] = all zero
        prev_index: varint   = 0xFFFFFFFF
        sig_len:    varint   // length of arbitrary extra-nonce data (max 100)
        signature:  [u8; sig_len]   // MUST begin with height as a varint
        sequence:   u32
    }
    output_count:  varint
    outputs:       TxOutput[]
    locktime:      varint = 0
}
```

The `signature` field is not a signature; it is the miner's extra-nonce space.
Beginning it with the block height prevents coinbases at different heights from
sharing a txid (the same intent as Bitcoin's BIP34).

---

## 8. Signature hash (sighash)

The **BIP341** construction is used.

This chain has no scripts, so what corresponds to BIP341's `scriptPubKey` is the
output's **spending condition** (`version || payload_len || payload`, called the
lock below).

### 8.0 Tagged hashes

```
tagged(tag, msg) = BLAKE3(tag bytes || 0x00 || msg)
```

BIP340 uses `SHA256(SHA256(tag) || SHA256(tag) || msg)`, which is a workaround
for SHA-256 being vulnerable to length extension. BLAKE3 is structurally
length-extension resistant, so prefixing the tag with a NUL separator is enough.
Since tags contain no NUL, this encoding is prefix-free, and different tags can
never produce the same input string.

### 8.1 Construction

```
msg =
    0x00                                       // epoch
    hash_type                          u8      // the byte from §8.3
    tx.version                         u32 LE
    tx.locktime                        u64 LE

    ─── only when not ANYONECANPAY ─────────────────────────
    tagged("OAG/sighash/prevouts",   prev_txid || prev_index of every input)
    tagged("OAG/sighash/amounts",    amounts of the UTXOs every input references) ★
    tagged("OAG/sighash/locks",      locks of the UTXOs every input references)   ★
    tagged("OAG/sighash/sequences",  sequence of every input)

    ─── commitment to outputs (by base type) ───────────────
    ALL / DEFAULT : tagged("OAG/sighash/outputs", output count || all outputs)
    SINGLE        : tagged("OAG/sighash/outputs", 1 || the corresponding output)
    NONE          : (nothing included)

    input_index                        u32 LE

    ─── only when ANYONECANPAY ─────────────────────────────
    this input's prev_txid || prev_index
    the amount of the UTXO this input references                           ★
    the lock of the UTXO this input references                             ★
    this input's sequence              u32 LE

sighash = tagged("OAG/sighash", msg)
```

The three items marked ★ are the subject of
[§8.2](#82-committing-to-every-input-amount).

Under `SINGLE`, if there is no corresponding output, no signature can be
produced. Bitcoin's behaviour of "return the hash value 1" is not adopted; here
it is an outright error.

#### The inner hashes do not depend on the input index

Of the parts above, five — `H(prevouts)`, `H(amounts)`, `H(locks)`,
`H(sequences)`, and `H(outputs)` under `ALL` — **are not a function of the
input index**. They come out the same for every input of the same transaction.

An implementation SHOULD compute them once per transaction. Rebuilding them
for each input means hashing the same bytes n times for a transaction with n
inputs, which **makes the work O(n²)**. Each input adds about 76 bytes to
those buffers, so a transaction filling `MAX_TX_SIZE` — roughly 980 inputs —
would hash 73 MB.

**This is an optimisation, not a rule.** Either way the sighash comes out the
same, and consensus is unaffected.

### 8.2 Committing to every input amount

Including `H(amounts of the UTXOs every input references)` is a key point of
this specification.

> **Background**: Bitcoin's original sighash did not commit to input amounts.
> That allowed a malicious PC to tell a hardware wallet a false input amount,
> get it signed, and drain the difference as a miner fee. Bitcoin fixed this in
> BIP143 (SegWit). This specification includes it from the first version, so a
> hardware wallet can check the fee by itself.

### 8.3 Sighash flags

| Value | Name | Meaning |
| ---: | --- | --- |
| `0x00` | DEFAULT | same as `ALL`. Signature is 64 bytes (the flag byte is omitted) |
| `0x01` | ALL | commits to all inputs and all outputs |
| `0x02` | NONE | does not commit to outputs |
| `0x03` | SINGLE | commits only to the output at the same index |
| `0x81` | ALL \| ANYONECANPAY | own input only + all outputs |
| `0x82` | NONE \| ANYONECANPAY | own input only |
| `0x83` | SINGLE \| ANYONECANPAY | own input + the corresponding output only |

For anything other than `0x00`, the signature is 65 bytes and the last byte is
the flag.

Any byte not in the table above (`0x04` and up, and `0x80`, which would be
`ANYONECANPAY` alone) is **undefined and MUST be rejected**.

`SINGLE | ANYONECANPAY` is used to build partially signed transactions. See
[Interoperability and DEXs](#17-interoperability-and-dexs).

---

## 9. Blocks

### 9.1 Block header (fixed at 100 bytes)

```
BlockHeader {
    version:       u32        //  4  offset  0
    prev_hash:     [u8; 32]   // 32  offset  4
    merkle_root:   [u8; 32]   // 32  offset 36
    timestamp:     i64        //  8  offset 68   Unix seconds
    difficulty:    u64        //  8  offset 76
    height:        u64        //  8  offset 84
    nonce:         u64        //  8  offset 92
}                             // 100 bytes total
```

Putting `nonce` last lets a miner iterate by rewriting only the final 8 bytes.

### 9.2 Why the timestamp is i64

Bitcoin's block header carries a `u32` timestamp, which **overflows on
7 February 2106**.

This chain finishes emission about 190 years after 2026 — **2216** — so it
certainly crosses that point. `u32` is therefore not an option.

### 9.3 How difficulty is expressed

Bitcoin's `nBits` (a 4-byte compact form) is not used. Difficulty is held
directly as `u64`, and the target is derived:

```
MAX_TARGET = 2^256 − 1
target(difficulty) = MAX_TARGET / difficulty      (integer division)
```

`nBits` has historically produced bugs from non-canonical encodings and sign-bit
handling, and LWMA works with difficulty directly, so `u64` is both simpler and
safer.

### 9.4 Block

```
Block {
    header:       BlockHeader
    tx_count:     varint
    transactions: Transaction[tx_count]
}
```

### 9.5 Reservation for aux_pow (merged mining)

**Bit 0** of the `version` field is reserved as the `AUX_POW` flag.

```
version & 0x00000001 == 0  → verify RandomX(header) directly  (the only path in v1)
version & 0x00000001 == 1  → verify the parent chain's PoW    (undefined)
```

In v1, a block with this bit set is **invalid**. If merged mining with Monero is
introduced later, the auxiliary PoW data will go outside the header, in the
block body; the header's size and structure will not change.

---
## 10. Consensus rules

### 10.1 Parameters

```
TARGET_BLOCK_TIME        = 60 seconds
MAX_BLOCK_SIZE           = 200,000 bytes
MAX_TX_SIZE              = 100,000 bytes
COINBASE_MATURITY        = 120 blocks  (2 hours)
MEDIAN_TIME_SPAN         = 11 blocks
MAX_FUTURE_TIME_DRIFT    = 300 seconds
```

`MAX_FUTURE_TIME_DRIFT` is far shorter than Bitcoin's two hours. At a 60-second
block interval, two hours would grant 120 blocks' worth of latitude, which
leaves too much room to manipulate difficulty.

`COINBASE_MATURITY` is **deeper than Bitcoin's 100 blocks**. In wall-clock terms
two hours looks short, but the unit that matters is block count. Pushing back a
reorg takes cumulative work, and that is proportional to block count
(→ [settled items in §19](#settled-items)).

### 10.2 Block validation

A block MUST satisfy all of the following.

1. Serialised size is at most `MAX_BLOCK_SIZE`
2. `header.height == parent's height + 1`
3. `header.prev_hash` points at a known valid block
4. `header.timestamp > the parent's median time past`
5. `header.timestamp ≤ the node's current time + MAX_FUTURE_TIME_DRIFT`
6. `header.difficulty` matches what [LWMA](#12-difficulty-adjustment-lwma) computes
7. The `AUX_POW` bit of `header.version` is 0
8. The PoW is valid ([Proof of work](#11-proof-of-work))
9. `header.merkle_root` matches the value recomputed from the transaction list
10. The first transaction is the coinbase and no other transaction is
11. The height at the head of the coinbase's `signature` matches `header.height`
12. Every transaction is valid
13. Total coinbase outputs ≤ `block_subsidy(height) + total fees`
14. No UTXO is spent twice within the same block
15. The block is not empty
16. The coinbase has at least one output and does not exceed `MAX_TX_SIZE`

### 10.3 Transaction validation

1. At least one input and at least one output
2. Serialised size is at most `MAX_TX_SIZE`
3. Every input references an unspent output present in the UTXO set
4. When spending a coinbase output,
   `current height − creation height ≥ COINBASE_MATURITY`
5. Every output amount satisfies `0 ≤ amount ≤ MAX_SUPPLY`
6. `Σinputs ≥ Σoutputs` (evaluated with checked arithmetic; invalid on overflow)
7. For every input, the referenced spending condition is checked per
   [§10.4](#104-handling-unknown-versions)
8. Every input's signature passes
   [BIP340](#53-signatures-schnorr-bip340) verification
9. The `locktime` condition is satisfied
10. No UTXO is spent twice within the same transaction

### 10.4 Handling unknown versions

When an output's version is unknown to the node, it **MUST be treated as
anyone-can-spend for consensus purposes and its signature MUST NOT be checked**.

#### Why rejecting is not allowed

Treating an unknown version as invalid means that every time a new version is
introduced, old nodes reject new blocks — **adding a version necessarily becomes
a hard fork.** That would waste the whole point of giving outputs a length prefix
([§7.1](#71-structure)).

Leaving them anyone-can-spend lets a version be activated later by **tightening
the condition in a soft fork**. From an old node's point of view, new nodes are
merely checking an output that anyone should be able to spend more strictly, and
blocks produced by new nodes remain valid to old nodes. This is the same
mechanism Bitcoin used to deploy SegWit.

#### The accompanying danger

**Until a version is activated, funds must not be sent to an address of that
version.** They would be spendable by anyone. This is mitigated as follows.

| Layer | Mitigation |
| --- | --- |
| Wallet | warn when sending to an address of an unknown version ([§6.3](#63-address-versions)) |
| Node policy | do not relay a transaction that creates an output of an unknown version |
| Node policy | do not relay a transaction that spends an output of an unknown version |

The two policy-layer items are not consensus rules, so nothing stops a miner
from including such a transaction directly. Bitcoin has the same property.

#### Decision (confirmed)

This treatment **stands.**

The seemingly safer alternative is "an unknown version is invalid". But choosing
it means old nodes reject new blocks every time a version is added. **Adding a
version necessarily becomes a hard fork**, and the reason for making outputs
self-describing ([§7.1](#71-structure)) is lost at that point. For a small
network, a hard fork requiring every node to upgrade simultaneously is more
dangerous than a loss of funds that the three layers above already mitigate.

On top of that, **the range of versions is narrowed.**

```
A transaction with an output version of 32 or above MUST be invalid
```

Address versions live in bech32m's 5-bit field and can only express 0–31
([§6.3](#63-address-versions)). A version of 32 or above is **unreachable from
any address**. Even if an output form that bypasses addresses is added later, the
31 free slots from 1 to 31 suffice. The restriction therefore removes no soft-fork
headroom; it only shrinks the anyone-can-spend surface from 255 kinds to 31.

The restriction is **already in force**. `Lock` refuses a version of 32 or above
both at construction and at decoding, so a transaction containing one cannot even
be read.

### 10.5 Validation order (DoS resistance)

RandomX light-mode verification costs a few milliseconds per hash. An attacker
could exhaust a node's CPU by sending invalid headers in bulk, so **PoW
verification MUST come last.**

```
① is the parent known?              (hash map lookup)
② is height parent + 1?             (integer comparison)
③ is the timestamp in range?        (integer comparison)
④ does difficulty match expectation? (integer comparison)
⑤ is version's AUX_POW bit 0?       (bit operation)
   ────── only what passes all of the above ──────
⑥ RandomX verification              (several milliseconds)
```

In addition, a per-peer rate limit on header receipt MUST be applied.

### 10.6 Choosing the longest chain

The chain with the greatest cumulative work (the sum of each block's
`difficulty`) is adopted. The comparison is by work, not by block count.

**Ties**: when several tips have equal cumulative work, the one with the
**smaller block hash** MUST be chosen — except that a tie with the current tip
keeps the current tip (the chain received first wins). Without a defined tie
order, two chains of equal work arriving together make different nodes pick
different tips and consensus splits.

Tip candidates are **limited to blocks whose body is present**. A block known
only by its header cannot be connected and is therefore not a candidate
([§14.5](#145-p2p-protocol)). It MUST also be verified that every block on the
path from the candidate back to where it joins the active chain has its body.

No limit is placed on reorg depth. **None MUST be placed.** A network that has
split deeper than the limit never rejoins
(→ [settled items in §19](#settled-items)).

This is about a limit **as a rule**. A node that cannot go back because it no
longer holds the rollback data is not the same as a rule that caps the depth.
Even then it **MUST NOT** settle into some other state: it says it cannot
follow, so that the operator can sync again
(→ [§19](#settled-items)).

#### How two diverged nodes converge

Two nodes that mined different blocks while apart hold different ledgers at the
moment they connect. They converge like this.

```
        fork point
          │
   A ─────┼── a1 ── a2 ── a3                work 3
          └── b1 ── b2 ── b3 ── b4 ── b5    work 5   B
```

1. They connect. Each learns the other's height from `version`
2. The one that is behind (A) sends `getheaders`. Its locator lists A's own
   branch. B knows none of them, so from the height where **the two last agree**
   — the fork point here — it returns the headers for `b1..b5`
3. A validates the headers and puts them in its index. The tip does not move
   yet: a block with no body cannot be connected ([§14.5](#145-p2p-protocol))
4. A fetches the bodies of `b1..b5`, oldest first
5. When `b5` arrives, B's branch exceeds A's tip in work. A undoes `a3, a2, a1`,
   rewinds the UTXO set, and reconnects `b1..b5` **validating them itself**

Nothing switches while the work is tied. Two nodes that diverged at the same
height therefore do not converge merely by connecting. **They converge the moment
either one mines the next block.**

The coinbase of an undone branch MUST disappear from the UTXO set. Leaving it
would make money that does not exist spendable. Coinbase maturity
([§7.6](#76-the-coinbase-transaction)) exists to stop rewards circulating during
the period in which such an undo can occur.

#### Transactions from an undone branch

A reorg is not only about the UTXO set. **The mempool is also a projection of
what lies ahead of the active chain, so when the tip moves it has to be
realigned.**

Transactions that were in the undone branch go back to being unconfirmed.

- Non-coinbase transactions from the undone branch SHOULD be **returned to the
  mempool**. Otherwise a payment that once reached confirmation vanishes from
  every node's mempool, and is never mined again until the sender resends
- **The coinbase MUST NOT be returned.** The coinbase of an undone branch is a
  reward that no longer exists
- Before returning them, they **MUST be revalidated against the post-reorg
  UTXO set.** If the new branch spends the same UTXO, it is a double spend

Transactions that became confirmed on the new branch MUST be removed from the
mempool. Mining with them still present produces a block whose transactions have
no inputs — **a block you mined yourself, rejected by yourself.**

#### Revalidate what remains, too

Removing only "what was in the undone branch" and "what entered the new branch"
is not enough. **A reorg also invalidates the premises of the transactions that
remain.**

| What breaks | What happens |
| --- | --- |
| The parent was in the undone branch and could not be returned | the output being spent does not exist |
| The height went backwards | coinbase maturity ([§7.6](#76-the-coinbase-transaction)) is no longer met |
| The height went backwards | the locktime is in the future again |

After a reorg, therefore, the **entire mempool SHOULD be revalidated against the
post-reorg UTXO set.** Picking out the ones that fail misses all three of the
above.

The cost is proportional to the size of the mempool (signatures are re-verified).
Reorgs are rare and the mempool is bounded, so validating everything is preferred
over the complexity of selecting.

In this implementation `Mempool::rebuild_after_reorg` does this. It merges what
is being returned with what remains, **sorts parents before children**, and
re-accepts them in order. Offering a child first would fail, because at that
point its parent's output is not there.

#### Do not remove transactions merely because they were in a losing branch

When a received block does not join the active chain (a side chain), the
**mempool MUST NOT be touched.** The transactions in that block are still
unconfirmed and, as seen from our tip, still valid. Removing them here would stop
us relaying payments that are still valid and stop us including them when we
mine. Forks happen quite normally, so the impact is not small.

#### Implementation requirement: do not scan everything to find candidates

Implementing tip-candidate search as "scan the whole block index for the greatest
work" is O(n) per block and O(n²) over an initial sync. This implementation keeps
an incrementally maintained set ordered by work and looks only at the tail that
exceeds the current tip (the equivalent of Bitcoin's `setBlockIndexCandidates`).

Measured (candidate search isolated, per block):

| Blocks | Full scan | Incremental index |
| ---: | ---: | ---: |
| 1,000 | 1.8 μs | 0.037 μs |
| 10,000 | 31.5 μs | 0.051 μs |
| 100,000 | 655 μs | 0.062 μs |
| 400,000 | 7,070 μs | 0.072 μs |

Under the same conditions, writing to storage costs about 1,500 μs per block. At
a few thousand blocks the cost of a full scan is buried under the write. **At
100,000 blocks (about two and a half months) it matches the write, and beyond
that it dominates.**

The same applies to finding the header with the most work
([§14.5](#145-p2p-protocol)) and to propagating an invalid mark to descendants:
avoid full scans there too.

### 10.7 Confirmations for the receiving side

**This is not a consensus rule.** It is not a threshold at which a node rejects
anything; it is a guideline for someone receiving funds to decide "this will not
be undone".

The chain has no mechanism for declaring finality. As long as reorg depth is
unbounded ([§10.6](#106-choosing-the-longest-chain)), the probability of reversal
is never zero at any confirmation count. The receiver decides.

| Situation | Confirmations | Rough wall-clock | Kind |
| --- | ---: | ---: | --- |
| Accepting as payment | **10** | about 10 minutes | guideline |
| Large, or goods you cannot claw back | 20 or more | 20 minutes or more | guideline |
| Coinbase (mining reward) | 120 | about 2 hours | **consensus rule** ([§7.6](#76-the-coinbase-transaction)) |
| Zero confirmations | **MUST NOT be accepted** | — | [§13.3.2](#1332-replacement-by-fee-rbf) |

#### The basis for 10

The unit of comparison is **block count, not time.** The probability that an
attacker with hashrate share q overtakes z confirmations is determined by q and z
alone and **does not depend on the block interval** (Bitcoin whitepaper §11). The
conversion "blocks are 60 seconds, so wait ten times Bitcoin's count" is
therefore wrong.

| q (attacker's share) | z = 6 | z = 10 | z = 20 | z = 120 |
| ---: | ---: | ---: | ---: | ---: |
| 10 % | 0.024 % | 0.00012 % | ~0 | ~0 |
| 20 % | 1.43 % | 0.11 % | 0.0002 % | ~0 |
| 25 % | 4.99 % | 0.85 % | 0.011 % | ~0 |
| 30 % | 13.2 % | 4.17 % | 0.25 % | ~0 |
| 35 % | 28.2 % | 14.3 % | 2.77 % | 0.0000004 % |
| 40 % | 50.4 % | 36.0 % | 16.4 % | 0.010 % |

Bitcoin's convention is 6. This chain's guideline is **10**. For the same q, the
probability of reversal is roughly an order of magnitude below 6 confirmations.

The reason 6 is not enough is **cost**, not probability. q is "what fraction of
the whole you hold", and the price of that fraction is proportional to the
network's total hashrate. **On a young chain the whole is small, so the same q is
cheap to buy.** The probability formula does not reflect that difference. The
extra confirmations fill in a little of what it does not reflect.

The wait is 10 minutes. At 60 seconds per block that is shorter than Bitcoin's 6
confirmations (about 60 minutes). The position is **higher on probability, lower
on waiting time.**

#### When to wait beyond 10

- What you hand over cannot be recovered (physical goods, digital goods, a
  withdrawal to another chain)
- The amount received is large compared with 10 blocks of reward (100 OAG plus
  fees). If the profit exceeds the reward the attacker forgoes, the attack pays
- Hashrate has dropped sharply just beforehand. Until difficulty catches up
  ([§12](#12-difficulty-adjustment-lwma)), the same confirmation count is cheaper
  to overturn

#### When a reorg happens

**Confirmation counts do not only increase. They decrease, and they vanish.**

When a fork resolves, payments that were in the losing branch return to
unconfirmed ([§10.6](#106-choosing-the-longest-chain)). From the receiver's side:

| After the reorg | What happens |
| --- | --- |
| The new branch also contains the payment | the count **comes back at that depth** (9 → 2, say) and grows again |
| It is not in the new branch yet | the count **returns to 0**. It goes back to the mempool and waits to be mined again |
| The new branch spent the same UTXO to a different recipient | **that payment will never confirm.** A double spend has succeeded |

The third row is the entire reason for waiting for confirmations. Hand over goods
at 9 confirmations, get a 10-block reorg, and what you handed over does not come
back.

The wallet **re-reads the chain's UTXO set every time**, so running `balance`
after a reorg gives the correct value. It never remembers a previous display and
disagrees with the chain. But **there is no mechanism to tell you the count went
down.** Having seen 10 confirmations once does not mean you need not look again.

Check the confirmations **immediately before handing anything over.** It may have
gone backwards in the time between seeing 10 and fetching the goods.

#### How this is handled in the implementation

`oag-consensus::params::RECOMMENDED_CONFIRMATIONS` is 10. The wallet's
`balance --verbose` shows the confirmation count per UTXO and marks anything
under 10. **The mark is display only and does not block a send.** What to wait
for is the receiver's decision, not the wallet's.

---

### 10.8 assumevalid (shortening the initial sync)

An initial sync re-checks **every signature** from the genesis block to the
tip. The taller the chain grows, the more of the sync time this accounts for.

For blocks that are already buried deeply enough, there is a case for not
checking them again locally: an attacker cannot go back that far and rebuild
the proof of work.

**This is not a consensus rule.** The set of blocks that are accepted does not
change. Nodes configured differently still converge on the same chain. An
implementation therefore need not have this at all, and may leave it off by
default.

#### The rule

Where an implementation does have it, signature checking may be omitted only
for a block that meets **all** of the following.

1. There is a block A that the user or the implementation **named in advance**.
2. The block B being checked **is A, or is an ancestor of A**.

That B is an ancestor of A is established by walking back from A to height B
and finding B's hash there.

#### Only the signature check may be omitted

All of the following are still checked as before.

- Proof of work, difficulty, timestamp, height, the reference to the parent
- The merkle root
- Block and transaction sizes
- The amounts, and what the coinbase pays itself
- Double spends, both within the block and against the UTXO set
- Coinbase maturity and locktimes
- The length of the signature field, the sighash type, and the form of the
  public key and the signature

**Exactly one elliptic-curve check is omitted.**

#### Why ancestry is required

Without it, an attacker could switch signature checking off simply by feeding
you a different chain at or below height h. Requiring ancestry means an
attacker's chain is never an ancestor of the named block, so nothing is
omitted on it. Forging the named block itself would mean finding a BLAKE3
preimage.

While the named block has not been received, **nothing is omitted**.

#### What you are taking on trust

**That the named block is on the real chain.** This is not something you check;
it is something you **assume**. You are taking someone's word for it.

Accordingly:

- An implementation **MUST** let the user turn it off.
- Where a per-network default is shipped, its **hash and height MUST be
  published** so that a user can confirm them independently.
- The node **MUST** say at startup that it is in effect. It must not quietly
  stop checking.

#### In the implementation

`oag-node` takes `--assumevalid <hash>`, and `--assumevalid=0` turns it off.
Every per-network default is currently empty (`None`): putting a value there
means claiming that a block at that height is genuine, and not enough time has
passed to make that claim.

The mempool is **always checked in full**. This is a relaxation that is only
defensible for the deeply buried past; it does not apply to unconfirmed
transactions.

---
## 11. Proof of work

### 11.1 Algorithm

**RandomX** ([tevador/RandomX](https://github.com/tevador/RandomX), MIT) is
used, reached from Rust by FFI to the C++ reference implementation.

```
pow_hash = RandomX(seed_hash, header_serialized)
valid when: pow_hash (read as a big-endian u256) ≤ target(difficulty)
```

### 11.2 Modes

| Mode | Memory | Use |
| --- | ---: | --- |
| fast | 2 GB (shared) + 256 MB | mining |
| light | 256 MB | node validation |

A full node MUST be able to run in light mode. That is, running a node does not
require the 2 GB dataset. **Whether you mine and whether you can validate are
separate questions.**

**Both modes MUST return the same hash.** Only speed and memory differ. If that
breaks, a block mined in fast mode is rejected by a light-mode node. The test
`oag-pow/tests/fast_mode.rs::the_two_modes_agree_on_every_hash` compares the two
modes' output.

Fast mode builds and uses a 2 GB dataset. **Building it takes about a minute**,
so it must be rebuilt every time the seed epoch ([§11.3](#113-seed-epochs))
changes (2048 blocks, about 34 hours). The dataset is read-only, and as far as
the protocol is concerned it may be shared across threads. Only the VM is needed
per thread.

If 2 GB cannot be allocated, mining in light mode is fine. It is slower, but the
blocks it finds are the same.

**Thread safety**: a RandomX VM holds an internal scratchpad and must not be
shared across threads. When validating or mining in parallel, there **MUST be one
VM per thread.** Note that even light mode needs a 256 MB cache per thread (the
cache itself can be shared, but this implementation prefers simplicity and does
not share it).

#### Mining with several threads

Mining threads SHOULD **divide the nonce space evenly** between them: split 64
bits by the thread count and have each try a non-overlapping range. As soon as
one hit appears, everyone abandons the search on that template.

When the tip moves, the templates already handed out MUST be discarded. **A block
found on a template you failed to discard builds on the previous tip.**
Publishing it means creating a fork yourself. This implementation stamps
templates with a generation number and discards mismatches (the `pool` module in
`oag-miner`).

The fast-mode dataset **SHOULD be shared by all threads, one copy**. Each extra
thread only adds its VM's 2 MB scratchpad. Light mode multiplies by the thread
count in this implementation, because the cache is not shared.

| Mode | 1 thread | With 4 threads |
| --- | ---: | ---: |
| light | 256 MB | 1 GB |
| fast | 2 GB | 2 GB |

The light verifier used for validation is needed separately, one of them. A
mining thread's miner cannot be reused for validation (a VM cannot cross
threads).

> **How this implementation is built**: in `randomx-rs` 1.6.0, `RandomXDataset`
> is not `Send`, because it holds a raw pointer. `SharedDataset` in `oag-pow`
> wraps it and carries two lines of `unsafe impl Send / Sync`. **Those two lines
> are the only `unsafe` written anywhere in the workspace.** `oag-pow` alone is
> lowered to `#![deny(unsafe_code)]`; every other crate keeps
> `#![forbid(unsafe_code)]`. What those lines take responsibility for (read-only
> after initialisation, RandomX's own benchmark uses it the same way, freed
> exactly once through `Arc`) is written on `SharedDataset`.
>
> The VM is not wrapped. **The miner is still not passed around — the recipe
> is.** The recipe carries the `SharedDataset` across the thread boundary, and
> each worker thread builds its own VM on top of it. For the history, see
> [§19](#multi-threaded-mining-shares-the-dataset).

### 11.3 Seed epochs

The RandomX seed rotates at a fixed interval. Monero's scheme is used.

```
SEED_EPOCH_BLOCKS = 2048        (about 34 hours)
SEED_LAG          = 64 blocks

seed_height(h) = ((h − SEED_LAG) / 2048) × 2048      (for h ≥ 2048 + SEED_LAG)
seed_hash      = the block hash at seed_height
```

A shorter epoch makes miners rebuild the 2 GB dataset more often (one to two
minutes each time), lowering effective hashrate.

`SEED_LAG` is the grace period that keeps a reorg from changing the seed.

**`seed_hash` MUST be looked up on the branch of the header being validated.** It
MUST NOT be looked up in the active chain's height index. During headers-first
sync ([§14.5](#145-p2p-protocol)) there is a period where headers have arrived up
to height several thousand while not a single body has been connected, and during
that period the active chain's height is still 0. The index answers "not found"
even for a seed it ought to know.

When the lookup fails, another hash MUST NOT be substituted. With a different
key RandomX returns a different hash and **the PoW of a perfectly good block
fails.** Sync stops at an epoch boundary and cannot advance past it. If it cannot
be looked up, return an error.

### 11.4 What to uphold at the FFI boundary

RandomX is implemented in C++. Forbidding `unsafe` on the Rust side constrains
only the code written here — not the `unsafe` inside the crates being wrapped,
nor the C++ beyond them. The implementation MUST uphold the following at the
boundary.

**The VM MUST be checked for NULL.** C++'s `randomx_create_vm` returns
`nullptr` when VM allocation (`vm->allocate()`) throws. That happens when the
2 MB scratchpad cannot be allocated, or when the JIT cannot map executable
memory. `randomx-rs` 1.6.0 does not check for this NULL and wraps it in `Ok`, so
**using it as-is dereferences NULL on the first hash and takes the node down.**
Return an error and keep the node running.

**SHOULD fall back where the JIT is unavailable.** The flags recommended by
`randomx_get_flags` include `FLAG_JIT`. The JIT requires executable memory, so
allocation fails under SELinux's `deny_execmem`, PaX MPROTECT, containers that
enforce W^X, and so on. RandomX has an interpreter path (`FLAG_DEFAULT`) that
requires no executable memory. The implementation tries flags in the order

1. the recommended value (with JIT and hardware AES)
2. the recommended value minus `FLAG_JIT`
3. `FLAG_DEFAULT` (interpreter, software AES)

and uses the first that works. **Every path MUST return the same hash** (flags
select speed; there is only one thing being computed). If that breaks, consensus
splits on whether a node has a JIT. The test
`oag-pow/src/randomx.rs::every_flag_in_the_ladder_actually_produces_a_working_vm`
compares the output of every candidate.

The interpreter is roughly ten times slower. Falling back SHOULD be reported to
the operator.

**Large pages SHOULD be tried, and given up on quietly.** Fast mode reads all
over a 2 GB dataset, which is more than 4 KB pages' TLB can cover. The cache and
the dataset are first allocated with `FLAG_LARGE_PAGES`, and allocated again
without it if that fails. Large pages are almost never available without setup
on the OS side (`vm.nr_hugepages` on Linux, the "Lock pages in memory" right on
Windows), so **failing to get them MUST NOT be an error**. The flag is a speed
setting; the hash does not change.

They are not used for the VM's scratchpad. If allocating a VM fails, NULL comes
back and, by the rule below, cannot be freed. If it holds a reference to the
shared dataset, 2 GB is never freed again. For the same reason, the flags for
building VMs on the shared dataset are decided once, before building it, with a
light VM on the cache.

**A VM that was NULL MUST NOT be freed.** C++'s `randomx_destroy_vm` begins with
`assert(machine != nullptr)`. That line disappears under `NDEBUG`, but the
`cmake` crate carries Rust's profile straight through, so **under `cargo test`'s
default (dev) RandomX is built with `CMAKE_BUILD_TYPE=Debug` and the assertion is
live.** Discarding a NULL VM aborts on the spot. Let it go without freeing. The
cache and dataset it holds leak, but this path is only reached when allocation
has already failed, and a leak beats a dead node.

> Note that a dev build of RandomX is compiled without optimisation, so **both
> mining and validation are orders of magnitude slower.** Use `--release` when
> measuring speed.

---

## 12. Difficulty adjustment (LWMA)

### 12.1 Algorithm

**LWMA-1**
([zawy12/difficulty-algorithms](https://github.com/zawy12/difficulty-algorithms))
is used, adjusting every block.

```
T = 60                        target block time (seconds)
N = 90                        window (provisional)
k = N × (N + 1) × T / 2

L = 0
sum_D = 0
for i in 1..=N:
    st = clamp(timestamp[i] − timestamp[i−1], −6×T, +6×T)
    L += st × i
    sum_D += difficulty[i]

if L < k / 10:
    L = k / 10                // floor that damps a difficulty spike

next_difficulty = (sum_D × k) / (N × L)
```

Tolerating inverted timestamps (negative solvetimes) and handling them by
clamping is the characteristic feature of LWMA.

### 12.2 Validating the window N

`N = 90` (a 90-minute window) is used. The following are measured values from the
implemented simulation (tests in `crates/oag-pow/src/lwma.rs`). Solvetimes follow
an exponential distribution and the randomness is deterministic, so the results
reproduce.

#### Steady state

| Seed | Mean block interval | Peak difficulty swing |
| ---: | ---: | ---: |
| 1 | 60.55 s | 1.62× the equilibrium |
| 2 | 60.51 s | 1.33× |
| 3 | 60.50 s | 1.53× |

Within 1 % of the 60-second target.

#### Tracking hashrate changes

Time to come within 20 % of the equilibrium difficulty.

| Change | Blocks | Wall clock |
| --- | ---: | ---: |
| ×2 | 31 | 0.20 hours |
| **×10** | **99** | **0.70 hours** |
| ×1/2 | 74 | 1.70 hours |
| **×1/10** | **145** | **5.64 hours** |

#### A known weakness: asymmetry

As the table shows, **it tracks increases quickly but recovers slowly from
decreases**. Tracking a tenfold increase takes 0.7 hours; recovering from a drop
to a tenth takes 5.6.

This is common to all PoW chains. When hashrate is lost, block intervals
lengthen, so the wall-clock time to get through the blocks needed to lower
difficulty grows. A narrower window recovers faster but swings more in steady
state.

The practical effect is that **when a large amount of hashrate arrives
temporarily and leaves, the chain is slow for several hours afterwards.** For a
small chain that is a real harm, and the Monero merged mining mentioned in
[§17](#17-interoperability-and-dexs) is also a measure against that very
volatility.

This specification adopts N = 90 and accepts the weakness as known.

### 12.3 The bootstrap period

```
height < N + 1  →  difficulty = GENESIS_DIFFICULTY (fixed)
height ≥ N + 1  →  LWMA applies
```

### 12.4 regtest does not adjust

| Network | Difficulty adjustment |
| --- | --- |
| mainnet | yes |
| testnet | yes |
| regtest | **no** (always GENESIS_DIFFICULTY = 1) |

regtest does not adjust. If it did, stacking blocks faster would raise
difficulty. regtest exists for testing, and merely waiting out coinbase maturity
(120 blocks) requires stacking 120 of them. Stacking far faster than the
60-second target makes LWMA correctly raise difficulty, so **the more you stack
the slower it gets, and the test never ends.**

This matches Bitcoin's regtest (`fPowNoRetargeting`).

**mainnet and testnet MUST adjust.** Without it, they cannot track hashrate
changes at all.

---

## 13. Fee policy

### 13.1 Two layers

Fees are treated as **node policy, not a consensus rule.**

```
Consensus layer (enforced by every node; changing it needs a hard fork)
  └ no minimum fee. Only Σinputs ≥ Σoutputs is required

Node policy layer (each node's setting, changeable at any time)
  └ a transaction below MIN_RELAY_FEE_RATE is neither relayed nor kept in the mempool
```

This separation allows the minimum fee to be adjusted for OAG price movements
**without a hard fork**.

### 13.2 Defaults

```
MIN_RELAY_FEE_RATE = 0.000005 OAG / byte
                   = 50,000,000,000 atomic / byte   (5 × 10^10)

fee for a reference transaction (195 bytes) = 0.000975 OAG
```

### 13.3 Dust threshold

Unspent UTXOs are held permanently by every node, so an attack that mass-produces
tiny outputs permanently pollutes every node's memory.

```
cost of spending one input = 102 bytes × 0.000005 = 0.00051 OAG
three times that           = 0.00153 OAG
DUST_THRESHOLD             = 0.0015 OAG   (rounded as a policy value; the ratio is about 2.94)
                           = 15,000,000,000,000 atomic  (1.5 × 10^13)
```

A transaction containing an output below `DUST_THRESHOLD` is not relayed (node
policy, not a consensus rule).

### 13.3.1 Handling unknown versions (policy layer)

As stated in [§10.4](#104-handling-unknown-versions), outputs of an unknown
version are spendable by anyone at the consensus layer. At the policy layer the
defaults are:

- do not relay a transaction that **creates** an output of an unknown version
- do not relay a transaction that **spends** an output of an unknown version

The first prevents the accident of losing funds by paying an address before its
version is activated. The second avoids helping anyone seize such funds.

Both are policy; nothing stops a miner from putting them straight into a block.

### 13.3.2 Replacement by fee (RBF)

A transaction spending the same UTXO as one already in the mempool **evicts** the
earlier one and takes its place if all of the following hold. The evicted
transaction's descendants go with it. These correspond to BIP125 rules 2 through
5.

| # | Rule |
| --- | --- |
| 2 | adds no **unconfirmed input** that the evicted set did not have |
| 3 | its fee is at least the **total** of what it evicts (descendants included) |
| 4 | that increase is at least `incremental_relay_fee_rate × the replacement's size` |
| 5 | the number evicted (descendants included) is at most 100 |

Defaults are in [appendix A](#appendix-a-parameter-list).

#### Rule 1 (signalling replaceability) MUST NOT apply

BIP125's rule 1 makes only transactions that signalled "replaceable" via
`sequence` replaceable. **This chain does not require that.** Replacement can
happen whether or not anything was signalled. This matches where Bitcoin
eventually landed.

The reason is that the signal is a promise that cannot be kept.

- A miner need only take the higher fee; nothing obliges it to look at the signal
- If even one node that ignores the signal relays it, the replacement reaches
  miners
- Therefore "it did not signal, so zero confirmations are safe" does not hold

Advertising a guarantee that does not hold costs money to whoever believes it. So
it is not advertised.

#### A zero-confirmation transaction MUST NOT be accepted as payment

This rule holds with or without RBF; RBF merely made it visible. The receiver
waits for confirmations. How many is a guideline in
[§10.7](#107-confirmations-for-the-receiving-side) (10 by default).

#### Rules 3 and 4 look at totals, not rates

Consequently **a large replacement at a low rate can evict a small one at a high
rate**, even though the evicted one might have been mined sooner.

This is a weakness BIP125 still carries, and Bitcoin has it too. Adding a rule of
our own here would mean strict nodes dropping what lenient nodes relayed, and
mempool contents would diverge between nodes. **A divergent mempool feeds
directly into the hit rate of compact blocks**
([§14.9](#149-compact-blocks)). Compatibility wins.

### 13.4 Assessing spam resistance

```
cost of filling a 200,000-byte block
  = 200,000 × 0.000005 = 1.0 OAG / block
  = 1,440 OAG / day
```

During the bootstrap period this is cheap enough. It is a property common to all
PoW chains and is not something this specification solves.

### 13.5 Estimated chain growth

```
200,000 bytes × 525,600 blocks/year = about 105 GB/year (when full)
```

The following therefore MUST be implemented from v1.

- **Pruning**: a mode that discards validated old block bodies and keeps only the
  UTXO set and headers
- **UTXO snapshot sync**: a path by which a new node can join without validating
  the whole history (equivalent to Bitcoin's assumeutxo)

---
## 14. Network parameters

### 14.1 Ports

| Network | P2P | RPC | Mining |
| --- | ---: | ---: | ---: |
| mainnet | 9444 | 9445 | 9446 |
| testnet | 19444 | 19445 | 19446 |
| regtest | 29444 | 29445 | 29446 |

Naming rule: `testnet = mainnet + 10000`, `regtest = mainnet + 20000`.

#### Avoiding collisions with existing chains

The following ports are effectively occupied by major existing chains and are
not used.

| Port | Use |
| ---: | --- |
| 8332 / 8333 | Bitcoin RPC / P2P |
| 8444 | Chia |
| 8232 / 8233 | Zcash |
| 9332 / 9333 | Litecoin |
| 9999 | Dash |
| 18080 / 18081 | Monero P2P / RPC |
| 18333 | Bitcoin testnet |
| **18444** | **Bitcoin regtest** |
| 22556 | Dogecoin |
| 30303 | Ethereum devp2p |

In particular, **Bitcoin's 8333 MUST NOT be used.** Protocol crosstalk is
prevented by the magic bytes, so it is not a safety issue, but it inherits the
following operational problems for free:

1. cannot coexist with a Bitcoin node on the same host
2. constant connection attempts from Bitcoin's peer gossip and crawlers
3. exposure to corporate firewalls, ISPs and censorship equipment that block 8333
   as a Bitcoin signature
4. conflicts with some hosting providers' policies

Because Bitcoin's regtest uses 18444, this chain's testnet is **19444**, not
18444.

#### Default bind addresses

| Service | Default bind | Reason |
| --- | --- | --- |
| P2P | `0.0.0.0` | accepting inbound connections is the point |
| **RPC** | **`127.0.0.1` only** | it can move funds |
| **Mining** | **`127.0.0.1` only** | as above |

Losses of funds caused by exposing RPC to the internet have actually occurred in
several projects, Bitcoin, Ethereum and Monero among them. The defaults MUST
prevent it.

The mining interface is separated from RPC specifically to avoid the situation
where RPC has to be exposed in order to let miners connect.

### 14.2 Magic bytes

Four bytes at the head of every message. They are checked at the start of the
handshake and **are the actual mechanism separating the networks.** A port number
is only an operational convention and guarantees no separation.

The values are not chosen arbitrarily; they are derived deterministically from
the network name.

```
magic = BLAKE3("Orange/network/<network name>")[0..4]
```

| Network | Derived from | Value |
| --- | --- | --- |
| mainnet | `Orange/network/mainnet` | `33 97 55 03` |
| testnet | `Orange/network/testnet` | `7F 88 A0 C1` |
| regtest | `Orange/network/regtest` | `18 2C 9C 5E` |

None consists solely of printable ASCII, making accidental appearance in a
plaintext stream less likely.

### 14.3 Genesis difficulty

| Network | Difficulty |
| --- | ---: |
| mainnet | 1,000 |
| testnet | 10 |
| regtest | 1 |

**These are final. The value goes into the genesis header, so changing it
changes the genesis hash and makes a different chain.**

#### Why it is set low

LWMA does not act while history is shorter than the window of 90 blocks
([§12.3](#123-the-bootstrap-period)). That is, **the first 90 blocks stay at the
genesis difficulty.**

- If it were too high, no block would appear right after launch. Lowering
  difficulty requires actual blocks, so **there is no way out under its own
  power**
- If it is too low, the first 90 blocks merely come out fast and LWMA then raises
  it. Emission is brought forward by at most 900 OAG (0.00009 % of total supply)

Only the "too low" side is recoverable, so it is set low.

#### Reference figures

These are the numbers used to decide the difficulty. **A physical core on real
hardware is faster than this.** They were measured in a virtualised environment
and are not an upper bound.

| Mode | Hashrate | Interval at difficulty 1,000 |
| --- | ---: | ---: |
| light (256 MB) | about 30 H/s | about 33 s |
| fast (2 GB) | about 160 H/s | about 6 s |

One core of an Intel Xeon at 2.8 GHz, virtualised. RandomX flags were
`FLAG_HARD_AES | FLAG_JIT | FLAG_ARGON2_AVX2`.

To measure locally:

```sh
cargo run --release -p oag-pow --features randomx --example hashrate
```

### 14.4 The genesis block

Genesis is the definition of the chain. A different hash is a different chain, so
**once fixed it cannot be changed.** It is fixed on all three networks.

#### Genesis has no PoW

Genesis PoW MUST NOT be verified. The RandomX seed is the block hash at the
height given by [`seed_height`](#113-seed-epochs), and at height 0 that would be
genesis's own hash. **You cannot compute your own hash from your own hash.** The
genesis nonce is therefore 0 and carries no meaning.

From block 1 onwards, verification proceeds normally with the genesis hash as the
seed.

#### mainnet

| | |
| --- | --- |
| Block hash | `7511b77a9fb2aac8d7ba4655ed372c6fc3fbf800e1872a5c907bb64a775f0c40` |
| Timestamp | 1,788,220,800 (2026-09-01T00:00:00Z) |
| Coinbase message | `Orange is good` |
| Coinbase txid | `016a04257821869f1704bd1ab084a1d14af360a901f1b5930ca21f306b6f0871` |
| Merkle root | `0dfcbab210f8f5997ccad4c2c3fea4af9a783692bd5e35f6f83eba0b41456fb2` |
| Coinbase output | 10 OAG burned (below) |
| Difficulty | 1,000 |
| nonce | 0 |
| Serialised length | 208 bytes |

#### testnet

| | |
| --- | --- |
| Block hash | `0862309e4cf48d928fad77bbb1ba799835d627e1fd79592395ea284529664bfa` |
| Timestamp | 1,788,220,800 (2026-09-01T00:00:00Z) |
| Coinbase message | `Orange is good` |
| Coinbase txid | `016a04257821869f1704bd1ab084a1d14af360a901f1b5930ca21f306b6f0871` |
| Merkle root | `0dfcbab210f8f5997ccad4c2c3fea4af9a783692bd5e35f6f83eba0b41456fb2` |
| Coinbase output | 10 OAG burned (below) |
| Difficulty | 10 |
| nonce | 0 |
| Serialised length | 208 bytes |

mainnet and testnet share an identical coinbase and **differ only in the
header's difficulty**, so their block hashes differ.

#### What happens to the block 0 reward

On mainnet and testnet, the 10 OAG of block 0 is **issued and then burned.**

```
output: 10 OAG → lock { version: 0, payload: 00×32 }
as an address: oag1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6v5r6p
               toag1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3rsa95
```

Thirty-two zero bytes is not a valid secp256k1 x-only public key (there is no
curve point for x = 0). An attempt to spend it fails while reading the public
key, before signature verification, and is rejected.

**Being version 0 is essential.** An unknown version is spendable by anyone
([§10.4](#104-handling-unknown-versions)), so landing there would not be a burn.

The difference from "not taking it" (having no output) is that **the fact of
issuance stays on the ledger.** One entry remains in the UTXO set, and the
explorer shows 10 OAG sitting at the burn address. That nobody took it is
visible. Against total supply it is 0.000001 %.

#### regtest

| | |
| --- | --- |
| Block hash | `c38b0b105c8557912d3be1eeb6a3c0aedfdefd2882200a8ef1484dd9cad874ba` |
| Timestamp | 1,767,225,600 (2026-01-01T00:00:00Z) |
| Coinbase message | `Orange regtest` |
| Coinbase output | none (reward forgone) |
| Difficulty | 1 |
| nonce | 0 |
| Serialised length | 165 bytes |

regtest alone was fixed before mainnet, hence the different values. It is a chain
anyone can recreate locally and there is no reason to align it, so it is left as
is.

#### Always put the timestamp in the past

A block's timestamp must be after the median time past
([§10.2](#102-block-validation)), so stamping a future value makes mining
impossible until that time arrives.

### 14.5 P2P protocol

**Implemented in-house.** rust-libp2p is not used.

A PoW chain's P2P requirements amount to "propagate blocks and transactions".
libp2p's DHT and its variety of transports are overkill, and the weight of the
dependency plus the cost of tracking its specification changes was judged to
outweigh the benefit.

Features implemented:

- handshake (`version` / `verack`)
- peer discovery (seed nodes + address exchange)
- block and transaction propagation via `inv` / `getdata`
  (see "Relay rules" below)
- **headers-first sync**
- **compact blocks** — see [§14.9](#149-compact-blocks). Required from v1

#### Advertised services

The `services` field of `version` states **what a node can serve**.

| Bit | Name | Meaning |
| --- | --- | --- |
| — (0) | `SERVICE_NONE` | Serves nothing; holds headers only |
| `1 << 0` | `SERVICE_FULL_NODE` | Serves every block **from genesis** |
| `1 << 1` | `SERVICE_LIMITED` | Serves only recent blocks (pruned node) |

**A node that cannot serve every block MUST NOT advertise
`SERVICE_FULL_NODE`.** How far back it can go is not part of the
advertisement; a node that lacks a requested block answers `notfound`
(see "When told it is not held" above).

##### `services` is undefined at protocol version 1

Nodes speaking protocol version 1 always sent this field as 0.

**No implementation other than the full node ever spoke version 1.** A peer at
version 1 MUST therefore be treated as `SERVICE_FULL_NODE` regardless of the
value it sent. This is not a guess: no light or pruned node was ever released
for that version.

A 0 from version 1 MUST NOT be read at face value as "serves nothing". Reading
it that way would reclassify every running full node as a light node. **An
advertised 0 and an unfilled 0 are distinguishable only by version.**

`services` carries meaning **from version 2 onward**.

##### An advertisement, not a guarantee

A peer can lie. Nothing in the protocol stops a node from advertising
`SERVICE_FULL_NODE` while serving nothing. The advertisement is **a hint for
choosing who to connect to**, not a basis for trust; a peer that does not
deliver is routed around by `notfound` and by the request timeout.

Advertisements heard second-hand SHOULD NOT be recorded. The `services` carried
in `addr` is hearsay about a third party and can be forged. **Only record what
was confirmed in your own handshake.**

#### The sync procedure

Headers-first. Collect headers to confirm the shape of the chain, then fetch
bodies. A header is 1/2000 the size of a body and is enough to verify PoW and
linkage. Collecting them first means **asking for bodies only once you know which
blocks you actually need.** Requesting bodies in sequence instead lets a peer
feed you irrelevant blocks indefinitely.

```text
1. getheaders (locator)   ──▶
2.                        ◀──  headers (up to 2000)
   validate the headers and put them in the index (no bodies yet)
3. getdata (the bodies needed) ──▶
4.                        ◀──  block
   validate the body and connect it to the active chain
```

Whoever mines a new block announces it with `inv`. The receiver **cannot tell the
height or the linkage from a hash alone**, so rather than asking for the body
directly it starts again from `getheaders`.

#### When told they do not have it, reassign immediately

If a peer answers `getdata` with `notfound`, that request **MUST be returned to
the queue immediately.** Do not wait for a timeout.

The peer that announced the tip with `inv` is not necessarily the peer you ask
for the body. Bodies are requested evenly across connected peers, so **hitting a
peer that does not have that block yet is unavoidable.** Since it is unavoidable,
a refusal must be reassignable immediately. Waiting for a timeout although the
answer has already arrived means that block can be requested from nobody
meanwhile. Blocks connect only in parent order, so what stalls is not just that
one: **however many successors you gather, none of them can be connected.**

Only a `notfound` **from the peer the request was sent to** requeues it (MUST).
Letting anyone's count means an unrelated peer can strip someone else's request
merely by sending `notfound`.

Transactions are not requeued. Since one attempt is the rule (below), requeueing
leaves nowhere to ask next.

#### Relay rules

**Validate before passing on (MUST).** What you received must not be flung
sideways as-is. Only what you validated yourself may be relayed.

| Subject | Condition to relay | Form |
| --- | --- | --- |
| Block | passed validation and **the active chain's tip moved** | `inv` |
| Transaction | accepted into the mempool | `inv` |

The object itself (`block` / `tx`) MUST NOT be pushed. Only the hash is
announced, and whoever needs it asks with `getdata`. Pushing lets you send peers
things they do not want.

**SHOULD NOT relay back to the peer it came from.** They already have it. It is
harmless but wastes a round trip.

Replacements ([§13.3.2](#1332-replacement-by-fee-rbf)) relay under the same
condition: if the mempool accepted it, announce the new txid with `inv`. **There
is no way to announce that the evicted txid is "gone".** Each node either reaches
the same conclusion on its own or does not. This is not information that can be
transmitted, and it is one of the grounds for the rule that a zero-confirmation
transaction must not be accepted as payment.

A block that did not move the tip (a branch with less work) is not relayed.
**Nothing is lost by not relaying it.** If that branch later becomes longest, the
new block at that time moves the tip and it can be traced from there with
`getheaders`.

#### Propagation MUST NOT have a TTL

A flooding network must not cap the number of hops. Nodes beyond the cap never
receive the block, which is **a permanent chain split.** The network's diameter
is unknown and changes as nodes come and go, so no correct value can be chosen.
Convergence is decided by cumulative work, not by a hop budget.

Propagation stops because of **state**. A block you already have does not move
the tip, so it is not relayed. A transaction already in the mempool is not
accepted, so it is not relayed. The wave dies where it meets a node that already
knows.

Replacement works the same way. A node that has already applied a replacement
does not accept the same one again (`AlreadyKnown`). Keep raising the fee and you
can start a wave as often as you like, but you pay rule 4's increment each time.
**The price stands in for a hop cap.**

What prevents endless circulation is not a TTL but each of the following.

| What is bounded | Means |
| --- | --- |
| The same thing circulating | duplicates are not relayed (above) |
| Unrequested objects arriving | the pull model: `inv` → `getdata` |
| Items per message | 5,000 for `inv` / `getdata`, 2,000 for `headers` |
| Size of one message | 1 MiB ([§14.7](#147-message-framing)) |
| Outstanding requests | 16 blocks, 32 transactions (per peer) |

#### An unrequested transaction MUST NOT be validated

On receiving a `tx`, **first check whether that txid was requested from that
peer.** If it was not, discard it without looking at the contents.

Signature verification is expensive. If anyone can push a `tx` at you, a peer
that merely connected can spend as much of your CPU as it likes. Only what was
announced with `inv` and requested with `getdata` is verified.

The record of a request is **single-use**: it is cleared on receipt. If the same
peer sends the same thing repeatedly, the second message onwards does not pass.

A request that timed out is **forgotten and SHOULD NOT be retried.** A missing
block blocks everything after it, so blocks are retried; transactions have no
such constraint. When a peer announces a flood of non-existent txids, a retrying
design chases the same lie from peer to peer.

#### What to do when something is not accepted

| Subject | If validation fails |
| --- | --- |
| Block | **disconnect (MUST)** |
| Transaction | discard. MUST NOT disconnect |

Block validation rules are consensus. A peer that sends blocks that fail either
follows different rules or is malicious. Either way there is no point staying
connected.

There are many harmless reasons for a transaction not to be accepted: the fee is
below our policy, we already hold something else spending the same UTXO, and so
on (the policy layer of [§13](#13-fee-policy)). **Disconnecting over a policy
difference splits the network along policy lines.**

#### The three states of a block

Each block in the index is in one of the following states
([§10.2](#102-block-validation)).

| State | Meaning | Eligible as a tip? |
| --- | --- | --- |
| Header only | header and PoW verified; no body | no |
| Header valid | the body is present but has not been connected | yes |
| Fully valid | the body was validated and has been connected | yes |
| Invalid | validation failed; all descendants are invalid too | no |

Before switching the tip, confirm that **every block on the path back to where it
joins the active chain has its body.** Fetches are spread across peers, so bodies
can arrive out of order. Advancing with a gap in the middle would update the UTXO
set while skipping an unvalidated block.

### 14.6 Peer discovery

#### Seed nodes

| Network | Hostname |
| --- | --- |
| mainnet | `seed.oagcoin.org` |
| testnet | `testnet-seed.oagcoin.org` |
| regtest | none |

Resolving the hostname returns the IPs of running nodes in A / AAAA records. The
port is that network's default (DNS cannot carry a port).

**The seed MUST be queried only when the address book holds no candidates and
there is not a single outbound connection.** Once connected, nodes tell each
other addresses, so the seed is not needed. An existing network therefore does
not die when the seed goes down; only nodes trying to join are affected.

The seed's answer is not trusted. DNS travels in plaintext and can be rewritten
in transit. Addresses obtained from the seed MUST be treated the same as
addresses heard from any other peer.

No seed is provided for regtest. It is for local experimentation, not a public
network.

#### The address book

Learned addresses are kept in `peers.json` in the data directory. The structure
is the same **two-table** design as Bitcoin's `addrman`.

| Table | Contents | Buckets | Per bucket | Total |
| --- | --- | ---: | ---: | ---: |
| `new` | addresses merely heard about | 1,024 | 64 | 65,536 |
| `tried` | addresses actually connected to | 256 | 64 | 16,384 |

| | |
| --- | ---: |
| `new` buckets one source (/16) can touch | 64 |
| `tried` buckets one /16 can touch | 8 |
| Slots one address can occupy in `new` | 8 |
| Addresses accepted from one `addr` | 256 |
| Addresses returned to `getaddr` | 256 |
| Time until an address stops being handed out | 30 days |
| Retry interval | from 1 minute, doubling, capped at 6 hours |

The address book is **storage whose contents a peer decides.** Addresses sent in
`addr` are stored, so an attacker can inject whatever it likes. The goal is an
eclipse attack: fill the address book with its own nodes so the victim never
connects to an honest one, letting the attacker choose the chain it sees.

##### Promotion from `new` to `tried` MUST require a successful connection

Merely sending `addr` does not get you into `tried`. This is the keystone of the
two-table design.

##### Outbound connections MUST be drawn half from `new` and half from `tried`

**Even if `new` belongs entirely to an attacker, half the outbound connections go
to peers with a track record.** That single fact is what makes flooding
ineffective.

##### Buckets MUST be decided together with a per-node secret key

Buckets must not be decided from the address alone. If they could be, an attacker
would prepare addresses that fill a targeted bucket. The key MUST be stored
alongside the address book. **It MUST NOT change at every start.** Changing it
scatters every address into different buckets each time, and the tables lose
their meaning.

The structure itself bounds how many slots an attacker can occupy.

| Table | Grouped by | Buckets touched | Share of the whole |
| --- | --- | ---: | ---: |
| `new` | the /16 of the **peer that told us** | 64 / 1,024 | 6.25 % |
| `tried` | the /16 of the **address itself** | 8 / 256 | 3.1 % |

The premise is that **preparing many distinct networks is far more expensive**
than preparing many addresses.

##### Other rules

- **A healthy incumbent MUST NOT be evicted.** When a slot is taken, only an
  address with no prospects may be displaced. It must not be possible to churn
  the tables merely by lining up reachable nodes. If the `tried` destination is
  occupied and the incumbent is healthy, the address **is not promoted** and
  stays in `new`
- **A connected address MUST NOT depend on free space in `new`.** An address we
  actually connected to goes into `tried` even if no slot is available in `new`.
  `new` is where **untried** addresses live, and there is no reason for a peer we
  connected to to compete for a slot there. Requiring it would mean **filling
  `new` with announced addresses is enough to block honest peers from reaching
  `tried`.** The point of two tables is to account for proven peers separately;
  if filling one can block the path to the other, the separation is pointless.
  The rule above about healthy incumbents is unchanged: if the `tried`
  destination is occupied and the incumbent is healthy, do not admit it, and
  leave no entry belonging to neither table
- **Only `tried` addresses MUST be handed out.** Handing out addresses merely
  heard about means endorsing and spreading them. Bitcoin also hands out from
  `new`; this implementation does not. As a result, the address of a brand-new
  node nobody has connected to stops after one hop. **It does not stay stopped.**
  The node that heard it also dials from `new` half the time, so once it connects
  the address rises to `tried` and starts being handed out
- **Timestamps in the future MUST NOT be accepted.** The give-up test looks at
  age, so allowing them lets addresses claiming the future sit forever
- **Addresses unreachable on the public internet MUST NOT be stored**
  (loopback, private, CGNAT, link-local, documentation ranges). regtest allows
  them so two nodes can be connected locally
- **IPv4-mapped addresses MUST be judged as IPv4 and share grouping and buckets
  with IPv4.** Holding them twice lets one peer take two slots

##### When to give up on an address

Any of the following means the prospects are exhausted, and such an address is
the first to yield when a slot is needed (the same as Bitcoin's `IsTerrible`).

- more than 30 days since it was last seen
- three consecutive failures without ever having connected
- more than 7 days since the last successful connection, plus 10 consecutive
  failures

But **an address dialled within the last minute is not given up on.** Discarding
it before the result is in would instantly erase the peer just dialled.

#### Maintaining connections

Eight outbound connections are kept. The address book returns only one candidate
per /16, so that count is also **the number of distinct networks.**

**Inbound connections MUST NOT count toward it.** If they did, connecting to you
would be enough to stop your outbound connections.

#### How addresses spread

1. Send `getaddr` to peers you dialled. **Do not send it on inbound
   connections** (collecting addresses over connections anyone can open makes it
   easy for an attacker to be the one asked)
2. Answer `getaddr` **only once per connection (MUST)**. Answering repeatedly
   turns it into a tool for siphoning the entire address book
3. Newly confirmed reachable addresses are relayed to connected peers with
   `addr`. Addresses learned later travel by this path
4. Your own address is announced only when the operator states it. **There is no
   reliable way for a node to determine its own external address**

### 14.7 Message framing

```
magic     [4]   network identifier
command  [12]   command name, lowercase ASCII, NUL-padded
length    [4]   payload length (u32 LE)
checksum  [4]   BLAKE3(payload)[0..4]
payload  [length]
```

The prefix is 24 bytes.

#### The length MUST be checked before reading

If the declared payload length exceeds the limit, **disconnect without reading a
single byte of payload.** This prevents an attack that exhausts memory by
inflating only the length while keeping the connection open.

```
payload length limit   1 MiB
```

Both the largest block (200,000 bytes) and a fully packed `inv`
(5,000 items × 33 bytes = 165,000 bytes) fit with room to spare.

#### Item limits

| Message | Limit |
| --- | ---: |
| `inv` / `getdata` / `notfound` | 5,000 items |
| `headers` | 2,000 |
| `addr` | 1,000 |
| `getheaders` locator | 64 |
| User agent | 64 bytes |

### 14.8 Handshake

```
us ──version──▶ them
us ◀──version── them
us ──verack───▶ them
us ◀──verack─── them
```

Ordinary traffic begins only once both directions are complete. **Receiving a
substantive message before completion MUST disconnect** — so blocks are not
handed to a peer that has not identified itself.

The random value in `version` is used to detect self-connection. If a peer's
`version` carries the same value as ours, the connection is to ourselves.

### 14.9 Compact blocks

Rather than sending a whole block, **do not send what the peer already has.**

```
cmpctblock
  header        100 bytes
  nonce           8 bytes
  short IDs       6 bytes × (tx count − number embedded)
  embedded txs    the coinbase is always included, as the peer cannot have it
```

The receiver picks matching short IDs out of its mempool and asks for the
remainder by index with `getblocktxn`.

#### Measured

Measured values from the tests in `crates/oag-net/src/compact.rs`.

| Transactions in the block | `block` | `cmpctblock` | Ratio |
| ---: | ---: | ---: | ---: |
| 10 | 1,710 B | 270 B | 6 |
| 100 | 15,300 B | 810 B | 19 |
| 500 | 75,701 B | 3,211 B | 24 |
| **1,000** | **151,201 B** | **6,211 B** | **24** |

On a 10 Mbps link, sending out a 1,000-transaction block goes from **121 ms to
5 ms**.

#### Why this matters at a 60-second interval

The longer propagation takes, the higher the probability that blocks at the same
height are mined in parallel (the orphan rate). A high orphan rate favours large,
well-connected miners and drives centralisation. As seen in
[§7.2](#72-size-of-a-standard-transaction), this chain pushes 200,000 bytes every
60 seconds, and without compact blocks the orphan rate reaches 2–3 %.

#### Short ID collisions

A short ID is only 6 bytes, so it can coincide with an unrelated transaction in
the mempool. The reconstructed block would then be **the wrong block.**

**The merkle root MUST be verified at the end of reconstruction.** On a mismatch,
discard it and ask for a normal `block` instead. This catches both collisions and
a peer returning the wrong transactions.

The short-ID key changes per block.

```
key      = BLAKE3("OAG/cmpct/shortid" || header || nonce)
short_id = BLAKE3_keyed(key, txid)[0..6]
```

With a fixed key, an attacker could prepare colliding transactions in advance and
disrupt every node at once. Changing it per block prevents that.

### 14.10 Storage

**redb** (a pure-Rust embedded ACID database) is used.

rocksdb has a better track record but depends on C++, which complicates
cross-compilation. At the scale of this UTXO set, redb's performance was judged
sufficient.

---
## 15. RPC

This is the interface exchanges and block explorers connect to. It is
**JSON-RPC 2.0 over HTTP** — the same shape as bitcoind, and therefore the most
widely understood.

### 15.1 Shutting it off

| | Default |
| --- | --- |
| Bind address | **loopback only** (127.0.0.1) |
| Authentication | required, HTTP Basic |
| Cookie | generated at every start and written to `.cookie` in the data directory |
| `.cookie` permissions | owner read/write only (0600) |

Losses of funds from exposing RPC publicly have happened in several projects.
**The defaults prevent it** ([§14.1](#141-ports)).

The cookie is regenerated at every start. Putting it in a configuration file
means that file gets copied, committed to history and shared. Making it
disposable means a leak is void at the next start.

### 15.2 What is accepted as HTTP

All that is needed is "one JSON body to `POST /`". **Keeping the accepted surface
narrow is itself a defence.**

- Method `POST` and path `/` only
- `Content-Length` is required; `Transfer-Encoding` is refused (leaving the end
  of the body to the sender lets them send forever)
- The declared length is checked **before reading**
- Headers up to 8 KiB, body up to 4 MiB
- Authentication is checked **before invoking the method**
- Comparing the cookie **must take time independent of the contents.** A naive
  comparison stops at the first difference, so trying one byte at a time and
  timing the response lets an attacker recover it from the front

### 15.3 Methods

| Name | Arguments | Returns |
| --- | --- | --- |
| `getinfo` | none | network, height, tip, difficulty and so on |
| `getblockcount` | none | the active chain's height |
| `getbestblockhash` | none | the tip's block hash |
| `getblockhash` | `[height]` | the block hash at that height |
| `getblockheader` | `[hash]` | header contents and validation state |
| `getblock` | `[hash, verbose=true]` | the block; hex if `false` |
| `getrawtransaction` | `[txid, verbose=false]` | the transaction; mempool only without an index |
| `getaddresshistory` | `[address, start=0, count=100]` | transactions touching that address |
| `getindexinfo` | none | whether an index is present |
| `getmempool` | none | the list of txids in the mempool |
| `sendrawtransaction` | `[hex]` | the accepted txid |
| `scanutxos` | `[[address, …]]` | matching UTXOs and their total |

Amounts are `u128` and cannot be expressed by a JSON number. They are returned as
**decimal strings in atomic units.** Cumulative work likewise.

#### Methods that require an index

`getaddresshistory`, and `getrawtransaction` looking up a confirmed transaction,
**depend on the optional index** (→ [settled items in §19](#settled-items)). They
are unavailable on a node without one.

**In that case return an error, not an empty answer.** Answering "not found"
makes the caller read it as "that transaction does not exist". Not having it and
it not existing are different, and the distinction must not be erased. Whether an
index is present is discoverable via `getindexinfo`.

To look up a confirmed transaction without an index, fetch the block containing
it with `getblock` and search within it.

#### `scanutxos` is a full scan

There is no index from spending condition to UTXO either. The wallet reads the
whole UTXO set and picks out its own. This is the same approach as bitcoind's
`scantxoutset`.

The scan is bounded, and on reaching the bound it returns `truncated: true`.
**The caller must look at this.** Displaying the total as a balance without
checking would understate it.

### 15.4 The explorer

A separate, **read-only** HTTP service for browsing the chain. It listens on
`127.0.0.1:8080` by default.

#### Do not reuse the RPC interface

The interface in [§15.2](#152-what-is-accepted-as-http) accepts only "one JSON
body to `POST /`, with a cookie". **That narrowness is exactly that layer's
safety.** Widening it to allow `GET` and arbitrary paths would weaken the shape
of the entrance that can move funds.

The explorer only reads and has no path that changes state. Keeping it as a
separate interface means loosening one does not loosen the other.

#### What is accepted

- Verbs `GET` and `HEAD` only; everything else is refused
- Paths `/`, `/block/<height|hash>`, `/tx/<txid>`, `/address/<address>`,
  `/mempool`, `/search?q=`
- Request headers up to 8 KB; one request per connection

**Both paths and queries are strings the user chooses.** Every value embedded in
a page is escaped. Even for something run locally, failing to escape creates an
entrance for injecting arbitrary script.

#### Do not go silent when there is no index

Transaction and address lookups depend on the index ([§19](#settled-items)). On a
node without one, **display "not held" rather than an empty history.** An empty
view is read by the user as "there are no transactions". Browsing blocks works
without an index.

#### List history oldest-first

Address history is listed oldest-first. The index's keys are ordered by height,
so reading in that order is cheapest, and paging is just reading onwards.
Ordering newest-first requires counting everything, and doing so while hiding
that the count was truncated is dangerous.

#### Do not decode bodies to build a list

The "recent blocks" list at the front needs only height, time, transaction count,
size, difficulty and hash per row. Time and difficulty are in the block index's
header, size is the length of the stored record itself, and the transaction count
is a single varint right after the header. **None of it requires constructing the
block body.**

Decoding the body would allocate every transaction, including those never shown.
A full block ([§10](#10-consensus-rules), 200,000 bytes) can hold about 670
transactions, so drawing 25 rows would allocate and immediately discard over
16,000. Worse, that work happens inside the node's own work queue, so **for its
duration the node is handling neither blocks nor peers.**

The list is also built in **a single read transaction.** Querying per height
makes the snapshot differ row by row, so a block arriving mid-render shows the
upper and lower rows at different points in time.

#### Page long lists

Transactions within a block are paged at the same width as address history.
Dumping a full block on one page is 670 rows. The number shown is the **index
within the block**. Renumbering per page would disagree with the position the
index points at ([§19](#settled-items)).

Paging links point at a block hash, not a height. Linking by height means that
while viewing a side-chain block, "next" jumps to **a different block** at the
same height on the active chain.

---

## 16. Wallet

### 16.1 Relationship with the node

The wallet talks to the node **over JSON-RPC only**. It holds no chain state, and
**private keys never reach the node.** Signing finishes on the wallet side, and
only the finished product is submitted with `sendrawtransaction`.

### 16.2 Key storage

**One seed, encrypted under a passphrase.**

| Measure | What it protects against |
| --- | --- |
| Argon2id (m=128 MiB, t=4, p=1) | brute force; makes even purpose-built hardware uneconomic |
| ChaCha20-Poly1305 | reading the contents; also detects tampering |
| File mode 0600 | other users on the same machine |
| Zeroing on exit | residue in memory and swap |

The salt and nonce are **regenerated on every save.** Encrypting twice with the
same key and nonce reuses the keystream and leaks the difference between the
plaintexts.

#### Raise memory before iterations

For the same increase in elapsed time, doubling `m_cost` is stronger than
doubling `t_cost`. What Argon2 forces on an attacker is **the amount of memory
that must be provisioned in parallel**, and raising the iteration count does not
reduce how many can be run side by side. Argon2's own guidance is likewise
"memory first, then iterations".

The ceiling on `m_cost` is set by browsers (§16.9). There is no point in a record
that cannot be opened on a phone, so it stays within what a phone's wasm can
allocate.

#### Derivation parameters MUST be stored with the record

Decryption derives with **the values that were written at the time.** Deriving
with the current defaults means old records stop opening the moment the defaults
change. **A record that will not open is indistinguishable from lost funds.**

Because of this, the defaults may be raised later. Raising them keeps old records
openable.

Fields kept outside the ciphertext (network, address count) are **included in the
associated data.** Without that, tampering with them still decrypts
successfully — lower the address count and addresses you ought to have stop
appearing.

The file is **written out under a different name and then renamed.** Overwriting
means "truncate, then write", and losing power right after the truncation leaves
an empty wallet. **Lose the seed and the funds are unrecoverable.**

Permissions are checked on load, and a file readable by anyone but the owner is
refused. A wrong passphrase and tampering are **refused without distinction.**
Being able to distinguish them gives an attacker a signal to probe with modified
files.

#### What it cannot protect against

- **A weak passphrase.** Argon2id only raises the cost of brute force; it does
  not make a guessable phrase strong. Fewer than 8 characters is refused
- Anyone who can read the running process's memory. The decrypted seed is there
  while it is in use
- Zeroing a private key is not "secure erasure". It may be optimised away, and
  copies made along the way may remain

### 16.3 Seed and key derivation

The recovery phrase is **12 BIP39 words.** From it, BIP39's 64-byte seed is
produced, and BIP32 follows the BIP44 path ([§6.6](#66-hd-wallets)).

```
recovery phrase (12 words)
    │  PBKDF2-HMAC-SHA512, 2048 rounds, salt = "mnemonic" ‖ optional passphrase
    ▼
seed (64 bytes)
    │  BIP32
    ▼
m / 44' / <coin_type>' / 0' / 0 / <index>
```

#### One phrase is enough

In a scheme that creates keys one at a time and lists them, **the backup goes
stale every time you add an address.** Restoring from an old backup afterwards
leaves the funds on the new addresses invisible. Deriving from a seed means the
same phrase restores however many you add later.

#### What is stored

The wallet file's ciphertext holds **the entropy as well as the seed.** The seed
alone cannot be turned back into words: BIP39's seed is the output of PBKDF2 and
is one-way. Both are kept so the phrase can be displayed again.

#### No migration path is provided

Version 1 wallets (a plaintext list of keys) and version 2 wallets (a 32-byte
seed with a bespoke derivation) **are not read.** No automatic conversion is
provided, because it would prolong the period in which an "old phrase" and a "new
phrase" coexist. A pre-migration wallet exports its private keys and pays the
funds into a new wallet. This is done before the public testnet, while there are
no funds to protect.

### 16.4 How the passphrase is obtained

**Never from a command-line argument.** Arguments are visible to other users on
the machine via the process list, and they persist in shell history.

With a terminal, it is asked for with echo off; otherwise it is read from
standard input. It can also be read from a file (`--passphrase-file`).

### 16.5 Deciding the fee

The fee is proportional to size, size is determined by the number of inputs, and
the number of inputs is determined by the amount needed (payment + fee). **It is
circular.**

So inputs are added one at a time and the transaction is **actually built and
measured.** Because the real size is used rather than an estimate, it never falls
below the rate. A BIP340 signature is fixed at 64 bytes, so adding signatures does
not change the size and it can be measured exactly before signing
([§5](#5-cryptographic-primitives)).

The change amount is not yet decided, but the encoded length of an amount varies
with its value ([§7](#7-transactions)). The largest possible value is assumed for
the measurement. The real change can only shrink it, never overflow it, and the
difference is a few bytes.

### 16.6 What the wallet refuses

| Refused | Reason |
| --- | --- |
| Paying an address of an unknown version | it becomes anyone-can-spend ([§10.4](#104-handling-unknown-versions)); paying before activation loses the funds |
| A payment below the dust threshold | it will not be relayed |
| A build whose change would be dust | dust stays in the UTXO set forever and nobody collects it; it goes to the fee instead |
| Signing an input whose key is absent | sending a partially signed transaction loses the fee without moving the funds (use [§16.8](#168-partially-signed-transactions-pst) to collect signatures) |
| Showing a balance from a truncated scan | it would understate the balance |
| A passphrase shorter than 8 characters | encrypted but unprotected |
| Overwriting an existing wallet | it permanently loses the funds the seed there protected |
| Loading a version 1 wallet (plaintext key list) | it would let plaintext keys stay in use |
| Consolidating with one or fewer candidates | it would only pay a fee to rebuild the same shape |

### 16.7 Consolidating UTXOs

Mining adds **one UTXO per block**, because a coinbase has a single output. Left
alone, you hit the `scanutxos` bound ([§15.3](#153-methods), 10,000 entries), at
which point the wallet refuses both to display a balance and to send. A balance
from a truncated scan understates the real one, and showing it is worse than
failing loudly ([§16.6](#166-what-the-wallet-refuses)).

At a 60-second interval, **10,000 blocks is about 7 days.** Anyone who keeps
mining will get there.

#### It is a different build from a payment

A payment starts from "how much to send" and picks UTXOs to cover it.
Consolidation is the reverse: **the UTXOs are chosen first, and the result is
everything collected minus the fee.** There is exactly one output and no change.
Because no amount is specified, it never creates the non-existent shape of a
zero-value payment.

#### One pass is not enough

`MAX_TX_SIZE` ([§10](#10-consensus-rules), 100,000 bytes) is a consensus-side
limit. One input is roughly 102 bytes, so **about 980 fit in one transaction.**
Anything beyond that waits for the next pass. How many did not fit is reported
**separately** from how many are waiting to mature. The former is cleared by
running again after confirmation; the latter can only be waited out. Mixing them
leaves the user unsure which they are waiting for.

Smallest first. The total is the same whichever are left behind, but a smaller
output carries a higher fee relative to its own size, so folding it earlier pays.

#### Do not refuse to consolidate just because the bound was hit

A balance cannot be stated without seeing everything. It comes out short by
whatever was not added, so claiming a balance from a truncated scan is a lie.
That is why balances are refused
([§16.6](#166-what-the-wallet-refuses)).

**Consolidation is different.** Folding does not require everything. If some of
your holdings come back, they can be made into one. Indeed, hitting the bound is
exactly when consolidation is needed, and refusing there would mean **the tool
for getting out is unusable precisely in the state you need to get out of.**

The set that comes back is not "the most recent N". A UTXO's key is
`txid ++ output index`, and a txid is a hash, so the ordering is effectively
arbitrary. It is **an arbitrary N of your holdings**, which is quite enough to
fold. Each pass reduces holdings by (folded count − 1), so repeating brings you
under the bound.

When the scan was truncated, do not say "everything has been folded". There are
still holdings you have not seen.

#### Do not count outputs used by unconfirmed transactions

`scanutxos` reads the UTXO set, so **outputs used by a sent but unconfirmed
transaction still answer "present".** Building on that produces a transaction
spending the same outputs as the previous consolidation, which is treated as a
replacement offer and refused. No money is lost, but it is impossible to tell why
running it twice behaved that way. Exclude outputs used by mempool transactions
first.

### 16.8 Partially signed transactions (PST)

The equivalent of Bitcoin's PSBT (BIP174): a format for carrying an unsigned
transaction **together with everything signing requires.**

#### Why a raw transaction is not enough

The signing target (sighash) includes the **amount and spending condition** of
every output the transaction spends
([§8.2](#82-committing-to-every-input-amount)). A raw transaction carries only
the reference (`OutPoint`) — neither the amount nor the condition. The signer
would therefore have to consult the chain, and a machine holding only keys could
not sign.

#### Format

```
PST {
    magic        [6]  = "oagpst"
    version      u8   = 1
    unsigned_tx  Transaction    // every input's signature MUST be empty
    input_count  varint         // MUST match unsigned_tx.inputs
    inputs       PstInput[]
    output_count varint         // MUST match unsigned_tx.outputs
    outputs      PstOutput[]
}

PstInput {
    utxo        TxOutput        // the output this input spends: amount and condition
    sighash     u8              // sighash type
    signature   var_bytes       // length 0 means unsigned
    derivation  Option<Derivation>
}

PstOutput {
    derivation  Option<Derivation>   // to confirm the change is ours
}

Derivation { account: varint, change: varint, index: varint }
```

`Derivation` carries the last three components of
`m/44'/<coin_type>'/<account>'/<change>/<index>` — the ones the wallet chooses
([§6.6](#66-hd-wallets)). `purpose` and `coin_type` are fixed by the
specification and there is no point carrying them.

**`derivation` is a hint, not evidence.** The signer MUST verify that the key
derived by that path really matches the spending condition.

#### Roles

The same division as BIP174.

| Role | What it does |
| --- | --- |
| Creator | builds the unsigned transaction and attaches the outputs it spends |
| Signer | signs **only the inputs it can sign** |
| Combiner | merges separately signed copies into one |
| Finalizer | extracts the transaction once everything is present |

#### What to uphold

- **On decoding, a `unsigned_tx` that carries signatures MUST be rejected.**
  If it did, the transaction being displayed and the signing target would diverge
- **When combining, verify both that `unsigned_tx` is identical and that the
  attached outputs match (MUST).** The attached outputs are not part of the
  transaction, so they can disagree even when the txid is the same. A different
  amount means a different sighash
- **When finalizing, verify every signature before returning (MUST).** The
  combiner may be broken, or malicious. If it is not caught here, you find out
  only after broadcasting
- **An existing signature MUST NOT be overwritten.** It is someone else's share
- **The fee SHOULD be shown before signing**

#### `unsigned_tx`'s txid is not the final txid

This chain's txid is the hash of the whole transaction encoding, **signatures
included** ([§5.3](#53-signatures-schnorr-bip340)). Adding signatures changes the
txid. The txid of the `unsigned_tx` inside a PST is for checking "is this the
same transaction", not a number to give to the recipient.

BIP340 nonce generation mixes in auxiliary randomness, so signing the same target
with the same key produces different bytes each time. **The final txid is decided
only after finalizing.** That a third party cannot alter it is unchanged.

#### The lying-about-amounts attack does not work

PSBT has a class of attack where an input amount is misrepresented so that the
signer pays an outrageous fee. **It does not work here.** Because the sighash
includes every input amount
([§8.2](#82-committing-to-every-input-amount)), a signature made over a false
amount does not verify against the real one. You do not lose money; you simply
get an invalid transaction.

This is one of the reasons §8.2 exists.

### 16.9 The browser wallet

With `--wallet`, the node opens an interface serving a wallet to the browser. The
default is `127.0.0.1:25565`.

#### Keys MUST NOT pass through the node

**Signing finishes inside the browser.** Neither the seed nor any private key may
be sent to the node. The interface accepts only signed transactions.

The node offers exactly four things.

| Endpoint | What it does |
| --- | --- |
| `/api/info` | report height and network |
| `/api/scan` | count unspent outputs for the addresses given |
| `/api/history` | read history for the addresses given |
| `/api/send` | pass a signed transaction to the mempool |

Every one is **something anyone can already do over P2P.** The right to broadcast
belongs to everyone and the chain's contents are public. Opening these does not
widen what the node can do. **No endpoint that touches keys or changes settings
MUST be added.**

#### The implementation MUST NOT be duplicated

The browser side loads `oag-wallet` compiled to wasm. Key derivation, record
encryption and sighash computation run **the same code as the CLI.**

Nothing cryptographic may be rewritten in JavaScript. With two implementations,
one day they disagree — and what lies past the disagreement is funds that cannot
be signed for.

The record format is the same, so a wallet made in the CLI opens in the browser
and vice versa.

#### Nothing MUST be pulled in from outside

The wasm served has **no imports.** The browser runs it with
`WebAssembly.instantiate(bytes, {})` alone.

This is to avoid depending on external tooling such as `wasm-bindgen`. A state
where the tool's version must match the crate's version to build at all leads to
**shipping something nobody can rebuild.** Being rebuildable with `cargo build`
alone is preserved.

Randomness is the one thing wasm has no source for. Thirty-two bytes from
`crypto.getRandomValues` are handed in at startup, and from then on output is
drawn from a BLAKE3 XOF keyed with them. **A record MUST NOT be created before
the seed is supplied**, or the salt and nonce become predictable.

The page, the JS and the wasm are all self-contained within what this interface
serves. `Content-Security-Policy` restricts load sources to itself.

#### It MUST NOT share an interface with the explorer

Browser storage is partitioned per `scheme + host + port`. **A separate interface
means a separate partition.** Even with an injection hole on the explorer side,
the encrypted record cannot be read from there.

Sharing one interface erases that partition. The explorer embeds transaction IDs
and addresses into pages, and no one can guarantee forever that there is no hole
there.

#### It MUST NOT be served externally in plaintext

Even over a plaintext channel, **the signature protects the contents.** The
recipient and the amount are both covered, so neither can be rewritten in
transit. They can only be suppressed.

What cannot be protected is **the channel that delivers the page.** The signing
code is sent to the browser every time. Replace it and the seed can be lifted
while everything looks the same.

Listening on anything but loopback therefore requires a certificate. Without one,
**startup is refused.** For local experimentation plaintext is fine.

#### Storage is not a backup

The encrypted record goes in localStorage. But that is **a cache, not a backup.**
It disappears if the origin changes, and some engines clear it simply because you
have not visited for a while.

So immediately after creation, **do not let the user proceed until they have
written down the recovery phrase.** Even if the record vanishes, the words bring
it back.

#### Restoring from a phrase MUST NOT look only at unspent outputs

A recovery phrase does not record how many addresses were handed out. Finding out
means deriving addresses at indices not yet claimed and asking the chain.

At that point, **unspent outputs alone MUST NOT be consulted.** An address that
received and then spent everything has no unspent outputs, so stopping the search
there misses the funds beyond it. **Evidence of use is found in the history**
(which needs the index of §15).

The path is the single line `m/44'/1033'/0'/0/<index>`; neither accounts nor a
change branch fork off (§16.3). Only the index is scanned. While the number can
still change (the SLIP-0044 item in §16.3), **hold the path as an array.**
`/api/scan` takes an array of addresses, so the old and new paths can be mixed
into one call.

---

## 17. Interoperability and DEXs

### 17.1 Premises

This chain has two properties.

1. **There is exactly one asset, OAG.** There is no token issuance.
2. **There is no script language.** Conditional payments cannot be expressed
   directly.

Therefore:

| Kind | Possible? |
| --- | :---: |
| Cross-chain atomic swaps (OAG ↔ BTC / LTC / XMR, …) | **yes** |
| P2P swap markets (order book off-chain, settlement by swap) | **yes** |
| Bridging to another chain and trading on an existing DEX | **yes** (needs a bridge operator) |
| An order-book DEX within this chain | **no** (there is no counter-asset) |
| An AMM-style DEX (Uniswap and the like) | **no** (no execution environment) |
| Lending / derivatives | **no** (as above) |

### 17.2 Atomic swaps with adaptor signatures

Thanks to the linearity of Schnorr signatures, cross-chain atomic swaps can be
constructed **without using any script at all.**

```
1. Both parties build a 2-of-2 aggregate key with MuSig2 and send funds to it
   → on-chain it is indistinguishable from an ordinary single-signature payment

2. Before sending funds, they pre-sign refund transactions with a locktime
   for each other
   → if the counterparty walks away, the funds are recoverable after the timeout

3. When the signature is published on one chain, the adaptor-signature property
   lets a secret value be recovered from it, unlocking the funds on the other
```

**Advantages over HTLCs**:

- requires no script (the only scheme realisable on this chain)
- no identical hash value is stamped on both chains, so an outside observer
  cannot tell the two transactions are related
- the same size and the same shape as an ordinary payment

**Protocol requirements** (all already in this specification):

| Requirement | Where |
| --- | --- |
| BIP340 Schnorr signatures | [5.3](#53-signatures-schnorr-bip340) |
| Transaction ID non-malleability | [5.3](#53-signatures-schnorr-bip340) |
| Absolute locktime | [7.4](#74-locktime) |
| Relative locktime semantics | [7.5](#75-sequence-relative-locktime) |
| Sighash flags | [8.3](#83-sighash-flags) |

MuSig2 and adaptor signatures are **entirely wallet-layer technology** and
require no consensus change. They are therefore not implemented in v1 and can be
added later as a wallet feature.

### 17.3 Room for future extension

The path for more advanced trading features is reserved as address-version space
([6.3](#63-address-versions)).

```
version 1 →  hashlock + timelock (HTLC-style output)
version 2 →  script hash
```

These can be added as soft forks. Old nodes treat an output of an unknown version
as **anyone-can-spend at the consensus layer**, so even when new nodes impose a
condition on that version, blocks produced by new nodes remain valid to old ones
([§10.4](#104-handling-unknown-versions)). Nothing may be paid to that version
before activation, and old nodes refusing to relay it as non-standard is a policy
to reduce that danger, not a consensus rule.

**Realising an AMM requires an execution environment for arbitrary computation,
and that is a different design beyond the scope of this specification.**

---
## 18. Record of design decisions

The main choices and the reasons for them.

| Decision | Choice | Reason |
| --- | --- | --- |
| Consensus | PoW (RandomX) | fair distribution via CPU mining; ASIC resistance |
| Language | Rust | no GC, so block-validation latency is deterministic. The type system suits a consensus state machine. RandomX FFI is lighter than cgo. Tari as precedent |
| Accounting model | UTXO | simple validation; easy to parallelise |
| Signature curve | secp256k1 | libsecp256k1's track record; hardware wallet support; BIP32 non-hardened derivation available |
| Signature scheme | Schnorr (BIP340) | non-malleable; fixed 64 bytes; batch verification; MuSig2 and adaptor signatures available |
| General hash | BLAKE3 | fast; the reference implementation is Rust; length-extension resistant, so no double hashing |
| Amount type | u128 | 10^25 atomic does not fit in u64 |
| Decimal places | 16 | — |
| Emission curve | linear, no halving | simple to implement with no room for off-by-one. No hashrate cliff at a halving. Mining opportunity stays open to newcomers for a long time |
| Initial distribution | none | the core of the fair-distribution goal |
| Timestamp | i64 | emission finishes in 2216 and u32 breaks in 2106 |
| Difficulty representation | u64 directly | avoids the class of bugs from nBits' non-canonical encodings; LWMA works with difficulty directly |
| Merkle tree | RFC 6962 | structurally avoids Bitcoin's CVE-2012-2459 |
| Addresses | bech32m | detects 100 % of errors up to 4 characters; forbids mixed case; smaller QR codes |
| Fees | per byte, node policy | no scripts, so gas (charging for computation) is unnecessary. Tracks price movements without a hard fork |
| Privacy | none | greatly reduces implementation volume and audit cost. Transactions are about 1/8 of Monero's size |
| P2P | in-house | the requirements are simple; libp2p's dependency weight outweighs the benefit |
| Storage | redb | pure Rust, easy to cross-compile |
| Resident size of the block index | keep the objects in storage; resident memory holds only tip candidates and a bounded cache | holding everything is 500 bytes × 525,600 blocks a year: 2.5 GB at 10 years, 5 GB at 20. Neither disk nor initial sync hits a limit first — resident memory does. Bitcoin can hold everything because its interval is 10 minutes; at 60 seconds it does not hold ([§19](#settled-items)) |
| Chain-selection candidates | maintain a work-ordered set incrementally | a full scan is O(n) per block and O(n²) over an initial sync. At 100,000 blocks it matches the cost of writing to storage ([§10.6](#106-choosing-the-longest-chain)) |
| Mnemonic | BIP39, 12 words (128 bits) | 128 bits matches secp256k1's real strength of 2^128. A longer seed is not stronger than the curve and only adds transcription errors ([§6.6](#66-hd-wallets)) |
| Key derivation | BIP32 / BIP44 | avoids a state where a phrase written in the standard vocabulary is interpreted into different keys by another wallet. Keeps the path to hardware wallets open |
| mainnet coin type | put the applied-for 1033 in the implementation, and hold the mainnet launch until registration completes | fixing the path early lets wallet testing proceed. Before funds are involved, a number change costs only the path |
| Unknown output versions | keep anyone-can-spend, restrict versions to 0–31 | rejecting makes every version addition a hard fork. Restricting the range shrinks the dangerous surface without reducing soft-fork headroom ([§10.4](#104-handling-unknown-versions)) |
| Merged mining | disabled in v1 | do not debug the standalone chain and the Monero integration at the same time. Only header space is reserved |
| Partially signed transactions | the same division of roles as PSBT (BIP174); carry the spent outputs alongside | because the sighash includes every input's amount and spending condition, a key-holding machine cannot sign from a raw transaction alone ([§16.8](#168-partially-signed-transactions-pst)) |
| Address book | the same two-table structure as `addrman`; promotion from `new` to `tried` requires a successful connection | with one table, a peer holding many /16s fills it. Two tables structurally guarantee that half the outbound connections go to peers with a track record ([§14.6](#146-peer-discovery)) |
| Replacement by fee | apply BIP125 rules 2–5; do not require rule 1 (signalling) | the signal is a promise that cannot be kept. A miner need only take the higher fee, and one node ignoring the signal is enough to propagate the replacement. Advertising "it did not signal, so zero confirmations are safe" costs money to whoever believes it ([§13.3.2](#1332-replacement-by-fee-rbf)) |
| Receiver confirmations | a guideline of 10 blocks, not a consensus rule | the probability of reversal depends only on q and the confirmation count, not on the block interval, so 6 would give the same probability as Bitcoin. What differs is cost: a young chain's total hashrate is small, so the same share is cheap to buy. The confirmation count fills in that gap, hence 10. It is not enforced by nodes because what to wait for is the receiver's own risk, not a matter of consensus ([§10.7](#107-confirmations-for-the-receiving-side)) |
| Mempool after a reorg | return what was in the undone branch, then **revalidate the entire mempool** | picking out what fails misses transactions orphaned from their parents and ones whose maturity or locktime is no longer met after the height went back. Leaving them broken means a block you mined gets rejected by yourself. Reorgs are rare and the mempool is bounded, so full validation beats the complexity of selection ([§10.6](#106-choosing-the-longest-chain)) |
| A block on a losing branch | do not touch the mempool | that block is not on the active chain, and the transactions in it are still unconfirmed. Removing them stops us relaying and mining payments that are still valid. Forks happen normally, so the impact is not small ([§10.6](#106-choosing-the-longest-chain)) |

### Considered and not adopted

| Option | Why not |
| --- | --- |
| Cosmos SDK / a bespoke PoS chain | incompatible with RandomX (PoW) |
| Issuing as an ERC-20 token | contrary to the goal of having our own chain |
| Go | RandomX would go through cgo, and the call cost plus cross-compilation burden cancels out Go's development-speed advantage |
| ECDSA | malleable; no batch verification; no MuSig2 |
| Ed25519 | no BIP32 non-hardened derivation, so no xpub deployment; hardware wallet support is heavy |
| A halving schedule | to reconcile 1 billion total with a 10 OAG reward, the halving period would be 95 years, which does not work |
| Privacy features (RingCT, etc.) | excessive implementation volume and audit cost; transactions become 8–12 times larger |
| 1 MB blocks | 526 GB of growth per year makes running a node impossible |
| A SegWit-equivalent mechanism | with Schnorr and no scripts there is no malleability, so it is unnecessary |
| A 24-word mnemonic | even with a 256-bit seed, the derived keys top out at secp256k1's 2^128. Doubling the phrase only adds transcription errors |
| Treating unknown versions as invalid | every version addition becomes a hard fork. Requiring every node to upgrade at once is more dangerous than a loss of funds already mitigated at three layers |
| Launching mainnet before registration completes | the moment a different number is accepted, the keys derived from existing phrases change. To a user that is indistinguishable from the funds disappearing |
| A bespoke mnemonic wordlist | BIP39's wordlist is unique in its first four characters, and existing implementations and dictionaries work as-is |
| A transaction index on by default | every node would pay 37 GB a year when blocks are full. Consensus requires only the UTXO set, and a wallet need only record the transactions relevant to itself. Operators who need it enable `--index` |
| A maximum reorg depth | a network split deeper than the cap never rejoins. Leaving the attack possible is better than creating the possibility of a permanent split |
| Extending coinbase maturity | pushing back a reorg takes cumulative work, not time, and in block count 120 is already deeper than Bitcoin's 100. Extending it changes only how long you wait for the reward, not the cost of a reorg |
| Requiring a rate increase for replacement | BIP125 rules 3 and 4 look only at totals, so a large low-rate transaction can evict a small high-rate one. Adding a rule of our own here makes mempool contents diverge between nodes, which feeds directly into compact-block hit rates. The weakness is accepted in favour of compatibility |

---

## 19. Open questions

Items to be decided during implementation.

### Priority: high

- [ ] **Register the mainnet SLIP-0044 coin type**
      ([§6.6](#66-hd-wallets)). The BIP44-capable wallet that the application
      presupposed is implemented, and
      **`satoshilabs/slips` pull request #2061 has been submitted for number
      1033 and is awaiting review.** The implementation carries 1033 and can
      derive mainnet keys. testnet uses reserved number 1 and does not depend on
      this registration. Since neither acceptance nor timing is guaranteed, it is
      built into the mainnet launch schedule. **Until registration is final, do
      not put funds on a mainnet address**

### Priority: low

- [ ] **Whether to adopt proper fuzzing** — the decode paths already have tests
      that throw large numbers of byte strings corrupted by a seeded RNG
      (`oag-consensus/tests/decode_robustness.rs`,
      `oag-net/tests/message_robustness.rs`). Every CI run confirms two things:
      "no byte string causes a `panic`" and "anything that decodes re-encodes
      back to the same bytes". But it is guesswork: it neither measures path
      coverage nor digs into the branches it gets stuck on. Whether to add
      `cargo-fuzz` (libFuzzer) as a separate crate will be decided before the
      mainnet launch

- [x] **An English specification** — this file. The Japanese
      [`SPEC.md`](SPEC.md) remains normative; this is a translation
- [ ] **Choosing a block explorer**

### Settled items

All but the last follow Bitcoin's answer. The reasons are also in the table in
[§18](#18-record-of-design-decisions).

**Only the resident size of the block index differs.** Bitcoin keeps everything
in memory, which works because at a 10-minute interval there are only 960,000
entries. At this chain's 60-second interval the same approach does not hold.

| Item | Decision | Where |
| --- | --- | --- |
| Whether the address book should match `addrman` | yes; two-table structure | [§14.6](#146-peer-discovery) |
| Replacement by fee (RBF) | include it; apply BIP125 rules 2–5, do not require rule 1 | [§13.3.2](#1332-replacement-by-fee-rbf) |
| Partially signed transaction format | include it; the same roles as PSBT (BIP174) | [§16.8](#168-partially-signed-transactions-pst) |
| Transaction index | **not provided.** Added as an optional feature when needed | below |
| Coinbase maturity | **stays at 120 blocks.** Unchanged | below |
| Maximum reorg depth | **not provided.** Pruning rollback data and block bodies is an option the operator chooses | below |
| Multi-threaded mining | **included.** All threads share one dataset (from 0.1.1; 0.1.0 built one per thread) | [§11.2](#112-modes) |
| Resident size of the block index | **not proportional to height.** Storage holds the objects; only tip candidates and a bounded cache stay resident | below |

#### The block index's resident size is not proportional to height

**The objects of known blocks MUST NOT be kept resident in memory.**

At a 60-second interval, ten times as many blocks accumulate as Bitcoin's in the
same number of years. At roughly 500 bytes each, holding everything is 2.5 GB at
10 years, 5 GB at 20 and 50 GB by the time emission completes 190 years out.
**What hits a limit first is neither disk nor initial sync but resident memory.**
The bodies are 203 bytes for an empty block, so even 10 million blocks is 2 GB of
disk, and initial sync measured at 45 blk/s is two and a half days — comparable
to Bitcoin today.

Only two things stay resident.

| | Determined by |
| --- | --- |
| Tip candidates (the work-ordered set) | **the number of competing branches.** One branch's worth with no fork |
| A cache of recently fetched objects | **a bound.** 4096 entries, about 1 MB |

Neither depends on the length of the chain. The authoritative copies are in
storage, and anything evicted from the cache is fetched again. The parent-to-child
map is also in storage (it is only consulted when propagating an invalid mark to
descendants).

A tip candidate may be discarded once it falls below the tip's work. Switching
happens only to a branch that strictly exceeds it
([§10.6](#106-choosing-the-longest-chain)), and the tip's work never decreases,
so something that fell below can never become a candidate again.

Everything MUST NOT be loaded at once at startup. Read the tip first, take
entries one at a time, and discard anything below the tip on the spot. The amount
read is the same, but the amount held at once is constant.

**Absence from the cache MUST NOT be treated as "unknown".** When a lookup fails,
return an error. Conflating them means treating a perfectly good block as unknown
and silently leaving the chain (the same mistake as the seed resolution in
[§11.3](#113-seed-epochs)).

#### Multi-threaded mining shares the dataset

**This decision was reversed in 0.1.1.** "The 0.1.0 decision" below is kept as
the record of the time.

##### Why it was reversed in 0.1.1

It said "the price is memory and nothing else", but that memory was too much.

- Mining fast mode with 6 threads takes **12 GB**. A user really did mine with 6
  threads. Monero and XMRig need 2 GB for the same thread count.
- Building the dataset (about a minute) also runs once per thread, again every
  epoch.
- Speeding it up with large pages would need large pages multiplied by the
  thread count too. 12 GB of large pages is practically unobtainable on Windows.

So option (b) was taken, but without a thin crate: `SharedDataset` in `oag-pow`
carries just two lines of `unsafe impl Send / Sync`. No `unsafe` body (code that
touches pointers) was written. What was written is only the declaration "this
type may cross threads", and its grounds are listed on the type.

The recipe mechanism stays. The recipe carries the `SharedDataset` across, and
the VM is built on each worker thread. Only the inside of the recipe changed.

Option (a) remains open too. If upstream adds `Send` / `Sync`, the two lines are
no longer needed, and a `const _` in `oag-pow` will fail the build to make it
known.

##### The 0.1.0 decision

The question was: "`RandomXDataset` is not `Send`, so 2 GB cannot be shared. What
now?" The options were (a) ask `randomx-rs` to add `Send`, (b) allow `unsafe` in
a thin crate that handles the dataset, or (c) settle for one thread.

**None of them. The question was framed too narrowly.** Sharing is needed only if
you have already decided to "build one miner and hand it out". **Change what is
handed out from the miner to the recipe, and no sharing is needed.** All that
crosses a thread boundary is the seed value, and the miner is built on each
thread and never leaves it. No `unsafe`, and no waiting on upstream.

The price is memory. Nothing is shared, so it scales with the thread count (the
table in [§11.2](#112-modes)). In light mode one thread is 256 MB, so eight
threads is 2 GB — the same as one fast thread. **Which of one fast thread and
eight light threads is faster depends on the machine**, which is also why no
ratio is written into the specification.

Option (a) remains open. If upstream adds `Send`, the fast dataset can be shared
and multi-threaded fast mining fits in 2 GB. At that point only the inside of the
recipe mechanism changes. A `const _` in `oag-pow` will fail the build the moment
upstream adds `Send`, to make it known.

#### No transaction index by default

Neither an index from txid to transaction nor one from spending condition to
transaction is **held by default.** The only index consensus requires is the UTXO
set, and validation never asks "where is the transaction with this txid" (an
input always points at an `OutPoint`).

This is the same judgement as Bitcoin leaving `-txindex` off by default. A wallet
need only record the transactions relevant to itself
([§16.1](#161-relationship-with-the-node)).

**A real need to look up everything did arise, for the explorer, so it was added
as an optional feature.** Only a node given `--index` builds it. The default is
unchanged.

##### Shrinking the key

Done naively, the key is a 32-byte txid plus a 32-byte hash of the spending
condition. With full blocks sustained, that needs **124 GB a year** — the index
would be heavier than the chain's own 105 GB/year.

So the key is shrunk to 14 bytes.

```text
┌──────────────┬───────────┬──────────┐
│ prefix 8 B   │ height 4 B│ index 2 B│
└──────────────┴───────────┴──────────┘
  head of hash   u32 BE      u16 BE
```

There is no value. **The key itself is the location.** That turns 124 GB a year
into **37 GB**.

| Index | Naive key | Shrunk key |
| --- | --- | --- |
| Transaction index (txid → location) | 35 GB/year | 7 GB/year |
| Address index (lock → transaction) | 89 GB/year | 30 GB/year |
| Total | 124 GB/year | **37 GB/year** |

Both assume a year of full blocks. Full means 673 transactions a minute, 11 a
second — about 1.6 times Bitcoin. Real usage is orders of magnitude below that.

An 8-byte prefix **collides.** But it never gives a wrong answer. What the index
returns is "look here", not the answer; the caller reads the transaction at that
location and **compares against the complete txid or the complete lock**,
discarding it on a mismatch. A collision only adds one spurious candidate. With
350 million entries in a 2^64 space, the expected number of collisions is about
0.003, deliberately producing one takes 2^64 work, and success buys nothing but
one wasted lookup.

Height and index are big-endian so that **byte order matches chain order.** A
prefix range scan over the same prefix yields history oldest-first. No sorting is
needed, and paging is just reading onwards.

##### The index moves in the same transaction as the UTXO set

Index updates happen **inside the same write transaction** as connecting and
disconnecting blocks. Splitting them creates a possible state of "the UTXO set
advanced but the index is stale", which would need machinery to repair that
divergence after every power loss. Kept together, the index always points at the
same place as the UTXO set.

Input-side addresses are **read from the undo information.** An input names only
an `OutPoint`, and the output it points at is already gone from the UTXO set. The
record kept for reorgs is the only source.

##### Never build a half-finished index

Rebuilding is also one transaction. **The worst outcome of a power loss midway is
a half-built index.** An index that is "absent" can refuse lookups; an index that
is "half present" without knowing it returns incomplete history as if it were
complete. The user believes it. Only states that can be told apart are created.

#### Coinbase maturity stays at 120 blocks

The question was "isn't two hours short?" The unit of comparison is wrong.

Pushing back a reorg takes **cumulative work**, which is proportional to block
count, not time. Against Bitcoin's 100 blocks this chain has 120 — **deeper in
block count than Bitcoin.** One block is 60 seconds so the wall-clock figure
comes out small, but the work stacked in those two hours is 120 blocks' worth.

It is true that in a low-hashrate period a 120-block reorg is cheap in absolute
terms. **But extending maturity does not fix that.** What extending fixes is only
"how long until the reward can be spent"; it does not change the cost of a reorg.
What does help is difficulty adjustment
([§12](#12-difficulty-adjustment-lwma)) and not treating a small number of
confirmations as final.

#### No maximum reorg depth

A cap would bound what a 51 % attack can rewrite. In exchange, **a network split
deeper than the cap never rejoins.** A chain that cannot rejoin does not recover
from an attack until a human decides which branch — the attacker's or the honest
one — is real.

This chain's convergence is decided by cumulative work alone
([§10.6](#106-choosing-the-longest-chain)). Bitcoin is the same and has no depth
limit. Leaving the attack possible is better than creating the possibility of a
permanent split.

#### Rollback data, though, an operator may throw away

Rollback data (undo) is **only ever read when the chain reorganises back over a
block**. One record is added per block, and its size follows the UTXOs that
block spent, so a run of full blocks runs to tens of gigabytes a year.

An implementation may prune it. But:

- It SHOULD NOT prune by default. The decision above stands as the default.
- Pruning is **not a consensus rule**. The set of blocks accepted does not
  change, and a node that prunes converges on the same chain as one that does
  not.
- On meeting a reorganisation deeper than what it kept, it MUST NOT quietly
  settle into a different state. It says it cannot follow, so that the operator
  can sync again.

The worry above — that a network split deeper than the cap never rejoins —
applies to a cap that is a consensus rule. A node that discarded storage
**gets back to the right chain by syncing again**. It is not a permanent split.

`oag-node` enables it with `--prune-undo <blocks>`; leaving the number out
keeps 4320 (three days at one minute per block).

#### Block bodies may go on the same terms

A body is **only held in order to hand it to somebody else**. What a node needs
to verify with is the UTXO set, and that survives pruning whole.

An implementation may prune bodies. On top of the conditions for rollback data:

- A node that has pruned MUST NOT announce `SERVICE_FULL_NODE`
  ([§14.5](#145-p2p-protocol)). It announces `SERVICE_LIMITED`.
- A body it does not have MUST be answered with `notfound`. **Saying nothing is
  the worst of it**: the peer waits out its timeout, and since blocks only
  connect in order from the parent, more than that one block stalls.
- The chain of headers MUST NOT be broken. The headers and the parent links in
  the index are not pruned. Break them and a node can no longer walk back to the
  genesis block to confirm which chain it is on.
- Verification MUST NOT change. A pruned node still checks every signature,
  amount, double spend, maturity and proof of work on a new block. Pruning is
  about what it can serve, not about what it takes on trust. This is where it
  parts from a light client.
- The genesis block may be kept. It costs one block.

A pruned store MUST NOT build the transaction index. There is no way to index
transactions in bodies that were thrown away, and an index with holes returned
as a complete one is believed. Only "complete" and "absent" are states worth
having.

Having pruned MUST be recorded in the store. Turning the setting off and
restarting does not bring the blocks back. Deciding what to announce from the
setting alone would mean claiming to serve what cannot be served.

When choosing who to sync from, a node whose bodies have not caught up may
prefer peers announcing `SERVICE_FULL_NODE`. **It MUST NOT skip an address
whose announcement it has never heard**, though: an announcement is only known
from a handshake, so skipping them leaves a node with an empty address book
unable to make a single connection.

`oag-node` enables it with `--prune <blocks>`; leaving the number out keeps
4320. It prunes bodies and rollback data to the same depth, so it cannot be
combined with `--prune-undo`, nor with `--index`, `--explorer` or `--wallet`,
which need the index. The shallowest depth it accepts is 144; below that the
one- and two-block reorganisations of ordinary operation would leave it stuck.

#### A light node is built first without changing the protocol

A light node (one holding only headers) **can be built from the existing
messages alone**.

```text
getheaders / headers    the header chain; it verifies the proof of work itself
getdata(Block) / block  the contents; it recomputes the merkle root itself
```

**Merkle proofs are not needed.** A proof exists so that a block need not be
downloaded, not to make verification stronger. With the block in hand the root
can be computed. Filters and proofs alike are **tools for saving bandwidth, and
leaving them out costs nothing in safety**.

So `PROTOCOL_VERSION` stays where it is and running nodes change nothing.

##### What to settle now so it is not rewritten once blocks fill up

So that filters (BIP158-style) can be added later, a light node SHOULD
implement these as **two separate stages**:

1. **Deciding whether to fetch** — for now, always fetch. Later this becomes:
   fetch the filter, fetch the block only on a match
2. **Verifying and collecting** — verify the block and collect the transactions
   touching its own locks

**Stage 2 does not change by one bit** between the two, because either path
ends with the block itself in hand and checks it the same way. A filter lives
entirely inside stage 1. Mixing the two means rewriting all of it when blocks
fill up.

##### Filters MUST NOT be committed to blocks

A filter digest MUST NOT go into the header. Changing the header format is a
hard fork, **a price a running chain cannot pay**. Bitcoin also chose not to
commit them in BIP157/158.

An uncommitted filter can be lied about. A lie makes a node **miss a payment to
itself** (it cannot be made to see a transaction that is not there: fetching the
block settles that). Pulling filters from several peers and comparing them makes
up for it. This is a property a light node carries anyway, not one filters
introduce.

##### The announcement can be added at that time

Serving filters is announced as `SERVICE_COMPACT_FILTERS` (`1 << 2`).
`effective_services` in [§14.5](#145-p2p-protocol) passes unknown bits through
unchanged, so **adding a bit costs running nodes nothing**. It is the road
already travelled by `SERVICE_LIMITED` for pruned nodes.

---

## Appendix A: parameter list

```
━━━ Identity ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Name                        Orange
Ticker                      OAG
mainnet HRP                 oag
testnet HRP                 toag
regtest HRP                 roag

━━━ Currency ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DECIMALS                    16
1 OAG                       10^16 atomic
MAX_SUPPLY                  10^25 atomic  (1,000,000,000 OAG)
BLOCK_REWARD                10^17 atomic  (10 OAG)
EMISSION_END_HEIGHT         100,000,000
PREMINE                     0
Amount type                 u128

━━━ Consensus ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TARGET_BLOCK_TIME           60 seconds
MAX_BLOCK_SIZE              200,000 bytes
MAX_TX_SIZE                 100,000 bytes
COINBASE_MATURITY           120 blocks
MEDIAN_TIME_SPAN            11 blocks
MAX_FUTURE_TIME_DRIFT       300 seconds
LWMA_WINDOW (N)             90            (provisional)
MAX_TARGET                  2^256 − 1

━━━ Proof of work ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Algorithm                   RandomX
SEED_EPOCH_BLOCKS           2048
SEED_LAG                    64 blocks
Validation mode             light (256 MB)
Mining mode                 fast (2 GB / thread)

━━━ Cryptography ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Curve                       secp256k1
Signatures                  Schnorr / BIP340 (64 bytes)
Sighash                     BIP341 construction
General hash                BLAKE3-256
Merkle                      RFC 6962
Addresses                   bech32m (BIP350)
HD wallet                   BIP32 / BIP39 / BIP44

━━━ Fees (node policy) ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MIN_RELAY_FEE_RATE          5 × 10^10 atomic / byte
                            (0.000005 OAG / byte)
DUST_THRESHOLD              1.5 × 10^13 atomic
                            (0.0015 OAG)
Fee for a reference tx      0.000975 OAG
INCREMENTAL_RELAY_FEE_RATE  5 × 10^10 atomic / byte
                            (the replacement increment; same as MIN_RELAY_FEE_RATE)
MAX_REPLACEMENT_COUNT       100           (how many a replacement may evict)

━━━ Receiver guidance (neither consensus nor policy) ━━━━
RECOMMENDED_CONFIRMATIONS   10 blocks     (about 10 minutes; SPEC §10.7)
Large / irreversible handover  20 blocks or more
Zero confirmations          MUST NOT be accepted

━━━ Network ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
mainnet P2P/RPC/Mining      9444 / 9445 / 9446
testnet P2P/RPC/Mining      19444 / 19445 / 19446
regtest P2P/RPC/Mining      29444 / 29445 / 29446
RPC/Mining bind default     127.0.0.1 only
Address book new table      1,024 buckets × 64
Address book tried table    256 buckets × 64
new buckets one source hits 64
tried buckets one /16 hits  8
new slots one address takes up to 8
Magic bytes (mainnet)       33 97 55 03
Magic bytes (testnet)       7F 88 A0 C1
Magic bytes (regtest)       18 2C 9C 5E

━━━ Genesis ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Timestamp (main/test)       1,788,220,800  (2026-09-01T00:00:00Z)
Coinbase message            Orange is good
Block 0 reward              10 OAG burned (pinned to the zero key)
Difficulty (main/test/reg)  1,000 / 10 / 1
mainnet hash                7511b77a9fb2aac8...907bb64a775f0c40
testnet hash                0862309e4cf48d92...95ea284529664bfa
regtest hash                c38b0b105c855791...f1484dd9cad874ba
```

## Appendix B: derived figures

```
Blocks per year               525,600
Issuance per year             5,256,000 OAG
Time to complete emission     about 190 years 3 months
Reference transaction size    195 bytes (193 for small, 197 for large payments)
Transactions per block        about 1,025
Throughput                    about 17.1 per second
Chain growth (when full)      about 105 GB/year
Cost to fill every block      1.0 OAG/block = 1,440 OAG/day
```

---

## Appendix C: references

- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) — hierarchical deterministic wallets
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) — mnemonic code
- [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) — multi-account hierarchy
- [BIP68](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki) — relative locktime
- [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) — Schnorr signatures
- [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) — Taproot (the sighash design)
- [BIP350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki) — bech32m
- [RFC 6962](https://datatracker.ietf.org/doc/html/rfc6962) — Certificate Transparency (merkle tree)
- [tevador/RandomX](https://github.com/tevador/RandomX) — the RandomX reference implementation
- [zawy12/difficulty-algorithms](https://github.com/zawy12/difficulty-algorithms) — LWMA
- [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) — the BLAKE3 reference implementation

---

**This document is a pre-implementation draft. Inconsistencies found during
implementation are reflected here, and this document — not the code — is treated
as normative.** For this English edition, that normativity belongs to the
Japanese [`SPEC.md`](SPEC.md); anything here that disagrees with it is a bug in
the translation.
