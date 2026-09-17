# Orange (OAG)

RandomX を Proof of Work に用いる、CPU マイニング型の UTXO ブロックチェーン。
[chroma](https://github.com/kusogakiller/chroma) をベースにしている。

> **状態: 開発初期。** 3 つのネットワークすべてでジェネシスが確定し、
> ピア発見も動きます。**まだテストネットは稼働しておらず、通貨としての
> 価値もありません。**

| 項目 | 内容 |
| --- | --- |
| 合意形成 | Proof of Work (RandomX) |
| 会計モデル | UTXO |
| 署名 | Schnorr / BIP340 (secp256k1) |
| ブロック間隔 | 60 秒 |
| 総発行量 | 1,000,000,000 OAG |
| 発行 | 10 OAG/ブロック 固定、半減期なし、約 190 年で完了 |
| 初期配布 | **なし** (全量マイニング。ブロック 0 の 10 OAG は焼却) |
| プライバシー | なし (透明台帳) |
| 実装 | Rust |

## 設計目標

1. **公平な分配** — プレマイン・ICO・開発者報酬を一切持たない
2. **単純さ** — スクリプト言語も仮想マシンも持たない。攻撃面を最小に保つ
3. **長期的な分配** — 半減期を持たない線形発行

明示的な非目標: プライバシー、スマートコントラクト、高スループット。

## 仕様書

**[`docs/SPEC.md`](docs/SPEC.md) が正典です。** すべてのパラメータ、コンセンサス
ルール、および設計判断の理由が記載されています。実装との差異は仕様書側を優先して
解消します。

## 進捗

| フェーズ | 内容 | 状態 |
| ---: | --- | --- |
| 0 | ワークスペース、CI、仕様書 | 完了 |
| 1 | 基本型 (金額・ハッシュ・アドレス・鍵) | 完了 |
| 2 | トランザクション・ブロック・シリアライズ・sighash | 完了 |
| 3 | 検証ロジック、UTXO セット | 完了 |
| 4 | RandomX、難易度調整 (LWMA) | 完了 |
| 5 | チェーン状態、リオーグ | 完了 |
| 5b | 永続化 (redb)・チェーンとの接続 | 完了 |
| 6 | mempool、手数料ポリシー | 完了 |
| 7a | P2P プロトコル (枠組み・メッセージ・ハンドシェイク) | 完了 |
| 7b | ブロックロケータ、取り寄せの割り振り | 完了 |
| 7c | Compact Blocks | 完了 |
| 7d | TCP トランスポート | 完了 |
| 8 | マイナー | 完了 |
| 9a | ノード (oag-node) — 記憶域・チェーン・採掘・CLI | 完了 |
| 9b | ノードへの P2P 組み込み (2 台での同期) | 完了 |
| 10a | JSON-RPC (ノード側) | 完了 |
| 10b | CLI ウォレット (鍵・残高・送金) | 完了 |
| 10c | 安全性の強化 (鍵の暗号化・種からの導出) | 完了 |
| 11a | チェーン選択の候補探しを漸進的にする | 完了 |
| 11b | ジェネシス確定 (3 ネットワークすべて) | 完了 |
| 11c | RandomX の fast モード (採掘) | 完了 |
| 11d | ピア発見 (アドレス帳・`addr`・シードノード) | 完了 |
| 11e | BIP39 / BIP32 / BIP44 (控えの語) | 完了 |
| 11f | テストネット公開 | 未着手 |
| 12a | 取引索引・アドレス索引 (任意機能) | 完了 |
| 12b | ブロックエクスプローラ | 完了 |

## クレート構成

```
crates/
├── oag-primitives/   金額 (u128)・BLAKE3・マークル・varint・鍵・アドレス
├── oag-consensus/    符号化・パラメータ・トランザクション・ブロック・
│                    sighash・UTXO セット・検証
├── oag-pow/          難易度・ターゲット・LWMA・シードエポック・RandomX
├── oag-chain/        ブロックインデックス・最良チェーン選択・リオーグ・ジェネシス
│                    記憶域の抽象 (ChainStore) とメモリ実装
├── oag-store/        永続化 (redb)
├── oag-mempool/      mempool・中継ポリシー
├── oag-net/          P2P プロトコル (枠組み・メッセージ・ハンドシェイク・
│                    ロケータ・取り寄せの割り振り・Compact Blocks・TCP)
├── oag-miner/        ブロックテンプレートの組み立てと nonce の探索
├── oag-rpc/          JSON-RPC 2.0・最小限の HTTP・合言葉・呼び出し側
├── oag-node/         ノード本体・専用スレッド・ピアとのやり取り・実行ファイル
└── oag-wallet/       鍵の保管・支払いの組み立てと署名・実行ファイル
```

`oag-pow` の RandomX は feature `randomx` の背後にある。C++ 実装のビルドに
cmake と C++ コンパイラを要するため、既定では無効にしてある。

```sh
cargo test -p oag-pow --features randomx
```

同様に `oag-net` の TCP を扱う層は feature `tokio` の背後にあります。
プロトコルの規則そのものは feature なしで使えます。

```sh
cargo test -p oag-net --features tokio
```

## 動かす

mainnet / testnet / regtest のいずれも起動します。**手元で試すなら
regtest** です。難易度が 1 なので 1 台ですぐにブロックが積み上がります。

| ネットワーク | ジェネシス難易度 |
| --- | ---: |
| mainnet | 1,000 |
| testnet | 10 |
| regtest | 1 |

最初の 90 ブロックはこの難易度のままです (LWMA は窓が埋まるまで働かない)。

### 掘らないで動かす

**採掘は任意です。既定では掘りません。** `--mine` を付けなければ、
ブロックを検証して中継するだけのノードとして動きます。

```sh
./target/release/oag-node run --network mainnet --datadir ./oag-data
```

検証は RandomX の light モード (256 MB) だけで済みます。**2 GB を積んで
いない機械でもフルノードを動かせます** (SPEC §11.2)。採掘するかどうかと、
検証できるかどうかは別です。

### 掘る

`--mine` を付けたときだけ掘ります。報酬の受取先 `--payout` が要ります。
さらに `--fast` を付けると RandomX の fast モード (2 GB) を使います。
省くと light モード (256 MB) のまま掘ります。

```sh
./target/release/oag-node run --network mainnet --datadir ./oag-data \
    --mine --fast --payout <アドレス> --blocks 5
```

手元のハッシュレートは次で測れます。

```sh
cargo run --release -p oag-pow --features randomx --example hashrate
```

#### 何スレッドで掘るか

既定は 1 本です。`--mining-threads` で増やせます。`0` を渡すとコア数に
合わせます。

```sh
./target/release/oag-node run --network mainnet --datadir ./oag-data \
    --mine --payout <アドレス> --mining-threads 4
```

**本数を増やすと memory も増えます。** RandomX の採掘器はスレッドを
またげないので、1 本ごとに自分の分を建てます。

| モード | 1 本あたり | 4 本なら |
| --- | ---: | ---: |
| light | 256 MB | 1 GB |
| fast | 2 GB | 8 GB |

`--fast` と `--mining-threads 0` を同時に渡しても 1 本のままにします。
積んでいる memory が分からないのに、2 GB ずつ確保しにいかないためです。
fast を何本も建てたいときは本数を明示してください。

light を何本も建てるのと fast を 1 本建てるのは、どちらも 2 GB 前後に
なります。**どちらが速いかは機械によります。** 上の `hashrate` で
light の 1 本あたりの速さを測り、本数を掛けて比べてください。

```sh
cargo build --release -p oag-node

# 受取先アドレスを作る
./target/release/oag-node keygen --network regtest --out regtest.key

# 5 ブロック掘る (--blocks を省くと止まらない)
./target/release/oag-node run --network regtest --datadir ./oag-data \
    --mine --payout <上で出たアドレス> --blocks 5

# 今の状態を見る
./target/release/oag-node info --network regtest --datadir ./oag-data

# block/<高さ>/<ブロックハッシュ>.dat の形で書き出す
./target/release/oag-node export-blocks --network regtest \
    --datadir ./oag-data --out ./block
```

### 公開ネットワークに繋ぐ

mainnet と testnet では、繋ぎ先を指定しなければ自動で探します。住所帳が
空のときだけ DNS シード (`seed.manh2309.org`) を引き、あとはノード同士が
住所を教え合います。外向きの接続を 8 本保ちます。

外から繋いでもらいたいノード (シードに載せるノードなど) では、自分の
住所を名乗る必要があります。**自分の外向きの住所を自分で確かめる手立ては
無いので、明示してください。**

```sh
./target/release/oag-node run --network testnet \
    --listen 0.0.0.0:19444 --external-addr <公開IP>:19444
```

`--no-discovery` を付けると、住所帳もシードも使わず `--connect` で
名指しした相手だけに繋ぎます。

### 手元で 2 台を繋ぐ

2 台を繋ぐには、片方を待ち受けにして、もう片方から `--connect` します。

```sh
# 1 台目: 待ち受けて掘る
./target/release/oag-node run --network regtest --datadir ./node-a \
    --listen 127.0.0.1:19444 --mine --payout <アドレス>

# 2 台目: 掘らずに繋いで同期する
./target/release/oag-node run --network regtest --datadir ./node-b \
    --no-listen --connect 127.0.0.1:19444
```

同期は headers-first です。ヘッダを先に集めてチェーンの形を確かめ、
そのうえで本体を取り寄せます。受け取ったブロックは**自分で検証**して
おり、UTXO セットは相手から貰うのではなく自分で組み立てています。

## エクスプローラで見る

`--explorer` を付けると、ブラウザで鎖の中身を見られます。既定は
`http://127.0.0.1:8080/` です。

```sh
./target/release/oag-node run --network mainnet --datadir ./nodedata --explorer
```

高さ・ブロックハッシュ・取引 ID・アドレスのどれでも探せます。取引の頁には
入力側の金額と相手まで出ます。**読むだけの口**で、送金も設定変更もここから
はできません。

住所を変えたいときは `--explorer 127.0.0.1:9000` のように渡します。
ループバック以外にすると外から見えるようになります。

### ブロックが太っても重くならないようにしてあること

先頭の一覧は、並べる 25 ブロックの**本体を読みません**。時刻と難易度は
ブロックインデックスのヘッダから、大きさは保存した記録の長さから、取引数は
ヘッダ直後の varint 1 個から取ります。本体を復号すると、表に出さない取引
まで全部組み立てることになり、満杯のブロック (約 670 取引) が 25 個なら
16,000 件あまりを確保して捨てる計算になります。しかもそれはノード本体の
処理列の中で起きるので、その間ブロックもピアも捌けなくなります。

一覧はまとめて 1 回の読み取りで作ります。行ごとに引き直すと、描いている
最中に届いたブロックで上下の行が違う時点を映すためです。

ブロック内の取引表は 50 件ずつに区切ります。番号はブロック内の通し番号
なので、索引が指す位置とそのまま照らし合わせられます。

### 索引について

取引 ID とアドレスで引くには**索引が要ります**。`--explorer` を付けると
自動で作られますが、エクスプローラなしで RPC からだけ使うなら `--index`
を付けてください。

```sh
./target/release/oag-node run --network mainnet --datadir ./nodedata --index
```

初回だけ鎖全体を走査します。以後はブロックを受け取るたびに更新されるので、
組み直す必要はありません。`--drop-index` で捨てられます。

**既定では作りません。** コンセンサスは索引を必要とせず、ブロックが満杯の
まま 1 年続けば 37 GB の上乗せになるからです (`docs/SPEC.md` §19)。実際の
使われ方ではもっとずっと小さく、1 ブロックに 10 取引なら年 0.5 GB 程度です。

索引があると、次の手続きも使えるようになります。

| 手続き | 返すもの |
| --- | --- |
| `getaddresshistory` | そのアドレスに触れた取引 |
| `getrawtransaction` | 確定した取引 (索引が無いと mempool のみ) |
| `getindexinfo` | 索引を持っているか |

## 送金する

ウォレットはノードと **JSON-RPC でしか話しません**。秘密鍵はノードに
渡らず、署名はウォレット側で済ませます。

```sh
cargo build --release -p oag-wallet

# ウォレットを作る (パスフレーズを尋ねられ、控えの 12 語が表示される)
./target/release/oag-wallet --wallet ./alice.json new
./target/release/oag-wallet --wallet ./bob.json new

# alice のアドレス宛てに掘る (コインベースは 120 ブロック後に使える)
./target/release/oag-node run --network regtest --datadir ./oag-data \
    --mine --payout $(./target/release/oag-wallet --wallet ./alice.json address) \
    --blocks 130

# 残高を見る
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data balance

# 送る
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    send $(./target/release/oag-wallet --wallet ./bob.json address) 12.5
```

### 掘り続けるなら、ときどきまとめてください

掘っていると **1 ブロックにつき UTXO が 1 つ増えます**。コインベースの出力は
1 つだからです。放っておくと `scanutxos` の上限 (10,000 件) に当たり、そこで
**残高も送金も引けなくなります**。60 秒間隔なら 10,000 ブロックは**約 7 日**
です。

```sh
# まず見るだけ
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    consolidate --dry-run

# 畳む
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    consolidate
```

細かい出力を集めて、自分宛ての 1 つにまとめます。

- **1 回では畳み切れません。** 1 取引の上限 (100,000 バイト) が入力 980 件
  前後で頭を打つので、多いときは確定を待って繰り返します。あと何件残るかは
  毎回表示します
- **成熟していないコインベースは触りません。** 120 ブロック経つまで使えない
  ためで、その件数は畳み残しとは別に表示します
- **二度押しても損しません。** まとめるものが無ければ何もせず終わります。
  未確定のまとめが使っている出力も手持ちから外すので、同じ取引を二重に
  送ろうとして断られることもありません
- `--max-inputs` で 1 回に畳む本数を絞れます

手数料は安いです。満杯に近い 1 本 (100,000 バイト) で **0.5 OAG**、そこに
入る 980 件が 10 OAG ずつなら 9,800 OAG を 0.5 OAG で畳む計算になります。

### 受け取る側は何承認待つか

**目安は 10 ブロック (約 10 分) です。** 高額なもの、渡すと取り戻せない
ものは 20 以上。**0 承認 (mempool にあるだけ) は支払いとして受け取っては
いけません。**

覆される確率は攻撃者のハッシュレート比と承認数だけで決まり、**ブロック
間隔には依存しません**。Bitcoin の慣習は 6 で、10 なら同じ占有率に対して
確率はおよそ 1 桁下がります。6 で足りないのは確率ではなく費用の問題で、
若いチェーンは全体のハッシュレートが小さいぶん、同じ占有率が安く買える
ためです。詳細と数表は SPEC §10.7 にあります。

`balance --verbose` が UTXO ごとの確認数を出します。10 に満たないものには
`!` が付きます。**印は表示だけで、送金は妨げません。**

```sh
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    balance --verbose
```

なお、ウォレットの残高はチェーンの UTXO セットだけを見ており、mempool は
一切見ません。**0 承認の出力は残高に出ず、使うこともできません。**

#### 確認数は減ることがあります

ブロックが分岐して、こちらが見ていた枝が負けると、そこに入っていた支払いは
未確認に戻ります。**確認数は増えるだけではありません。**

- 新しい枝にも同じ支払いが入っていれば、確認数がその分だけ戻ります
  (9 → 2 など)。いずれまた伸びます
- まだ入っていなければ 0 に戻り、mempool で掘られるのを待ちます
- 新しい枝が同じ資金を別の宛先へ使っていれば、**その支払いは二度と確認
  されません**。これが二重使用です

ウォレットは毎回チェーンを見直すので、`balance` を実行し直せば正しい値が
出ます。ただし**減ったことを知らせる仕組みはありません。** 承認数は
**品物を渡す直前に確かめてください。**

### 鍵を持つ機械を分ける

鍵を持つ機械とノードに繋がる機械を分けたい場合は、**部分署名トランザクション
(PST)** を経由します。Bitcoin の PSBT 相当で、署名に要るもの (使う出力の金額と
支払い条件) を一緒に運ぶため、署名する側はチェーンを見に行く必要がありません。

```sh
# 繋がる側: 組み立てるだけ。署名しない
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    pst create $(./target/release/oag-wallet --wallet ./bob.json address) 12.5 \
    --out ./payment.pst

# 鍵を持つ側: ノードに繋がずに署名する
./target/release/oag-wallet --wallet ./alice.json pst sign ./payment.pst

# 繋がる側: 仕上げて送る
./target/release/oag-wallet --wallet ./alice.json --datadir ./oag-data \
    pst send ./payment.pst
```

複数の持ち主がそれぞれ署名した場合は `pst combine` で束ねます。中身はいつでも
`pst show` で確かめられます。**署名する前に手数料を見てください。**

RPC は**ループバックのみ**で待ち受け、合言葉による認証を要求します
(合言葉は起動のたびに作られ、`<datadir>/.cookie` に書かれます)。
`curl` からも呼べます。

```sh
curl -s --user "$(cat ./oag-data/.cookie)" -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":[]}' \
  http://127.0.0.1:9445/
```

ウォレットは**種 1 つをパスフレーズで暗号化して**保管します
(Argon2id + ChaCha20-Poly1305、ファイルの権限は 0600)。鍵は種から導くため、
**控えは種 1 つで足ります** — アドレスをあとから何個増やしても、同じ控えで
復元できます。

```sh
# 控えの語を表示する
./target/release/oag-wallet --wallet ./alice.json seed

# 控えの語から復元する
./target/release/oag-wallet --wallet ./recovered.json restore
```

控えは **BIP39 の 12 語**です。鍵の導出は BIP32 / BIP44 に従います。

```
m / 44' / <coin_type>' / 0' / 0 / <index>
```

> **控えの語を知る者は資金を動かせます。** 紙に書き写して安全な場所に
> 保管してください。パスフレーズが弱ければ暗号化は守ってくれません。

> **mainnet のアドレスへ資金を入れないでください。** mainnet の
> coin_type は 1033 ですが、SLIP-0044 へ申請したところで**まだ審査中**です。
> 別の番号で受理されれば経路が変わり、同じ控えから出るアドレスも変わります。
> ウォレットの動作確認は testnet と regtest (予約番号 1) で行ってください
> ([SPEC §6.6](docs/SPEC.md))。

BIP39 の追加パスフレーズを使う場合は `--mnemonic-passphrase` を渡します。
**打ち間違えても失敗としては現れません。** 別のパスフレーズは残高 0 の別の
ウォレットを作るだけで、どこにも誤りは表示されません。

`oag-node` は RandomX を必ず使うため、ビルドに cmake と C++ コンパイラが
必要です。

## ビルド

```sh
cargo test                    # テスト
cargo clippy --all-targets    # lint
cargo fmt --all -- --check    # 書式
```

ツールチェーンは `rust-toolchain.toml` で **1.98.0 に固定**しています。
rustup が自動で該当バージョンを取得するため、追加の操作は不要です。
固定しているのは、新しい rustc で追加された lint が CI でのみ失敗する事態を
避けるためです。

MSRV (最低必要バージョン) は **1.90** で、CI が毎回検証しています。
永続化に用いる redb がこのバージョンを要求するため、それに合わせています。

## ライセンス

MIT
