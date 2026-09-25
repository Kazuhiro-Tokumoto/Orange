# コマンド一覧

Orange (OAG) の `oag-node` と `oag-wallet` で使えるものを一枚にまとめる。
個々の説明は `--help` が持っている。ここは**何があるか**を見るための表で
あり、詳細はコマンド側が正である。

```
oag-node <コマンド> --help
oag-wallet <コマンド> --help
```

---

## まず動かす

```
oag-node run --network mainnet --datadir ./oag-data
```

繋ぎ先は自動で探す。設定は要らない。止めるのは Ctrl-C。

---

## oag-node

| コマンド | すること |
| --- | --- |
| `run` | ノードを動かす |
| `info` | いまの状態を見る (動かさずに読む) |
| `keygen` | 鍵を 1 つ作ってアドレスを出す |
| `compact` | 記憶域を詰め直して空きを OS に返す |
| `export-blocks` | アクティブチェーンのブロックをファイルに書き出す |

`info` `compact` `export-blocks` は**ノードを止めてから**使う。記憶域を
排他で開くため、動かしたままでは開けない。

### どこに置くか

| | 既定 |
| --- | --- |
| `--network <mainnet\|testnet\|regtest>` | `regtest` |
| `--datadir <path>` | `./oag-data` |

**`--network mainnet` を付け忘れると regtest で動く。** 本番に繋ぎたい
ときは必ず付ける。

### run — 繋ぐ

| | すること |
| --- | --- |
| `--listen <addr>` | 待ち受ける住所。既定は mainnet で `0.0.0.0:9444` |
| `--no-listen` | 待ち受けない。繋ぎに行くだけ |
| `--connect <addr>` | この相手だけに繋ぐ (繰り返し可) |
| `--external-addr <addr>` | 外から見えるこちらの住所を名乗る |
| `--no-discovery` | シードも住所交換も使わない |

外から繋いでもらうには **9444/tcp を開ける** (testnet は 19444)。開けなく
ても同期はできるが、他の人の同期先にはなれない。

### run — 掘る

| | すること |
| --- | --- |
| `--mine` | 採掘する。`--payout` が要る |
| `--payout <address>` | 報酬の受取先 |
| `--fast` | 速い方式。**2 GB** 要る。スレッドが何本でも 2 GB のまま |
| `--mining-threads <n>` | 使うスレッド数。`0` でコアの数 |
| `--blocks <n>` | この本数を掘ったら止める |

`--fast` のデータセット (2 GB) は全スレッドで 1 本を共有する。本数を
増やして増えるのは 1 本あたり 2 MB だけである。light は 1 本ごとに
256 MB 要る。

#### 大きなページ (large pages)

`--fast` のデータセットは、OS が許せば大きなページに置く。2 GB の中を
飛び回って読むので、普通の 4 KB のページより速くなる。**許されていな
ければ黙って普通のページで掘る。** 止まりはしない。

どちらになったかは、掘り始めのログで分かる。

```
mining with 6 threads (fast mode, large pages)   ← 使えている
large pages are not available, ...                ← 使えていない
```

使うには、機械の側で 1 度だけ設定が要る。

**Linux**: 2 MB のページを 1168 枚 (データセット 1040 + キャッシュ 128)
確保しておく。

```
sudo sysctl -w vm.nr_hugepages=1168
# 再起動しても残す
echo 'vm.nr_hugepages=1168' | sudo tee /etc/sysctl.d/90-orange.conf
```

確保した分は、掘っていないときも他のプログラムからは使えない。やめる
ときは `0` に戻す。

**Windows**: 自分のアカウントに「メモリ内のページのロック」の権限を付ける。

1. `Win + R` で `secpol.msc` を開く
2. ローカル ポリシー → ユーザー権利の割り当て → **メモリ内のページのロック**
3. 「ユーザーまたはグループの追加」で自分のアカウントを足す
4. **サインアウトしてサインインし直す** (再起動でもよい)

`secpol.msc` は Pro 以上にしかない。Home では普通のページのまま掘る。
長く動かしてメモリが細切れになっていると、権限があっても取れないことが
ある。そのときは再起動すると取れる。

**macOS**: 特に設定は無い。取れれば使う。

### run — 追うだけ (軽量モード)

| | すること |
| --- | --- |
| `--light` | チェーンを追うが、持たない |
| `--watch <address>` | 見張るアドレス。繰り返し可 |

ヘッダを集めて **PoW をフルノードとまったく同じように検証**し、本体を
もらって**マークルルートを自分で計算し直し**、`--watch` のアドレスを拾って
捨てる。残るのはヘッダだけである。

**他人に任せているわけではない。** 確かめられないのは「隠されたかどうか」
だけで、隠されると入金を**見落とす**。逆は起きない ── 鎖に無い入金を
でっち上げられることはない (SPEC §19)。

**節約できるのはディスクであって、通信量ではない。** ブロックは全部落とす。
いまの量で年 130 MB 程度である。

採掘も中継もできず、誰にもブロックを配れない。名乗りは `SERVICE_NONE`。

**アドレスは最初に渡しきること。** 走査済みのブロックは見直さないので、
後から足すと引き直しが要る。鍵は要らない。見るだけで使わない。

```
oag-node run --network mainnet --light --watch oag1q...
oag-node info --network mainnet          # 残高が出る
```

`height` は 0 のまま動かない (本体を繋がないため)。どこまで追えているかは
`headers to` を見る。

走査の結果は `<datadir>/light.scan` に残る。**再起動しても落とし直さない。**
`--watch` の中身を変えると、その場で最初から数え直す (変えたアドレスへの
入金を見落とさないため)。

`info` は**ノードを動かさずに**残高を読める。

### run — 記憶域を節約する

| | すること |
| --- | --- |
| `--prune [<blocks>]` | 直近のブロックだけ残す。既定 4320、最低 144 |
| `--prune-undo [<blocks>]` | 巻き戻し情報だけ落とす。既定 4320 |

`--prune` は**検証を弱めない**。UTXO セットは丸ごと残るので、新しい
ブロックの確かめ方は何も変わらない。手放すのは、古いブロックを他の人へ
配る能力と、その深さより深い再編成に自力で追従する能力である。

**シードや、人に同期先として使ってほしいノードには付けないこと。**
剪定したノードは `SERVICE_LIMITED` を名乗り、同期中の相手から繋ぎ先の
候補として外される。

`--index` `--explorer` `--wallet` とは併用できない。索引は本体を読んで
答えるためである。

### run — 索引と画面

| | すること |
| --- | --- |
| `--index` | 取引索引とアドレス索引を作る |
| `--drop-index` | 索引を捨てる |
| `--explorer [<addr>]` | エクスプローラ。既定 `127.0.0.1:8080` |
| `--wallet [<addr>]` | ブラウザのウォレット。既定 `127.0.0.1:25565` |
| `--tls-cert <path>` / `--tls-key <path>` | ウォレット画面の証明書 |

索引は**既定で作らない**。コンセンサスには要らず、満杯のブロックが続けば
年 37 GB を要する。`--explorer` と `--wallet` は索引に頼るので、付けると
暗黙に `--index` が付く。

ブラウザのウォレットは**署名がブラウザの中で終わる**。種も秘密鍵もノードに
渡らない。ループバック以外に開くときは証明書が要る。平文で配ったページは
差し替えられ、差し替えられたページは鍵をそのまま持っていく。

### run — RPC ほか

| | すること |
| --- | --- |
| `--rpc <addr>` | RPC を開く住所 |
| `--no-rpc` | RPC を開かない |
| `--assumevalid <hash>` | この高さ以下の署名検査を省く。`0` で無効 |
| `--exit-after <secs>` | 採掘を終えた後、この秒数で終了する |

RPC は cookie 認証である。`--datadir` の `.cookie` を読む。

`--assumevalid` は**確かめずに信じる設定**である。省くのは署名だけで、
PoW・merkle root・金額・二重使用・成熟・大きさは全部確かめる。

---

### 置きっぱなしにする (systemd)

`contrib/systemd/` に unit がある。優先度を下げて動かし、再起動で戻り、
止めるときは SIGTERM を送る。**軽量モードは SIGTERM で走査結果を書く**ので、
ここが噛み合っていないと止めるたびに数え直しになる。

```sh
sudo cp target/release/oag-node /usr/local/bin/
sudo cp contrib/systemd/oag-node.service /etc/systemd/system/
sudo cp contrib/systemd/oag-node.env /etc/default/oag-node   # 旗はここで選ぶ
sudo systemctl enable --now oag-node
journalctl -u oag-node -f
```

`--datadir` は unit 側が `/var/lib/oag-node` を渡す。それ以外の旗は
`/etc/default/oag-node` に書く。

**`MemoryDenyWriteExecute=yes` は足さないこと。** RandomX は実行時に
プログラムを組み立てるので、これを禁じると止まりはしないが黙って
インタプリタに落ちて 10 倍遅くなる。SELinux の `deny_execmem` も同じ。

## oag-wallet

| コマンド | すること |
| --- | --- |
| `new` | 財布を作る |
| `restore` | 復元語句から戻す |
| `seed` | 復元語句を表示する |
| `address` | 受取アドレスを出す |
| `balance` | 残高を見る |
| `send <宛先> <額>` | 送る |
| `consolidate` | 細かい UTXO をまとめる |
| `pst` | 部分署名取引 (PSBT 相当) |
| `info` | 繋いでいるノードの状態 |

共通の選択肢:

| | 既定 |
| --- | --- |
| `--network <net>` | `regtest` |
| `--wallet <path>` | `./wallet.json` |
| `--datadir <path>` | `./oag-data` (RPC cookie をここから読む) |
| `--rpc <addr>` | ループバックの RPC ポート |
| `--passphrase-file <path>` | 合言葉を入れたファイル |

**合言葉はコマンドラインから渡せない。** 引数は同じ機械の他の利用者から
プロセス一覧で見えるためである。指定しなければ端末で聞く。

### よく使うもの

```
oag-wallet new --network mainnet          # 作る。復元語句が出る
oag-wallet address --network mainnet      # 受け取る
oag-wallet address --new                  # 次のアドレスを出す
oag-wallet balance --verbose              # 内訳つきで見る
oag-wallet send <宛先> 1.5 --dry-run      # 送らずに中身だけ見る
oag-wallet send <宛先> 1.5                # 送る
```

**復元語句は一度しか出ない場面がある。** `new` の出力は必ず控える。
控えを取らずに閉じると、その財布は誰にも戻せない。

### sign / verify — アドレスの持ち主であることを示す

硬貨を動かさずに「このアドレスは自分のものだ」と言うための道具。シードノードの
名乗り、寄付先の告知、取引所への出金先の申告などに使う。

```sh
# 署名する (鍵が要る)
oag-wallet --network mainnet --wallet w.json sign --message 'Orange'

# 確かめる (鍵も財布もノードも要らない)
oag-wallet verify --address oag1... --signature <128桁の16進> --message 'Orange'
```

| | |
| --- | --- |
| `--message <text>` | 文字列そのもの。**末尾に改行を足さない** |
| `--file <path>` | ファイルの中身をバイト列としてそのまま。`-` で標準入力 |
| `--address <addr>` | `sign` では署名に使う鍵。既定は受取アドレス |

旗を何も付けなければ標準入力から読む。

**`verify` に `--network` は要らない。** どのネットワークのものかはアドレス自身が
名乗っている。合えば終了コード 0、合わなければ 1。

#### ブラウザからも使える

`--wallet` で開く画面にも同じものが載っている。**CLI で作った署名はブラウザで
通り、ブラウザで作った署名は CLI で通る**。どちらも同じ `oag-wallet` を呼んで
いるので、実装が二重になっていない。

- **署名** — 財布を開いた後の `Sign` タブ。押すと何に署名するのか一度出る
- **検証** — 錠前側の `Verify` タブ。**財布を開いていなくても使える**ので、
  ウォレットを持っていない人が貼られた署名をその場で確かめられる

検証を積んだぶん wasm は 791 KB から 2.0 MB になっている。増えた 1.3 MB は
secp256k1 の検証用テーブルで、**ブラウザ側はこれまで署名しかしていなかった**
ため入っていなかった。初回の読み込みだけで、あとはキャッシュに載る。

#### 取引の署名には絶対にならない

署名対象は `OAG/signedmessage` のタグ付きハッシュで、取引の `OAG/sighash` とは
別である。タグ付きハッシュは `tag || 0x00 || data` を BLAKE3 に通す前置符号なので、
**両者が同じ入力列になることはない**。

「メッセージに署名してください」と言って送金トランザクションの sighash を掴ませる、
という事故がこれで塞がる。

#### 本人確認に使うなら、確かめる側が文字列を決めること

署名が示すのは「**いつか**その鍵で署名した人がいる」ことだけである。固定文字列に
署名したものは、一度公開されれば誰でも複製して自分のものだと主張できる。

予測できない値を入れると、「その値を見た後に署名した」ことまで言える。

```
Orange OAG address proof | addr=oag1... | nonce=<乱数> | expires=<日時>
```

#### 確かめられないとき

改行が疑わしい。`--message` は改行を足さないが、ファイルやリダイレクトは足す。
Windows やチャットを経由すると LF が CRLF に書き換わる。どちらも `verify` が
気づいたときは指摘する。**ただし黙って直して通すことはしない** — 署名されたのは
手元のバイト列そのものであって、直したものではないからである。

### pst — 複数人で署名する

| | すること |
| --- | --- |
| `pst create` | 支払いを組んで書き出す。**署名しない** |
| `pst sign` | 自分の分の署名を足す |
| `pst combine` | 別々に署名されたものを 1 つにする |
| `pst show` | 中身を見る |
| `pst send` | 仕上げて送る |

---

## RPC

`--rpc` を開けると JSON-RPC で引ける。cookie 認証。

| 名前 | 引数 |
| --- | --- |
| `getinfo` | なし |
| `getblockcount` | なし |
| `getbestblockhash` | なし |
| `getblockhash` | `[高さ]` |
| `getblockheader` | `[ハッシュ]` |
| `getblock` | `[ハッシュ, 詳細=true]` |
| `getrawtransaction` | `[txid, 詳細=false]` |
| `getaddresshistory` | `[アドレス, 開始=0, 件数=100]` |
| `getindexinfo` | なし |
| `getmempool` | なし |
| `sendrawtransaction` | `[16進]` |
| `scanutxos` | `[[アドレス, …]]` |

`getrawtransaction` の確定分と `getaddresshistory` は索引を要る。
**索引が無いときは空の答えではなく誤りを返す。** 「見つからない」と
答えると、呼んだ側はそれを「その取引は無い」と受け取るためである。

```
cookie=$(cat ./oag-data/.cookie)
curl -s -u "$cookie" -X POST -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"getinfo","params":[]}' \
  http://127.0.0.1:9445/
```

---

## ポート

| | mainnet | testnet | regtest |
| --- | --- | --- | --- |
| P2P | 9444 | 19444 | 29444 |
| RPC | 9445 | 19445 | 29445 |
| 採掘 (予約) | 9446 | 19446 | 29446 |

9446 は採掘用インタフェースのために**取ってあるだけ**で、まだ何も待ち受けて
いない。開ける必要はない。

---

## 手元で試す

本番に触らずに動きを見たいときは regtest を使う。難易度 1 なので掘るのが
一瞬で終わる。

```
oag-node keygen --network regtest
oag-node run --network regtest --datadir ./tmp-data \
  --mine --payout <さっきのアドレス> --blocks 5 \
  --no-listen --no-discovery
oag-node info --network regtest --datadir ./tmp-data
```

---

より深い話は [`SPEC.md`](SPEC.md) にある。なぜそう決めたかまで書いてある。
