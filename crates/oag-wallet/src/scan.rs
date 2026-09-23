//! ブロックを走査して、自分の硬貨だけを追う。
//!
//! # 何のためにあるのか
//!
//! フルノードは UTXO セットを丸ごと持っている。財布はそこへ
//! `scanutxos` で聞けば残高が分かる ([`mod@crate::build`])。
//!
//! **UTXO セットを持たないノードには聞けない。** 軽量ノード
//! (ヘッダしか持たないノード) は、自分の硬貨を自分で数える必要がある。
//! ここがその部分である。
//!
//! # 何を信じているのか
//!
//! ここは**ブロックを受け取った後**の話しかしない。そのブロックが本物か
//! どうかは呼び出し側が決める。軽量ノードは、
//!
//! 1. ヘッダの連なりを集め、PoW を自分で検証する
//! 2. 中身をもらい、**merkle root を自分で計算し直す**
//! 3. 合っていたら、このモジュールに渡す
//!
//! という順で使う。2 を通しているので、**merkle proof は要らない**
//! (`docs/SPEC.md` §19)。proof が要るのは「中身を貰わずに済ませたい」
//! ときだけであり、貰っているなら root は自分で出せる。
//!
//! # 何を信じていないのか
//!
//! **相手がブロックを隠すことは防げない。** 見せられたものが正しいことは
//! 確かめられるが、見せられなかったものがあるかどうかは分からない。これは
//! 軽量ノードが構造上背負う性質であり、複数の相手から引くことで薄める。
//!
//! 隠されて困るのは「自分宛の入金に気づかない」である。**無い入金を
//! でっち上げられることはない。** ブロックのほうが嘘なら merkle root か
//! PoW で落ちる。

use oag_consensus::codec::{write_varint, CodecError, Decode, Encode, Reader};
use oag_consensus::lock::Lock;
use oag_consensus::tx::OutPoint;
use oag_consensus::{Block, Transaction};
use oag_primitives::{Amount, Hash};
use std::collections::{HashMap, HashSet};

/// 保存形式の版数。
///
/// 形が変わったら上げる。**古いものを読めてしまうほうが危ない。** 読めて
/// しまえば、意味の違う欄を黙って取り違えたまま残高を出すことになる。
const TRACKER_FORMAT: u8 = 1;

/// 保存した走査結果を読むときの誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TrackerError {
    /// 保存形式が違う。
    #[error(
        "the saved scan is format {found} but this build wants {expected}; \
             delete it and scan again"
    )]
    WrongFormat {
        /// 保存されていた版数。
        found: u8,
        /// この実装が読める版数。
        expected: u8,
    },
    /// バイト列が壊れている。
    #[error(transparent)]
    Codec(#[from] CodecError),
}

/// 自分のものだと分かっている未使用出力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedCoin {
    /// どの出力か。
    pub out_point: OutPoint,
    /// 金額。
    pub amount: Amount,
    /// 支払い条件。どの鍵で使えるかを見分けるために持つ。
    pub lock: Lock,
    /// 入っていたブロックの高さ。
    pub height: u64,
    /// コインベースか。**使えるようになるまで 120 ブロック待つ。**
    pub coinbase: bool,
}

impl OwnedCoin {
    /// この高さの時点で使えるか (コインベースの成熟, SPEC §10.6)。
    ///
    /// コインベース以外はいつでも使える。
    #[must_use]
    pub fn spendable_at(&self, height: u64) -> bool {
        if !self.coinbase {
            return true;
        }
        height.saturating_sub(self.height) >= oag_consensus::params::COINBASE_MATURITY
    }
}

/// 1 ブロック走査して分かったこと。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BlockChanges {
    /// 増えた硬貨。
    pub received: Vec<OwnedCoin>,
    /// 使われた硬貨。
    pub spent: Vec<OwnedCoin>,
}

impl BlockChanges {
    /// 何も起きなかったか。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.received.is_empty() && self.spent.is_empty()
    }
}

/// ブロックを 1 つ取り消して分かったこと。
///
/// [`CoinTracker::disconnect`] が返す。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rollback {
    /// このブロックで受け取っていた分。**手元から消えた。**
    pub undone: Vec<OwnedCoin>,
    /// このブロックで使われていた参照。
    ///
    /// **中身はここからは分からない** (別のブロックに入っている)。
    /// 自分のものだったかどうかも含めて、呼び出し側が引き直す。
    pub restore: Vec<OutPoint>,
}

impl Rollback {
    /// 自分に関わることが何も起きなかったか。
    ///
    /// `restore` は自分のものとは限らないので数に入れない。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.undone.is_empty()
    }
}

/// 自分の硬貨だけを持つ、小さな UTXO セット。
///
/// # なぜ全部を持たないのか
///
/// 全部持てばフルノードである。持たないから軽いのであって、**軽さと
/// 「他人の取引を検証できること」は同時に手に入らない。**
///
/// ここが持つのは、自分が見張っている `Lock` に触れた分だけである。
/// 高さに比例しては伸びない。自分の受け取り回数に比例して伸びる。
///
/// # 巻き戻し
///
/// 再編成では、取り消されたブロックを逆順に [`disconnect`](Self::disconnect)
/// へ渡す。**`connect` に渡したのと同じブロックでなければならない。**
/// 軽量ノードは本体を保存しないので、取り消しに備えて直近の数ブロック分は
/// 手元に置いておくか、取り消しが起きたらそこから引き直す。
#[derive(Debug, Clone, Default)]
pub struct CoinTracker {
    /// 見張っている支払い条件。
    watched: HashSet<Lock>,
    /// 持っている硬貨。
    coins: HashMap<OutPoint, OwnedCoin>,
    /// どの高さまで見たか。まだ何も見ていなければ `None`。
    scanned_to: Option<u64>,
}

impl CoinTracker {
    /// 空の追跡器を作る。
    #[must_use]
    pub fn new() -> CoinTracker {
        CoinTracker::default()
    }

    /// 見張る支払い条件を足す。
    ///
    /// **走査を始める前に足しておくこと。** 後から足しても、既に通り過ぎた
    /// ブロックは見直さない。足りなければ [`rescan_from`](Self::rescan_from)
    /// で戻す。
    pub fn watch(&mut self, lock: Lock) {
        self.watched.insert(lock);
    }

    /// 見張っている条件の数。
    #[must_use]
    pub fn watched_len(&self) -> usize {
        self.watched.len()
    }

    /// この条件を見張っているか。
    #[must_use]
    pub fn watches(&self, lock: &Lock) -> bool {
        self.watched.contains(lock)
    }

    /// どの高さまで見たか。
    #[must_use]
    pub fn scanned_to(&self) -> Option<u64> {
        self.scanned_to
    }

    /// 走査済みの印をこの高さの手前まで戻す。
    ///
    /// 硬貨は消さない。**後から見張る条件を足したときに使う。** 呼んだ側が
    /// その高さから順に `connect` をやり直す。
    pub fn rescan_from(&mut self, height: u64) {
        self.scanned_to = height.checked_sub(1);
    }

    /// 持っている硬貨をすべて。
    pub fn coins(&self) -> impl Iterator<Item = &OwnedCoin> {
        self.coins.values()
    }

    /// 持っている硬貨の数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.coins.len()
    }

    /// 1 枚も持っていないか。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.coins.is_empty()
    }

    /// 合計。**成熟していないコインベースを含む。**
    ///
    /// 手元にある額であって、いま使える額ではない。使える分は
    /// [`spendable`](Self::spendable) が答える。
    ///
    /// 溢れたら `None`。**黙って丸めない** (SPEC §3)。発行上限が
    /// 10 億 OAG なので現実には起きないが、起きたときに嘘の残高を
    /// 見せるくらいなら答えないほうがよい。
    #[must_use]
    pub fn total(&self) -> Option<Amount> {
        Amount::sum(self.coins.values().map(|c| c.amount))
    }

    /// この高さで実際に使える合計。
    ///
    /// **120 ブロック経っていないコインベースを外す。** 外さずに見せると、
    /// 送ろうとして初めて断られることになる (SPEC §10.6)。
    #[must_use]
    pub fn spendable(&self, height: u64) -> Option<Amount> {
        Amount::sum(
            self.coins
                .values()
                .filter(|c| c.spendable_at(height))
                .map(|c| c.amount),
        )
    }

    /// ブロックを 1 つ進める。
    ///
    /// **使われた分を先に引き、受け取った分を後から足す。** 同じブロックの
    /// 中で受け取ってすぐ使う取引があるので、順序が要る。逆にすると、
    /// 足す前に引こうとして取りこぼす。
    pub fn connect(&mut self, block: &Block) -> BlockChanges {
        let height = block.header.height;
        let mut changes = BlockChanges::default();

        for tx in &block.transactions {
            // 入力側。コインベースの入力は既存の出力を指していない。
            if !tx.is_coinbase() {
                for input in &tx.inputs {
                    if let Some(coin) = self.coins.remove(&input.prev_out) {
                        changes.spent.push(coin);
                    }
                }
            }
            // 出力側。
            self.take_outputs(tx, height, &mut changes.received);
        }

        self.scanned_to = Some(height);
        changes
    }

    /// ブロックを 1 つ巻き戻す。
    ///
    /// `connect` に渡したのと同じブロックを渡す。順序は connect の逆で
    /// ある。
    ///
    /// # 使われた分をここでは戻せない
    ///
    /// 取り消すブロックの入力が指している出力は、**別のブロックに入って
    /// いる。** 手元にあるのは取り消すブロックだけなので、金額も支払い
    /// 条件もここからは分からない。
    ///
    /// だから戻すのではなく、[`Rollback::restore`] に参照だけを並べて返す。
    /// **偽の金額を置いて辻褄を合わせない。** 合わせると、残高は正しく
    /// 見えるのに使おうとすると通らない硬貨が生まれる。
    ///
    /// 呼び出し側は、その参照を含むブロックを引き直して `connect` し直すか、
    /// [`rescan_from`](Self::rescan_from) で分岐点まで戻してやり直す。
    /// 後者のほうが確実で、軽量ノードにとっては安い。
    pub fn disconnect(&mut self, block: &Block) -> Rollback {
        let height = block.header.height;
        let mut out = Rollback::default();

        for tx in block.transactions.iter().rev() {
            // 出力側を消す。**このブロックで受け取った分だけが消える。**
            let mut txid: Option<Hash> = None;
            for index in (0..tx.outputs.len()).rev() {
                let id = *txid.get_or_insert_with(|| tx.txid());
                let out_point = OutPoint::new(id, index as u32);
                if let Some(coin) = self.coins.remove(&out_point) {
                    out.undone.push(coin);
                }
            }
            // 入力側は参照だけ控える。
            if !tx.is_coinbase() {
                out.restore.extend(tx.inputs.iter().map(|i| i.prev_out));
            }
        }

        self.scanned_to = height.checked_sub(1);
        out
    }

    /// 走査の結果をバイト列にする。
    ///
    /// # なぜ保存するのか
    ///
    /// 保存しないと、**起動のたびにチェーンを丸ごと落とし直す。** 置いた
    /// まま動かしておきたい人にとって、これが一番の負担になる。再起動が
    /// 再同期を意味するなら、誰も置きっぱなしにしない。
    ///
    /// # 見張る条件も一緒に入れる
    ///
    /// 読み戻すときに、前回と同じ条件を見張っているかを確かめるためで
    /// ある。違っていれば走査をやり直さなければならない。**黙って続きから
    /// 数えると、足したアドレスへの入金が永久に抜け落ちる。**
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(TRACKER_FORMAT);
        // 見張る条件。**順序を決めてから書く。** HashSet の並びは走るたびに
        // 変わるので、同じ状態から同じバイト列が出ない。
        let mut watched: Vec<Vec<u8>> = self.watched.iter().map(|l| l.encode()).collect();
        watched.sort_unstable();
        write_varint(watched.len() as u128, &mut out);
        for lock in &watched {
            out.extend_from_slice(lock);
        }
        // 硬貨。こちらも高さと参照で並べておく。
        let mut coins: Vec<&OwnedCoin> = self.coins.values().collect();
        coins.sort_unstable_by_key(|c| (c.height, c.out_point.index, c.out_point.txid));
        write_varint(coins.len() as u128, &mut out);
        for coin in coins {
            coin.out_point.encode_into(&mut out);
            coin.amount.encode_into(&mut out);
            coin.lock.encode_into(&mut out);
            write_varint(u128::from(coin.height), &mut out);
            out.push(u8::from(coin.coinbase));
        }
        // どこまで見たか。**まだなら 0、見たなら高さ + 1** として書く。
        // 「高さ 0 まで見た」と「まだ見ていない」を区別する必要がある。
        write_varint(u128::from(self.scanned_to.map_or(0, |h| h + 1)), &mut out);
        out
    }

    /// [`encode`](Self::encode) の逆。
    ///
    /// **形式が違うものは読まない。** 読めてしまうほうが危ない。
    pub fn decode(buf: &[u8]) -> Result<CoinTracker, TrackerError> {
        let mut reader = Reader::new(buf);
        let format = reader.read_u8()?;
        if format != TRACKER_FORMAT {
            return Err(TrackerError::WrongFormat {
                found: format,
                expected: TRACKER_FORMAT,
            });
        }

        let watched_count = reader.read_count_of("tracker.watched", Lock::MIN_ENCODED_LEN)?;
        let mut watched = HashSet::with_capacity(watched_count);
        for _ in 0..watched_count {
            watched.insert(Lock::read_from(&mut reader)?);
        }

        let coin_len = OutPoint::MIN_ENCODED_LEN + 1 + Lock::MIN_ENCODED_LEN + 1 + 1;
        let coin_count = reader.read_count_of("tracker.coins", coin_len)?;
        let mut coins = HashMap::with_capacity(coin_count);
        for _ in 0..coin_count {
            let out_point = OutPoint::read_from(&mut reader)?;
            let amount = reader.read_amount()?;
            let lock = Lock::read_from(&mut reader)?;
            let height = reader.read_varint_u64("tracker.coin.height")?;
            let coinbase = reader.read_u8()? != 0;
            coins.insert(
                out_point,
                OwnedCoin {
                    out_point,
                    amount,
                    lock,
                    height,
                    coinbase,
                },
            );
        }

        let scanned_to = reader.read_varint_u64("tracker.scanned_to")?.checked_sub(1);
        reader.finish()?;

        Ok(CoinTracker {
            watched,
            coins,
            scanned_to,
        })
    }

    /// 見張っている条件が `locks` とぴったり同じか。
    ///
    /// **違っていたら続きから数えてはならない。** 足したアドレスへの入金が
    /// 永久に抜け落ちる。呼び出し側は走査をやり直す。
    pub fn watches_exactly(&self, locks: &[Lock]) -> bool {
        self.watched.len() == locks.len() && locks.iter().all(|l| self.watched.contains(l))
    }

    /// 出力のうち、自分宛のものを拾う。
    fn take_outputs(&mut self, tx: &Transaction, height: u64, into: &mut Vec<OwnedCoin>) {
        let coinbase = tx.is_coinbase();
        let mut txid: Option<Hash> = None;
        for (index, output) in tx.outputs.iter().enumerate() {
            if !self.watched.contains(&output.lock) {
                continue;
            }
            // txid は必要になって初めて計算する。**大半の取引は自分宛では
            // ない。** 走査するのは全ブロックなので、ここが効く。
            let id = *txid.get_or_insert_with(|| tx.txid());
            let coin = OwnedCoin {
                out_point: OutPoint::new(id, index as u32),
                amount: output.amount,
                lock: output.lock.clone(),
                height,
                coinbase,
            };
            self.coins.insert(coin.out_point, coin.clone());
            into.push(coin);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_consensus::params;
    use oag_consensus::tx::{encode_coinbase_signature, TxInput, CURRENT_TX_VERSION};
    use oag_consensus::{BlockHeader, TxOutput};
    use oag_primitives::merkle;
    use oag_primitives::SecretKey;

    /// 使い捨ての支払い条件。
    fn lock() -> Lock {
        Lock::pay_to_pubkey(&SecretKey::generate().public_key())
    }

    fn coinbase(height: u64, to: &Lock) -> Transaction {
        let mut input = TxInput::new(OutPoint::null());
        input.signature = encode_coinbase_signature(height, &height.to_le_bytes());
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![input],
            outputs: vec![TxOutput::new(params::block_subsidy(height), to.clone())],
            locktime: 0,
        }
    }

    /// `prev` を使って `outs` へ払う取引。署名は確かめないので空でよい。
    fn spend(prev: OutPoint, outs: &[(Amount, Lock)]) -> Transaction {
        Transaction {
            version: CURRENT_TX_VERSION,
            inputs: vec![TxInput::new(prev)],
            outputs: outs
                .iter()
                .map(|(a, l)| TxOutput::new(*a, l.clone()))
                .collect(),
            locktime: 0,
        }
    }

    fn block(height: u64, txs: Vec<Transaction>) -> Block {
        let ids: Vec<_> = txs.iter().map(|t| t.txid()).collect();
        Block {
            header: BlockHeader {
                version: 0,
                prev_hash: Hash::ZERO,
                merkle_root: merkle::merkle_root(&ids).expect("there is at least one"),
                timestamp: 1_800_000_000 + height as i64 * 60,
                difficulty: 1,
                height,
                nonce: 0,
            },
            transactions: txs,
        }
    }

    fn oag(n: u64) -> Amount {
        Amount::from_atomic(u128::from(n) * 10_000_000_000_000_000).expect("well under the cap")
    }

    // ━━━━━━━━ 拾う ━━━━━━━━

    #[test]
    fn a_payment_to_a_watched_lock_is_picked_up() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let changes = t.connect(&block(1, vec![coinbase(1, &mine)]));
        assert_eq!(changes.received.len(), 1);
        assert_eq!(t.len(), 1);
        assert_eq!(t.total().unwrap(), params::block_subsidy(1));
    }

    #[test]
    fn everybody_elses_money_is_ignored() {
        // **これが軽さの正体である。** 自分の分だけ持つから、高さに比例して
        // 伸びない。
        let mut t = CoinTracker::new();
        t.watch(lock());

        let changes = t.connect(&block(1, vec![coinbase(1, &lock())]));
        assert!(changes.is_empty());
        assert!(t.is_empty());
        assert_eq!(t.total().unwrap(), Amount::ZERO);
    }

    #[test]
    fn watching_nothing_finds_nothing() {
        let mut t = CoinTracker::new();
        assert!(t.connect(&block(1, vec![coinbase(1, &lock())])).is_empty());
        assert_eq!(t.watched_len(), 0);
    }

    #[test]
    fn several_outputs_in_one_transaction_all_count() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let cb = coinbase(1, &lock());
        let tx = spend(
            OutPoint::new(cb.txid(), 0),
            &[(oag(3), mine.clone()), (oag(4), lock()), (oag(2), mine)],
        );
        let changes = t.connect(&block(1, vec![cb, tx]));
        assert_eq!(changes.received.len(), 2, "two of the three were ours");
        assert_eq!(t.total().unwrap(), oag(5));
    }

    // ━━━━━━━━ 使う ━━━━━━━━

    #[test]
    fn spending_our_own_coin_removes_it() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let cb = coinbase(1, &mine);
        t.connect(&block(1, vec![cb.clone()]));
        assert_eq!(t.len(), 1);

        let tx = spend(OutPoint::new(cb.txid(), 0), &[(oag(1), lock())]);
        let changes = t.connect(&block(2, vec![coinbase(2, &lock()), tx]));
        assert_eq!(changes.spent.len(), 1);
        assert!(t.is_empty(), "the coin was spent but is still counted");
        assert_eq!(t.total().unwrap(), Amount::ZERO);
    }

    #[test]
    fn receiving_and_spending_inside_one_block_nets_out() {
        // **引いてから足すのでは取りこぼす。** 同じブロックの中で受け取って
        // すぐ使う取引があるので、順序がここで効く。
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let cb = coinbase(1, &lock());
        let to_me = spend(OutPoint::new(cb.txid(), 0), &[(oag(5), mine.clone())]);
        let away = spend(OutPoint::new(to_me.txid(), 0), &[(oag(4), lock())]);

        let changes = t.connect(&block(1, vec![cb, to_me, away]));
        assert_eq!(changes.received.len(), 1);
        assert_eq!(changes.spent.len(), 1);
        assert!(t.is_empty(), "it was received and spent in the same block");
    }

    #[test]
    fn a_coinbase_input_is_not_treated_as_a_spend() {
        // コインベースの入力は null を指している。既存の出力ではない。
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());
        t.connect(&block(1, vec![coinbase(1, &mine)]));
        let before = t.len();
        t.connect(&block(2, vec![coinbase(2, &lock())]));
        assert_eq!(t.len(), before);
    }

    // ━━━━━━━━ 成熟 ━━━━━━━━

    #[test]
    fn a_fresh_coinbase_is_held_but_not_spendable() {
        // **見せる額と使える額を分ける。** 分けずに見せると、送ろうとして
        // 初めて断られる (SPEC §10.6)。
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());
        t.connect(&block(1, vec![coinbase(1, &mine)]));

        assert_eq!(t.total().unwrap(), params::block_subsidy(1));
        assert_eq!(t.spendable(1).unwrap(), Amount::ZERO);
        assert_eq!(
            t.spendable(1 + params::COINBASE_MATURITY - 1).unwrap(),
            Amount::ZERO
        );
        assert_eq!(
            t.spendable(1 + params::COINBASE_MATURITY).unwrap(),
            params::block_subsidy(1),
            "it should be spendable exactly at the maturity depth"
        );
    }

    #[test]
    fn an_ordinary_payment_is_spendable_at_once() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let cb = coinbase(1, &lock());
        let tx = spend(OutPoint::new(cb.txid(), 0), &[(oag(7), mine)]);
        t.connect(&block(5, vec![cb, tx]));
        assert_eq!(t.spendable(5).unwrap(), oag(7));
    }

    // ━━━━━━━━ 保存と読み戻し ━━━━━━━━

    #[test]
    fn a_saved_scan_comes_back_the_same() {
        let mine = lock();
        let other = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());
        t.watch(other.clone());

        let cb = coinbase(1, &mine);
        t.connect(&block(1, vec![cb.clone()]));
        let tx = spend(
            OutPoint::new(cb.txid(), 0),
            &[(oag(3), other.clone()), (oag(2), lock())],
        );
        t.connect(&block(2, vec![coinbase(2, &lock()), tx]));

        let back = CoinTracker::decode(&t.encode()).unwrap();
        assert_eq!(back.len(), t.len());
        assert_eq!(back.total().unwrap(), t.total().unwrap());
        assert_eq!(back.scanned_to(), t.scanned_to());
        assert_eq!(back.watched_len(), 2);
        assert!(back.watches(&mine) && back.watches(&other));
        // 硬貨の中身まで一致すること。金額だけ合っていても使えない。
        let mut a: Vec<&OwnedCoin> = t.coins().collect();
        let mut b: Vec<&OwnedCoin> = back.coins().collect();
        a.sort_unstable_by_key(|c| (c.height, c.out_point.index));
        b.sort_unstable_by_key(|c| (c.height, c.out_point.index));
        assert_eq!(a, b);
    }

    #[test]
    fn an_empty_scan_survives_the_trip() {
        let t = CoinTracker::new();
        let back = CoinTracker::decode(&t.encode()).unwrap();
        assert!(back.is_empty());
        assert_eq!(back.scanned_to(), None);
        assert_eq!(back.watched_len(), 0);
    }

    #[test]
    fn having_scanned_the_genesis_is_not_the_same_as_having_scanned_nothing() {
        // **ここを 0 で潰すと、毎回ジェネシスを見直すか、見ていない
        // ブロックを見たことにするかのどちらかになる。**
        let mut t = CoinTracker::new();
        t.connect(&block(0, vec![coinbase(0, &lock())]));
        assert_eq!(t.scanned_to(), Some(0));
        assert_eq!(
            CoinTracker::decode(&t.encode()).unwrap().scanned_to(),
            Some(0)
        );

        let fresh = CoinTracker::new();
        assert_eq!(fresh.scanned_to(), None);
        assert_eq!(
            CoinTracker::decode(&fresh.encode()).unwrap().scanned_to(),
            None
        );
    }

    #[test]
    fn the_same_state_always_writes_the_same_bytes() {
        // HashSet と HashMap の並びは走るたびに変わる。並べてから書かないと、
        // 中身が同じでもファイルが毎回書き換わる。
        let mine = lock();
        let mut t = CoinTracker::new();
        for _ in 0..8 {
            t.watch(lock());
        }
        t.watch(mine.clone());
        for h in 1..6u64 {
            t.connect(&block(h, vec![coinbase(h, &mine)]));
        }
        let once = t.encode();
        let twice = CoinTracker::decode(&once).unwrap().encode();
        assert_eq!(once, twice, "the same state wrote different bytes");
    }

    #[test]
    fn a_different_format_is_refused() {
        let t = CoinTracker::new();
        let mut bytes = t.encode();
        bytes[0] = TRACKER_FORMAT + 1;
        assert!(matches!(
            CoinTracker::decode(&bytes),
            Err(TrackerError::WrongFormat { .. })
        ));
    }

    #[test]
    fn a_truncated_save_is_refused() {
        // 途中で電源が落ちた書きかけを、黙って半分だけ読まない。
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());
        t.connect(&block(1, vec![coinbase(1, &mine)]));
        let bytes = t.encode();
        assert!(CoinTracker::decode(&bytes[..bytes.len() - 3]).is_err());
    }

    #[test]
    fn trailing_rubbish_is_refused() {
        let mut bytes = CoinTracker::new().encode();
        bytes.push(0xff);
        assert!(CoinTracker::decode(&bytes).is_err());
    }

    #[test]
    fn a_saved_scan_can_tell_whether_the_watch_list_changed() {
        // **ここが緩いと、足したアドレスへの入金が永久に抜け落ちる。**
        // 続きから数えてよいかどうかは、これで決まる。
        let a = lock();
        let b = lock();
        let mut t = CoinTracker::new();
        t.watch(a.clone());
        t.watch(b.clone());

        assert!(t.watches_exactly(&[a.clone(), b.clone()]));
        assert!(
            t.watches_exactly(&[b.clone(), a.clone()]),
            "order should not matter"
        );
        // 足された。やり直しが要る。
        assert!(!t.watches_exactly(&[a.clone(), b.clone(), lock()]));
        // 減らされた。これも続きからでは答えが変わる。
        assert!(!t.watches_exactly(std::slice::from_ref(&a)));
        // 入れ替わった。数は同じでも別物である。
        assert!(!t.watches_exactly(&[a, lock()]));
    }

    #[test]
    fn a_resumed_scan_keeps_counting_from_where_it_stopped() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());
        t.connect(&block(1, vec![coinbase(1, &mine)]));

        // 落として、読み戻して、続ける。
        let mut back = CoinTracker::decode(&t.encode()).unwrap();
        assert_eq!(back.scanned_to(), Some(1));
        back.connect(&block(2, vec![coinbase(2, &mine)]));

        assert_eq!(back.len(), 2);
        assert_eq!(back.scanned_to(), Some(2));
        // 続けて走査した分と、止めずに走査した分が一致すること。
        t.connect(&block(2, vec![coinbase(2, &mine)]));
        assert_eq!(back.total().unwrap(), t.total().unwrap());
    }

    // ━━━━━━━━ 巻き戻し ━━━━━━━━

    #[test]
    fn disconnecting_takes_back_what_that_block_gave_us() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let b = block(1, vec![coinbase(1, &mine)]);
        t.connect(&b);
        assert_eq!(t.len(), 1);

        let back = t.disconnect(&b);
        assert_eq!(back.undone.len(), 1);
        assert!(t.is_empty(), "the reorged-away coinbase is still counted");
        // 高さ 1 を取り消したので、見終わっているのは高さ 0 までである。
        assert_eq!(t.scanned_to(), Some(0));
    }

    #[test]
    fn disconnecting_reports_what_it_cannot_put_back() {
        // **偽の金額を置いて辻褄を合わせない。** 使った先の出力は別の
        // ブロックにあるので、ここからは金額も lock も分からない。
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let cb = coinbase(1, &mine);
        t.connect(&block(1, vec![cb.clone()]));
        let prev = OutPoint::new(cb.txid(), 0);
        let tx = spend(prev, &[(oag(1), lock())]);
        let b2 = block(2, vec![coinbase(2, &lock()), tx]);
        t.connect(&b2);
        assert!(t.is_empty());

        let back = t.disconnect(&b2);
        assert!(back.undone.is_empty(), "we received nothing in that block");
        assert!(
            back.restore.contains(&prev),
            "the spend was not reported as needing a re-scan"
        );
        // **黙って戻さない。** 引き直すのは呼び出し側である。
        assert!(t.is_empty());
    }

    #[test]
    fn connect_and_disconnect_return_to_where_we_started() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());

        let b1 = block(1, vec![coinbase(1, &mine)]);
        let b2 = block(2, vec![coinbase(2, &mine)]);
        t.connect(&b1);
        t.connect(&b2);
        assert_eq!(t.len(), 2);
        assert_eq!(t.scanned_to(), Some(2));

        t.disconnect(&b2);
        assert_eq!(t.len(), 1, "only block 2's coinbase should have gone");
        assert_eq!(t.scanned_to(), Some(1));
        assert_eq!(t.total().unwrap(), params::block_subsidy(1));
    }

    // ━━━━━━━━ 走査の進み ━━━━━━━━

    #[test]
    fn the_scanned_height_follows_the_blocks() {
        let mut t = CoinTracker::new();
        assert_eq!(t.scanned_to(), None);
        t.connect(&block(0, vec![coinbase(0, &lock())]));
        assert_eq!(t.scanned_to(), Some(0));
        t.connect(&block(1, vec![coinbase(1, &lock())]));
        assert_eq!(t.scanned_to(), Some(1));
    }

    #[test]
    fn a_lock_added_later_needs_a_rescan() {
        // **後から足しても、通り過ぎたブロックは見直さない。** 黙って
        // 見つからないより、見直しが要ると分かるほうがよい。
        let late = lock();
        let mut t = CoinTracker::new();
        let b = block(7, vec![coinbase(7, &late)]);
        t.connect(&b);
        assert!(t.is_empty());

        t.watch(late.clone());
        assert!(t.is_empty(), "adding a lock must not conjure up old coins");

        t.rescan_from(7);
        assert_eq!(t.scanned_to(), Some(6), "the mark should have gone back");
        t.connect(&b);
        assert_eq!(t.len(), 1, "the rescan did not find it");
    }

    #[test]
    fn watching_the_same_lock_twice_is_harmless() {
        let mine = lock();
        let mut t = CoinTracker::new();
        t.watch(mine.clone());
        t.watch(mine.clone());
        assert_eq!(t.watched_len(), 1);
        assert!(t.watches(&mine));

        let changes = t.connect(&block(1, vec![coinbase(1, &mine)]));
        assert_eq!(changes.received.len(), 1, "it was counted twice");
        assert_eq!(t.len(), 1);
    }
}
