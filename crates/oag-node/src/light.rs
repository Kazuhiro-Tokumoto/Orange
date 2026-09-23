//! 軽量モード。ヘッダを自分で検証し、本体は走査して捨てる。
//!
//! # 何をしないのか
//!
//! UTXO セットを持たない。mempool も索引も持たない。採掘も中継もしない。
//! **持たないから軽いのであって、軽さと「他人の取引を検証できること」は
//! 同時に手に入らない。**
//!
//! # 何を自分で確かめるのか
//!
//! 預けるのは「見せられなかったものがあるか」だけである。見せられたものは
//! 全部自分で確かめる。
//!
//! 1. **ヘッダ** — PoW・難易度・時刻・親の繋がり。[`Chain::accept_header`]
//!    が通常のノードとまったく同じ検査をする
//! 2. **本体がそのヘッダのものか** — マークルルートを自分で計算し直す
//!
//! この 2 つで「このブロックは、この作業量に裏打ちされた鎖の上にあり、
//! 中身はヘッダが約束したとおりのものである」が言える。
//!
//! **merkle proof は要らない** (`docs/SPEC.md` §19)。proof が要るのは
//! 本体を貰わずに済ませたいときだけで、貰っているならルートは自分で出せる。
//!
//! # 何を預けるのか
//!
//! **ブロックを隠されることは防げない。** 相手が「そんなブロックは無い」
//! と言い続ければ、自分宛の入金に気づかない。複数の相手から引くことで
//! 薄めるしかない。
//!
//! 逆向きは起きない。**無い入金をでっち上げられることはない。** 嘘の
//! ブロックはマークルルートか PoW で落ちる。
//!
//! [`Chain::accept_header`]: oag_chain::Chain::accept_header

use oag_chain::store::ChainStore;
use oag_chain::{Chain, ChainError};
use oag_consensus::lock::Lock;
use oag_consensus::Block;
use oag_primitives::Hash;
use oag_wallet::scan::{BlockChanges, CoinTracker};
use std::collections::BTreeMap;

/// 順番待ちにしておく本体の上限。
///
/// 本体は複数の相手に振り分けて頼むので、順番どおりには届かない。
/// **届いた順に走査できない**ので、穴が埋まるまで手元に置く。
///
/// 置ける数に蓋をするのは、**穴の手前をわざと送らない相手がいたときに
/// 無限に溜まらないようにする**ためである。蓋に達したら、それ以上は
/// 受け取らずに捨てて頼み直す。
const MAX_PENDING: usize = 256;

/// 軽量モードで起きうる誤り。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LightError {
    /// 知らないヘッダの本体が届いた。
    ///
    /// **頼んでいないものを受け取らない。** ヘッダを検証していない以上、
    /// PoW の裏打ちがあるかどうかを知らない。
    #[error("the body of block {0} arrived without its header having been verified")]
    UnknownHeader(Hash),
    /// 本体がヘッダのマークルルートと合わない。
    ///
    /// **軽量ノードが自分で確かめられる、ほぼ唯一のことである。**
    #[error("the body of block {0} does not match the merkle root in its header")]
    MerkleMismatch(Hash),
    /// チェーンの読み取りに失敗した。
    #[error(transparent)]
    Chain(#[from] ChainError),
}

/// 1 ブロック走査した結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    /// どのブロックか。
    pub hash: Hash,
    /// 高さ。
    pub height: u64,
    /// 自分の硬貨に起きたこと。
    pub changes: BlockChanges,
}

/// 保存されたバイト列から、走査済みの高さだけを読む。
///
/// 再開する位置をチェーンから引き直すために要る。**全部を復号する前に
/// 高さだけ要る**ので、ここだけを覗く。読めなければ `None`。
#[must_use]
pub fn saved_height(saved: &[u8]) -> Option<u64> {
    CoinTracker::decode(saved).ok()?.scanned_to()
}

/// 軽量モードの状態。
///
/// ヘッダの木は [`Chain`] が持っている。ここが持つのは「どこまで走査したか」
/// と「自分の硬貨」だけである。
pub struct LightNode {
    tracker: CoinTracker,
    /// 直近に走査し終えたブロック。ここから前へ辿る。
    cursor: Hash,
    /// 順番待ちの本体。高さ順。
    pending: BTreeMap<u64, Block>,
}

impl LightNode {
    /// ジェネシスから始める。
    ///
    /// `watch` は見張る支払い条件。**走査を始める前に渡しきること。**
    /// 後から足したものは、通り過ぎたブロックには適用されない。
    pub fn new(genesis: Hash, watch: impl IntoIterator<Item = Lock>) -> LightNode {
        let mut tracker = CoinTracker::new();
        for lock in watch {
            tracker.watch(lock);
        }
        LightNode {
            tracker,
            cursor: genesis,
            pending: BTreeMap::new(),
        }
    }

    /// 自分の硬貨。
    pub fn tracker(&self) -> &CoinTracker {
        &self.tracker
    }

    /// 直近に走査し終えたブロック。
    pub fn cursor(&self) -> Hash {
        self.cursor
    }

    /// 順番待ちの数。
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// 次に頼むべき本体を、古い順に最大 `max` 件。
    ///
    /// # なぜ子から辿るのか
    ///
    /// 高さから引く索引はアクティブチェーンのものであり、**軽量モードでは
    /// ジェネシスから動かない** (本体を繋がないため)。使えない。
    ///
    /// 代わりに親子の表を前へ辿る。分岐していなければ子は 1 つで、1 歩が
    /// 1 回の引き当てで済む。分岐しているところだけ、どちらの枝かを
    /// [`Chain::ancestor_hash_at`] で確かめる。**滅多に起きない。**
    pub fn wanted<S: ChainStore>(
        &self,
        chain: &Chain<S>,
        max: usize,
    ) -> Result<Vec<Hash>, LightError> {
        let tip = chain.best_header()?;
        let mut out = Vec::new();
        let mut cursor = self.cursor;
        let mut height = match chain.entry(&cursor)? {
            Some(entry) => entry.height(),
            // 追っていた枝ごと消えた。呼び出し側が引き直す。
            None => return Ok(Vec::new()),
        };

        while out.len() < max && height < tip.height() {
            let children = chain
                .store()
                .children_of(&cursor)
                .map_err(|e| ChainError::Store(e.to_string()))?;
            let next = match children.len() {
                // 先端まで来た。
                0 => break,
                1 => children[0],
                // 分岐している。どちらが先端側かを確かめる。
                _ => match chain.ancestor_hash_at(&tip.hash, height + 1)? {
                    Some(hash) => hash,
                    None => break,
                },
            };
            // 順番待ちに既にあるものは頼まない。
            height += 1;
            if !self.pending.contains_key(&height) {
                out.push(next);
            }
            cursor = next;
        }
        Ok(out)
    }

    /// 届いた本体を受け取る。
    ///
    /// 確かめてから順番待ちに入れ、繋がるところまで走査して返す。届いた順が
    /// 高さの順とは限らないので、**穴が埋まるまでは走査しない。**
    ///
    /// # 誤り
    ///
    /// ヘッダを知らないもの ([`LightError::UnknownHeader`]) と、マークル
    /// ルートが合わないもの ([`LightError::MerkleMismatch`]) は断る。
    /// **断ったものは順番待ちに入れない。**
    pub fn offer<S: ChainStore>(
        &mut self,
        block: Block,
        chain: &Chain<S>,
    ) -> Result<Vec<Scanned>, LightError> {
        let hash = block.header.hash();

        // 1. このヘッダを検証済みか。**頼んでいないものを受け取らない。**
        let entry = chain.entry(&hash)?.ok_or(LightError::UnknownHeader(hash))?;

        // 2. 本体がそのヘッダのものか。**ここが軽量ノードの検証の要である。**
        if !block.merkle_root_is_valid() {
            return Err(LightError::MerkleMismatch(hash));
        }

        // 蓋に達していたら受け取らない。穴の手前を送らない相手がいても
        // 無限には溜まらない。
        let height = entry.height();
        if self.pending.len() >= MAX_PENDING && !self.pending.contains_key(&height) {
            return Ok(Vec::new());
        }
        self.pending.insert(height, block);

        Ok(self.drain(chain)?)
    }

    /// 繋がるところまで走査する。
    fn drain<S: ChainStore>(&mut self, chain: &Chain<S>) -> Result<Vec<Scanned>, ChainError> {
        let mut out = Vec::new();
        while let Some(entry) = chain.entry(&self.cursor)? {
            let next_height = entry.height() + 1;
            let Some(block) = self.pending.get(&next_height) else {
                break;
            };
            // **親が繋がっていることを必ず確かめる。** 高さだけで繋ぐと、
            // 別の枝の同じ高さを掴む。
            if block.header.prev_hash != self.cursor {
                break;
            }
            let block = self
                .pending
                .remove(&next_height)
                .expect("just looked it up");
            let hash = block.header.hash();
            let changes = self.tracker.connect(&block);
            self.cursor = hash;
            out.push(Scanned {
                hash,
                height: next_height,
                changes,
            });
            // 本体はここで落ちる。**保存しない。** それが軽量モードである。
        }
        Ok(out)
    }

    /// 保存してあった走査結果から起こす。
    ///
    /// `watch` が前回と違えば、**保存を捨ててジェネシスからやり直す。**
    /// 続きから数えると、足したアドレスへの入金が永久に抜け落ちる。
    /// 減らした場合も、残っている硬貨がどこから来たのか辻褄が合わなくなる。
    ///
    /// 読めなかったときも作り直す。**読めない保存を黙って半分使わない。**
    /// 理由は `note` に入れて返す。
    pub fn restore(
        saved: &[u8],
        genesis: Hash,
        cursor: Hash,
        watch: Vec<Lock>,
    ) -> (LightNode, Option<String>) {
        let tracker = match CoinTracker::decode(saved) {
            Ok(tracker) if tracker.watches_exactly(&watch) => tracker,
            Ok(_) => {
                return (
                    LightNode::new(genesis, watch),
                    Some("the watched addresses changed; scanning again from the start".into()),
                )
            }
            Err(e) => {
                return (
                    LightNode::new(genesis, watch),
                    Some(format!(
                        "the saved scan cannot be read ({e}); scanning again"
                    )),
                )
            }
        };
        (
            LightNode {
                tracker,
                cursor,
                pending: BTreeMap::new(),
            },
            None,
        )
    }

    /// 走査結果をバイト列にする。
    ///
    /// 順番待ちは入れない。**確かめ終わって数え込んだものだけ**を残す。
    pub fn encode(&self) -> Vec<u8> {
        self.tracker.encode()
    }

    /// 走査済みの印を、この高さの手前まで戻す。
    ///
    /// 再編成で枝が入れ替わったときに呼ぶ。**硬貨は消さない。** 呼んだ側が
    /// 分岐点から引き直す。
    pub fn rewind_to(&mut self, hash: Hash, height: u64) {
        self.cursor = hash;
        self.tracker.rescan_from(height + 1);
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_chain::scenarios::{build_on, open, NOW};
    use oag_chain::store::MemoryStore;
    use oag_consensus::validate::AcceptAnyPow;
    use oag_consensus::TxOutput;
    use oag_primitives::{merkle, Amount, SecretKey};

    fn a_lock() -> Lock {
        Lock::pay_to_pubkey(&SecretKey::generate().public_key())
    }

    /// コインベースの受取先を差し替える。PoW は `AcceptAnyPow` なので、
    /// マークルルートさえ張り直せば通る。
    fn paying(mut block: Block, to: &Lock) -> Block {
        let amount = block.transactions[0].outputs[0].amount;
        block.transactions[0].outputs[0] = TxOutput::new(amount, to.clone());
        let ids: Vec<Hash> = block.transactions.iter().map(|t| t.txid()).collect();
        block.header.merkle_root = merkle::merkle_root(&ids).unwrap();
        block
    }

    /// ヘッダだけを積む。**本体は渡さない。** 軽量ノードが見る形である。
    fn push_header(chain: &mut Chain<MemoryStore>, block: &Block) {
        chain
            .accept_header(&block.header, &AcceptAnyPow, NOW)
            .expect("the header is valid");
    }

    /// ヘッダだけの鎖を `count` 本積み、本体を高さ順に返す。
    fn headers_only(chain: &mut Chain<MemoryStore>, count: usize, salt: u64) -> Vec<Block> {
        let mut parent = chain.tip().unwrap().hash;
        let mut out = Vec::new();
        for i in 0..count {
            let block = build_on(chain, parent, salt * 1_000_000 + i as u64);
            parent = block.header.hash();
            push_header(chain, &block);
            out.push(block);
        }
        out
    }

    fn light(chain: &Chain<MemoryStore>, watch: Vec<Lock>) -> LightNode {
        LightNode::new(chain.tip().unwrap().hash, watch)
    }

    // ━━━━━━━━ 頼む順 ━━━━━━━━

    #[test]
    fn the_bodies_are_asked_for_oldest_first() {
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 5, 1);
        let node = light(&chain, vec![]);

        let want = node.wanted(&chain, 10).unwrap();
        let expected: Vec<Hash> = blocks.iter().map(|b| b.header.hash()).collect();
        assert_eq!(want, expected, "not asked for in height order");
    }

    #[test]
    fn asking_is_capped() {
        let mut chain = open(MemoryStore::new());
        headers_only(&mut chain, 10, 1);
        let node = light(&chain, vec![]);
        assert_eq!(node.wanted(&chain, 3).unwrap().len(), 3);
    }

    #[test]
    fn nothing_is_wanted_when_the_headers_end() {
        let chain = open(MemoryStore::new());
        let node = light(&chain, vec![]);
        assert!(node.wanted(&chain, 10).unwrap().is_empty());
    }

    #[test]
    fn what_is_already_waiting_is_not_asked_for_twice() {
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 4, 1);
        let mut node = light(&chain, vec![]);

        // 高さ 2 だけ先に届いた。穴が空いているので走査は進まない。
        node.offer(blocks[1].clone(), &chain).unwrap();
        assert_eq!(node.pending_len(), 1);

        let want = node.wanted(&chain, 10).unwrap();
        assert!(
            !want.contains(&blocks[1].header.hash()),
            "it asked again for a body it is already holding"
        );
        assert_eq!(want.len(), 3);
    }

    // ━━━━━━━━ 確かめる ━━━━━━━━

    #[test]
    fn a_body_whose_header_we_never_checked_is_refused() {
        // **頼んでいないものを受け取らない。** ヘッダを検証していなければ
        // PoW の裏打ちがあるかどうかを知らない。
        let chain = open(MemoryStore::new());
        let tip = chain.tip().unwrap().hash;
        let stranger = build_on(&chain, tip, 99);
        let mut node = light(&chain, vec![]);

        assert!(matches!(
            node.offer(stranger, &chain),
            Err(LightError::UnknownHeader(_))
        ));
        assert_eq!(node.pending_len(), 0, "a refused body was kept anyway");
    }

    #[test]
    fn a_body_that_does_not_match_its_merkle_root_is_refused() {
        // **軽量ノードが自分で確かめられる、ほぼ唯一のことである。**
        // ここが抜けると、PoW のあるヘッダに好きな中身を貼り付けられる。
        let mine = a_lock();
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 1, 1);
        let mut node = light(&chain, vec![mine.clone()]);

        // ヘッダはそのまま、中身だけ自分宛に差し替える。
        let mut forged = blocks[0].clone();
        let amount = forged.transactions[0].outputs[0].amount;
        forged.transactions[0].outputs[0] = TxOutput::new(amount, mine);

        assert!(matches!(
            node.offer(forged, &chain),
            Err(LightError::MerkleMismatch(_))
        ));
        assert_eq!(
            node.tracker().total().unwrap(),
            Amount::ZERO,
            "a forged payment was counted"
        );
    }

    // ━━━━━━━━ 走査 ━━━━━━━━

    #[test]
    fn a_payment_to_us_is_found() {
        let mine = a_lock();
        let mut chain = open(MemoryStore::new());
        let parent = chain.tip().unwrap().hash;
        let block = paying(build_on(&chain, parent, 1), &mine);
        push_header(&mut chain, &block);

        let mut node = light(&chain, vec![mine]);
        let scanned = node.offer(block.clone(), &chain).unwrap();

        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].height, 1);
        assert_eq!(scanned[0].changes.received.len(), 1);
        assert_eq!(
            node.tracker().total().unwrap(),
            block.transactions[0].outputs[0].amount
        );
        assert_eq!(node.cursor(), block.header.hash());
    }

    #[test]
    fn somebody_elses_block_moves_the_cursor_but_adds_nothing() {
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 3, 1);
        let mut node = light(&chain, vec![a_lock()]);

        for b in &blocks {
            node.offer(b.clone(), &chain).unwrap();
        }
        assert_eq!(node.cursor(), blocks[2].header.hash());
        assert_eq!(node.tracker().total().unwrap(), Amount::ZERO);
        assert_eq!(node.tracker().scanned_to(), Some(3));
    }

    #[test]
    fn bodies_arriving_out_of_order_wait_for_the_gap_to_close() {
        // **本体は複数の相手に振り分けて頼む。** 届く順は高さの順ではない。
        let mine = a_lock();
        let mut chain = open(MemoryStore::new());
        let mut parent = chain.tip().unwrap().hash;
        let mut blocks = Vec::new();
        for i in 0..3u64 {
            let b = paying(build_on(&chain, parent, i + 1), &mine);
            parent = b.header.hash();
            push_header(&mut chain, &b);
            blocks.push(b);
        }

        let mut node = light(&chain, vec![mine]);

        // 3 番目が先に届く。穴が空いているので走査しない。
        assert!(node.offer(blocks[2].clone(), &chain).unwrap().is_empty());
        assert_eq!(node.tracker().total().unwrap(), Amount::ZERO);
        // 2 番目。まだ 1 番目が無い。
        assert!(node.offer(blocks[1].clone(), &chain).unwrap().is_empty());
        assert_eq!(node.pending_len(), 2);

        // 1 番目が届いた瞬間に 3 つとも流れる。
        let scanned = node.offer(blocks[0].clone(), &chain).unwrap();
        assert_eq!(scanned.len(), 3, "the gap closed but they did not drain");
        assert_eq!(
            scanned.iter().map(|s| s.height).collect::<Vec<u64>>(),
            vec![1, 2, 3],
            "they drained out of height order"
        );
        assert_eq!(node.pending_len(), 0);
        assert_eq!(node.cursor(), blocks[2].header.hash());
    }

    #[test]
    fn the_same_body_twice_is_harmless() {
        let mine = a_lock();
        let mut chain = open(MemoryStore::new());
        let parent = chain.tip().unwrap().hash;
        let block = paying(build_on(&chain, parent, 1), &mine);
        push_header(&mut chain, &block);

        let mut node = light(&chain, vec![mine]);
        node.offer(block.clone(), &chain).unwrap();
        let total = node.tracker().total().unwrap();

        // 二度目は既に通り過ぎているので、順番待ちに入っても流れない。
        let again = node.offer(block, &chain).unwrap();
        assert!(again.is_empty());
        assert_eq!(
            node.tracker().total().unwrap(),
            total,
            "the payment was counted twice"
        );
    }

    // ━━━━━━━━ 持たない ━━━━━━━━

    #[test]
    fn the_body_is_not_kept() {
        // **これが軽量モードの全部である。** 走査したら捨てる。
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 3, 1);
        let mut node = light(&chain, vec![a_lock()]);

        for b in &blocks {
            node.offer(b.clone(), &chain).unwrap();
        }

        for b in &blocks {
            assert_eq!(
                chain.store().block(&b.header.hash()).unwrap(),
                None,
                "the body at height {} was stored",
                b.header.height
            );
        }
        // ヘッダのほうは残っている。**連なりを切らさない** (SPEC §19)。
        for b in &blocks {
            assert!(chain.entry(&b.header.hash()).unwrap().is_some());
        }
    }

    #[test]
    fn the_utxo_set_stays_empty() {
        // 軽量ノードは他人の UTXO を持たない。持てば軽くない。
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 4, 1);
        let before = chain.store().utxo_count();
        let mut node = light(&chain, vec![a_lock()]);
        for b in &blocks {
            node.offer(b.clone(), &chain).unwrap();
        }
        assert_eq!(
            chain.store().utxo_count(),
            before,
            "scanning grew the UTXO set"
        );
    }

    // ━━━━━━━━ 保存と読み戻し ━━━━━━━━

    #[test]
    fn a_saved_scan_resumes_where_it_stopped() {
        // **これが無いと、再起動のたびにチェーンを落とし直す。** 置いた
        // まま動かしてもらうには、再起動が再同期を意味してはならない。
        let mine = a_lock();
        let mut chain = open(MemoryStore::new());
        let mut parent = chain.tip().unwrap().hash;
        let mut blocks = Vec::new();
        for i in 0..4u64 {
            let b = paying(build_on(&chain, parent, i + 1), &mine);
            parent = b.header.hash();
            push_header(&mut chain, &b);
            blocks.push(b);
        }
        let genesis = chain.hash_at_height(0).unwrap().unwrap();

        let mut node = LightNode::new(genesis, vec![mine.clone()]);
        node.offer(blocks[0].clone(), &chain).unwrap();
        node.offer(blocks[1].clone(), &chain).unwrap();
        let saved = node.encode();
        let before = node.tracker().total().unwrap();

        // 落として、読み戻す。走査を再開する位置はチェーンから引き直す。
        let resume = chain
            .ancestor_hash_at(&chain.best_header().unwrap().hash, 2)
            .unwrap()
            .unwrap();
        let (mut back, note) = LightNode::restore(&saved, genesis, resume, vec![mine]);
        assert_eq!(note, None, "a clean resume should not complain");
        assert_eq!(back.tracker().total().unwrap(), before);
        assert_eq!(back.tracker().scanned_to(), Some(2));

        // **既に見たものは頼み直さない。**
        let want = back.wanted(&chain, 10).unwrap();
        assert_eq!(want.len(), 2, "it asked for blocks it had already scanned");
        assert_eq!(want[0], blocks[2].header.hash());

        back.offer(blocks[2].clone(), &chain).unwrap();
        back.offer(blocks[3].clone(), &chain).unwrap();
        assert_eq!(back.tracker().len(), 4);
    }

    #[test]
    fn changing_the_watched_addresses_forces_a_rescan() {
        // **ここが緩いと、足したアドレスへの入金が永久に抜け落ちる。**
        // 続きから数えると、そのアドレスが載っていたブロックは二度と
        // 見直されない。
        let first = a_lock();
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 2, 1);
        let genesis = chain.hash_at_height(0).unwrap().unwrap();

        let mut node = LightNode::new(genesis, vec![first.clone()]);
        node.offer(blocks[0].clone(), &chain).unwrap();
        let saved = node.encode();

        // 見張る先が増えた。
        let (back, note) = LightNode::restore(
            &saved,
            genesis,
            blocks[0].header.hash(),
            vec![first, a_lock()],
        );
        assert!(note.is_some(), "it resumed despite the watch list changing");
        assert_eq!(back.cursor(), genesis, "it did not go back to the start");
        assert_eq!(back.tracker().scanned_to(), None);
        assert_eq!(back.tracker().watched_len(), 2);
    }

    #[test]
    fn an_unreadable_save_starts_over_rather_than_guessing() {
        let mine = a_lock();
        let chain = open(MemoryStore::new());
        let genesis = chain.hash_at_height(0).unwrap().unwrap();

        let (back, note) = LightNode::restore(b"not a scan", genesis, genesis, vec![mine]);
        assert!(note.is_some(), "it said nothing about an unreadable save");
        assert_eq!(back.cursor(), genesis);
        assert!(back.tracker().is_empty());
    }

    #[test]
    fn the_saved_height_can_be_read_without_decoding_everything() {
        // 再開位置をチェーンから引き直すのに、高さだけ先に要る。
        let mine = a_lock();
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 2, 1);
        let genesis = chain.hash_at_height(0).unwrap().unwrap();
        let mut node = LightNode::new(genesis, vec![mine]);
        node.offer(blocks[0].clone(), &chain).unwrap();

        assert_eq!(saved_height(&node.encode()), Some(1));
        assert_eq!(saved_height(b"rubbish"), None);
    }

    // ━━━━━━━━ 巻き戻し ━━━━━━━━

    #[test]
    fn rewinding_drops_the_queue_and_marks_a_rescan() {
        let mut chain = open(MemoryStore::new());
        let blocks = headers_only(&mut chain, 3, 1);
        let mut node = light(&chain, vec![a_lock()]);
        node.offer(blocks[0].clone(), &chain).unwrap();
        node.offer(blocks[2].clone(), &chain).unwrap();
        assert_eq!(node.pending_len(), 1);

        let genesis = chain.tip().unwrap().hash;
        node.rewind_to(genesis, 0);
        assert_eq!(node.cursor(), genesis);
        assert_eq!(node.pending_len(), 0, "the queue survived a rewind");
        // 高さ 0 まで戻した = 高さ 0 は見終わっている。
        assert_eq!(node.tracker().scanned_to(), Some(0));
        // 巻き戻した先から、また頼める。
        assert_eq!(node.wanted(&chain, 10).unwrap().len(), 3);
    }
}
