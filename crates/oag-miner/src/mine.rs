//! 採掘。
//!
//! テンプレートの `nonce` を変えながら PoW ハッシュを計算し、難易度を
//! 満たすものを探す。
//!
//! # ハッシュの計算は差し替えられる
//!
//! [`PowHasher`] として抽象化してある。実際の採掘では RandomX を渡すが、
//! 試験では速い偽物を渡せる。RandomX は 1 ハッシュに数ミリ秒かかるため、
//! 探索の筋道そのものを試すのに使うと時間がかかりすぎる。
//!
//! # 探索空間
//!
//! `nonce` は 64 ビットある。使い切ったときは
//! [`crate::TemplateRequest::extra_nonce`] を変えて組み直す。コインベースの
//! 中身が変わると txid が変わり、マークルルートが変わり、探索空間が
//! まるごと新しくなる。

use crate::template::BlockTemplate;
use oag_consensus::Block;
use oag_pow::target::{target_from_difficulty, ZeroDifficulty};
use oag_primitives::Hash;

/// PoW ハッシュの計算。
pub trait PowHasher {
    /// ヘッダのバイト列から PoW ハッシュを求める。
    fn hash(&self, header_bytes: &[u8]) -> Hash;
}

/// 採掘を打ち切るかどうかの判断。
///
/// 新しいブロックが届いた、停止を指示された、といった事情で真を返す。
pub trait StopSignal {
    /// 打ち切るべきか。
    fn should_stop(&self) -> bool;
}

/// 決して打ち切らない。
#[derive(Debug, Clone, Copy, Default)]
pub struct NeverStop;

impl StopSignal for NeverStop {
    fn should_stop(&self) -> bool {
        false
    }
}

impl<F: Fn() -> bool> StopSignal for F {
    fn should_stop(&self) -> bool {
        self()
    }
}

/// 採掘の結果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MiningOutcome {
    /// 見つかった。
    Found {
        /// 完成したブロック。
        block: Box<Block>,
        /// 試した回数。
        attempts: u64,
    },
    /// 与えられた範囲を試し切ったが見つからなかった。
    Exhausted {
        /// 試した回数。
        attempts: u64,
    },
    /// 打ち切られた。
    Stopped {
        /// 試した回数。
        attempts: u64,
    },
}

impl MiningOutcome {
    /// 見つかったブロック。
    pub fn block(self) -> Option<Block> {
        match self {
            MiningOutcome::Found { block, .. } => Some(*block),
            _ => None,
        }
    }

    /// 試した回数。
    pub fn attempts(&self) -> u64 {
        match self {
            MiningOutcome::Found { attempts, .. }
            | MiningOutcome::Exhausted { attempts }
            | MiningOutcome::Stopped { attempts } => *attempts,
        }
    }
}

/// 採掘の失敗。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MineError {
    /// 難易度が 0。
    #[error(transparent)]
    Difficulty(#[from] ZeroDifficulty),
}

/// `nonce` を `start` から `count` 個試す。
///
/// 打ち切りの判断は [`CHECK_INTERVAL`] 回ごとに行う。毎回問い合わせると
/// 探索そのものより判断の方が重くなりうるためである。
pub fn mine(
    template: &BlockTemplate,
    hasher: &dyn PowHasher,
    start: u64,
    count: u64,
    stop: &dyn StopSignal,
) -> Result<MiningOutcome, MineError> {
    let target = target_from_difficulty(template.header.difficulty)?;
    let mut working = template.clone();
    let mut attempts = 0u64;

    for offset in 0..count {
        if attempts > 0 && attempts.is_multiple_of(CHECK_INTERVAL) && stop.should_stop() {
            return Ok(MiningOutcome::Stopped { attempts });
        }

        working.header.nonce = start.wrapping_add(offset);
        attempts += 1;

        let hash = hasher.hash(&working.hash_input());
        if oag_pow::target::meets_target(&hash, &target) {
            return Ok(MiningOutcome::Found {
                block: Box::new(working.into_block()),
                attempts,
            });
        }
    }

    Ok(MiningOutcome::Exhausted { attempts })
}

/// 打ち切りの判断を行う間隔。
pub const CHECK_INTERVAL: u64 = 64;

#[cfg(feature = "randomx")]
impl PowHasher for oag_pow::randomx::RandomXVerifier {
    fn hash(&self, header_bytes: &[u8]) -> Hash {
        // 計算に失敗した場合、絶対に難易度を満たさない値を返す。
        // 採掘は止まらず、ただそのノンスが外れになるだけである。
        self.hash(header_bytes)
            .unwrap_or(Hash::from_bytes([0xff; 32]))
    }
}

#[cfg(feature = "randomx")]
impl PowHasher for oag_pow::randomx::RandomXMiner {
    /// light モードと**同じ値を返す**。違うのは速さだけである。
    fn hash(&self, header_bytes: &[u8]) -> Hash {
        self.hash(header_bytes)
            .unwrap_or(Hash::from_bytes([0xff; 32]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{build_template, TemplateRequest};
    use oag_consensus::codec::Encode;
    use oag_consensus::lock::Lock;
    use oag_mempool::Mempool;
    use oag_pow::target::meets_difficulty;
    use oag_primitives::{hash, SecretKey};
    use std::cell::Cell;

    /// 実際に分布のあるハッシュ。RandomX の代わりに使う。
    struct FastHasher;

    impl PowHasher for FastHasher {
        fn hash(&self, header_bytes: &[u8]) -> Hash {
            hash::block_hash(header_bytes)
        }
    }

    /// 決して難易度を満たさないハッシュ。
    struct NeverWins;

    impl PowHasher for NeverWins {
        fn hash(&self, _: &[u8]) -> Hash {
            Hash::from_bytes([0xff; 32])
        }
    }

    /// 呼ばれた回数を数えるハッシュ。
    struct Counting {
        calls: Cell<u64>,
    }

    impl PowHasher for Counting {
        fn hash(&self, _: &[u8]) -> Hash {
            self.calls.set(self.calls.get() + 1);
            Hash::from_bytes([0xff; 32])
        }
    }

    fn template(difficulty: u64) -> BlockTemplate {
        let request = TemplateRequest {
            prev_hash: hash::block_hash(b"parent"),
            height: 500,
            difficulty,
            timestamp: 1_800_000_000,
            payout: Lock::pay_to_pubkey(&SecretKey::generate().public_key()),
            extra_nonce: b"orange".to_vec(),
        };
        build_template(&request, &Mempool::new()).unwrap()
    }

    #[test]
    fn mining_finds_a_nonce_that_meets_the_difficulty() {
        let template = template(64);
        let outcome = mine(&template, &FastHasher, 0, 100_000, &NeverStop).unwrap();

        let attempts = outcome.attempts();
        let block = outcome.block().expect("難易度 64 なら見つかるはず");

        // 見つけたブロックが本当に条件を満たしていること。
        let pow = FastHasher.hash(&block.header.encode());
        assert!(
            meets_difficulty(&pow, 64).unwrap(),
            "難易度を満たしていないブロックが返された"
        );
        // 内容は変わっていないこと。
        assert_eq!(block.transactions, template.transactions);
        assert_eq!(block.header.merkle_root, template.header.merkle_root);
        assert!(attempts > 0);
    }

    #[test]
    fn difficulty_one_is_found_immediately() {
        let template = template(1);
        let outcome = mine(&template, &FastHasher, 0, 10, &NeverStop).unwrap();
        assert_eq!(outcome.attempts(), 1, "難易度 1 は 1 回目で当たるはず");
        assert!(outcome.block().is_some());
    }

    #[test]
    fn an_exhausted_range_is_reported() {
        let template = template(1_000_000);
        let outcome = mine(&template, &NeverWins, 0, 500, &NeverStop).unwrap();
        assert_eq!(outcome, MiningOutcome::Exhausted { attempts: 500 });
        assert!(outcome.block().is_none());
    }

    #[test]
    fn mining_stops_when_told_to() {
        // 新しいブロックが届いたら、その土台での探索は無駄になる。
        let template = template(1_000_000);
        let outcome = mine(&template, &NeverWins, 0, 1_000_000, &|| true).unwrap();
        match outcome {
            MiningOutcome::Stopped { attempts } => {
                assert!(
                    attempts <= CHECK_INTERVAL + 1,
                    "打ち切りの判断が遅すぎる ({attempts} 回)"
                );
            }
            other => panic!("打ち切られなかった: {other:?}"),
        }
    }

    #[test]
    fn the_stop_signal_is_not_asked_every_round() {
        // 毎回問い合わせると、探索より判断の方が重くなりうる。
        let asked = Cell::new(0u64);
        let template = template(1_000_000);
        let _ = mine(&template, &NeverWins, 0, 1_000, &|| {
            asked.set(asked.get() + 1);
            false
        })
        .unwrap();
        assert!(
            asked.get() <= 1_000 / CHECK_INTERVAL + 1,
            "{} 回も問い合わせている",
            asked.get()
        );
    }

    #[test]
    fn every_nonce_in_the_range_is_tried() {
        let counting = Counting {
            calls: Cell::new(0),
        };
        let template = template(1_000_000);
        let outcome = mine(&template, &counting, 0, 777, &NeverStop).unwrap();
        assert_eq!(outcome.attempts(), 777);
        assert_eq!(counting.calls.get(), 777, "試した回数と計算回数が合わない");
    }

    #[test]
    fn the_search_can_start_anywhere() {
        // 複数のスレッドで範囲を分けて探すための性質。
        let template = template(1);
        let outcome = mine(&template, &FastHasher, 12_345, 10, &NeverStop).unwrap();
        let block = outcome.block().unwrap();
        assert_eq!(block.header.nonce, 12_345);
    }

    #[test]
    fn the_nonce_wraps_around_without_panicking() {
        let template = template(1_000_000);
        let outcome = mine(&template, &NeverWins, u64::MAX - 2, 5, &NeverStop).unwrap();
        assert_eq!(outcome.attempts(), 5);
    }

    #[test]
    fn zero_difficulty_is_an_error() {
        let template = template(0);
        assert!(matches!(
            mine(&template, &FastHasher, 0, 1, &NeverStop),
            Err(MineError::Difficulty(_))
        ));
    }

    #[test]
    fn a_harder_target_needs_more_attempts() {
        // 難易度を上げると、平均して必要な試行回数が増えること。
        let easy: u64 = (0..8)
            .map(|seed| {
                let mut t = template(4);
                t.header.timestamp += seed;
                mine(&t, &FastHasher, 0, 100_000, &NeverStop)
                    .unwrap()
                    .attempts()
            })
            .sum();
        let hard: u64 = (0..8)
            .map(|seed| {
                let mut t = template(256);
                t.header.timestamp += seed;
                mine(&t, &FastHasher, 0, 100_000, &NeverStop)
                    .unwrap()
                    .attempts()
            })
            .sum();
        assert!(
            hard > easy * 4,
            "難易度 256 の方が難易度 4 より明らかに多く試すはず ({easy} → {hard})"
        );
    }
}
