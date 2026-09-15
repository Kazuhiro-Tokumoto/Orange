//! 複数スレッドでの採掘。
//!
//! PoW の探索は分けられる。ノンス空間を等分して、スレッドごとに別の
//! 範囲を試せばよい。当たりが 1 個見つかればその時点で終わりである。
//!
//! # 採掘器はスレッドをまたがない
//!
//! RandomX の VM はスクラッチパッドを書き換えるため、複数のスレッドで
//! 共有できない (`oag-pow` の `randomx` モジュールを見よ)。データセットも
//! 同じで、`randomx-rs` の型は `Send` ですらない。
//!
//! そこで**採掘器を渡さない。作り方を渡す**。[`HasherFactory`] は
//! それぞれの作業スレッドの上で呼ばれ、そのスレッドだけが使う採掘器を
//! 建てる。スレッド境界を越えるのは作り方 (シードの値など、ただの数)
//! だけであり、採掘器そのものは生まれた場所から動かない。**`unsafe` は
//! 要らない。**
//!
//! 代償は memory である。共有しないのだから、スレッドの数だけ要る。
//! light モードなら 1 スレッドあたり 256 MB、fast モードなら 2 GB。
//! どちらを何本建てるかは呼び出し側が決める。
//!
//! # 仕事の配り方
//!
//! 先端が動けば、それまで掘っていた土台は無駄になる。捨てさせる仕掛けが
//! [`MiningPool::dispatch`] の**世代番号**である。配るたびに 1 つ増やし、
//! 作業スレッドは自分の持つ番号と食い違ったらすぐ手を止める。
//! 止まるまでの間は [`crate::mine::CHECK_INTERVAL`] 回以内である。
//!
//! 世代番号は当たりにも付いて回る。古い土台で当たったブロックは、
//! 受け取った側で捨てられる ([`MiningPool::take_found`])。**捨てないと、
//! 既に動いた先端の 1 つ前に繋がるブロックを自分で掘って出すことになる。**

use crate::mine::{mine, MiningOutcome, PowHasher};
use crate::template::BlockTemplate;
use oag_consensus::Block;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// ひと続きで試すノンスの数。
///
/// これを試すごとに試行回数を数え上げる。大きすぎると採掘の速さの表示が
/// 飛び飛びになり、小さすぎると土台を複製する手間が目立つ。打ち切りの
/// 判断はこれとは別に [`crate::mine::CHECK_INTERVAL`] 回ごとに行うので、
/// ここを大きくしても手を止めるのが遅れることはない。
const NONCE_CHUNK: u64 = 1_024;

/// 採掘器の作り方。
///
/// 引数は作業スレッドの通し番号 (`0` から始まる)。**呼ばれるのは
/// そのスレッドの上である。** 返した採掘器はそのスレッドから出ない。
pub type HasherFactory =
    Arc<dyn Fn(usize) -> Result<Box<dyn PowHasher>, String> + Send + Sync + 'static>;

/// 採掘スレッドを起こせなかった。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolError {
    /// OS がスレッドを作らせてくれない。
    #[error("採掘スレッドを起こせない: {0}")]
    Spawn(String),
    /// 採掘器を建てられない。memory が足りないときはこれになる。
    #[error("採掘器を用意できない: {0}")]
    Hasher(String),
}

/// 作業スレッドに配る仕事。
struct Job {
    /// この仕事の世代。[`MiningPool::generation`] と食い違ったら捨てる。
    generation: u64,
    /// 掘る土台。
    template: BlockTemplate,
}

/// 採掘スレッドの束。
///
/// 落とすと、走っている仕事を捨てさせてから全スレッドの終わりを待つ。
pub struct MiningPool {
    /// 作業スレッドごとの仕事の口。
    jobs: Vec<mpsc::Sender<Job>>,
    /// 当たりの受け口。世代番号が付いている。
    found: mpsc::Receiver<(u64, Box<Block>)>,
    workers: Vec<JoinHandle<()>>,
    /// いま有効な世代。配るたびに増える。
    generation: Arc<AtomicU64>,
    /// 全スレッドの試行回数の合計。
    attempts: Arc<AtomicU64>,
    /// いま配ってある仕事の世代。配っていなければ `None`。
    current: Option<u64>,
    threads: usize,
}

impl MiningPool {
    /// スレッドを起こし、それぞれの上で採掘器を建てる。
    ///
    /// **全員の用意ができてから返る。** fast モードでは 1 個あたり 1 分
    /// 前後かかるが、並行に進むので待ち時間は 1 個分で済む。
    ///
    /// 1 人でも建てられなければ、起こした分を畳んでから誤りを返す。
    /// 半分だけ動く状態を残さないためである。
    pub fn spawn(
        threads: NonZeroUsize,
        make_hasher: HasherFactory,
    ) -> Result<MiningPool, PoolError> {
        let threads = threads.get();
        let generation = Arc::new(AtomicU64::new(0));
        let attempts = Arc::new(AtomicU64::new(0));
        let (found_tx, found) = mpsc::channel();
        let (ready_tx, ready) = mpsc::channel();

        let mut jobs = Vec::with_capacity(threads);
        let mut workers = Vec::with_capacity(threads);

        for index in 0..threads {
            let (job_tx, job_rx) = mpsc::channel();
            let make = Arc::clone(&make_hasher);
            let found_tx = found_tx.clone();
            let ready_tx = ready_tx.clone();
            let for_worker = Arc::clone(&generation);
            let counter = Arc::clone(&attempts);
            let spawned = std::thread::Builder::new()
                .name(format!("oag-mine-{index}"))
                .spawn(move || {
                    work(
                        index,
                        threads,
                        &make,
                        &job_rx,
                        &found_tx,
                        &for_worker,
                        &counter,
                        &ready_tx,
                    );
                });
            match spawned {
                Ok(handle) => {
                    jobs.push(job_tx);
                    workers.push(handle);
                }
                Err(e) => {
                    shut_down(&generation, jobs, workers);
                    return Err(PoolError::Spawn(e.to_string()));
                }
            }
        }
        // 自分の持ち分は閉じる。作業スレッドが全員終われば口が閉じる。
        drop(found_tx);
        drop(ready_tx);

        let mut failure: Option<String> = None;
        for _ in 0..threads {
            let outcome = match ready.recv() {
                Ok(result) => result,
                Err(_) => Err("採掘スレッドが黙って終わった".to_string()),
            };
            if let Err(e) = outcome {
                failure.get_or_insert(e);
            }
        }
        if let Some(e) = failure {
            shut_down(&generation, jobs, workers);
            return Err(PoolError::Hasher(e));
        }

        Ok(MiningPool {
            jobs,
            found,
            workers,
            generation,
            attempts,
            current: None,
            threads,
        })
    }

    /// 新しい土台を配る。**前の仕事は捨てられる。**
    ///
    /// 先端が動いたとき、mempool に取引が増えたとき、時刻を入れ直したい
    /// ときに呼ぶ。
    pub fn dispatch(&mut self, template: BlockTemplate) {
        // 先に世代を進める。走っている作業スレッドはこれを見て手を止め、
        // 新しい仕事を取りに戻る。
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        self.current = Some(generation);
        for job in &self.jobs {
            let _ = job.send(Job {
                generation,
                template: template.clone(),
            });
        }
    }

    /// 配ってある仕事を捨てさせる。次を配るまでスレッドは眠る。
    pub fn abandon(&mut self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.current = None;
    }

    /// 当たっていれば取り出す。待たない。
    pub fn take_found(&mut self) -> Option<Block> {
        while let Ok((generation, block)) = self.found.try_recv() {
            if Some(generation) == self.current {
                return Some(*block);
            }
        }
        None
    }

    /// 当たるまで、あるいは `timeout` が尽きるまで待つ。
    ///
    /// 古い世代の当たりは捨てて待ち続ける。
    pub fn wait(&mut self, timeout: Duration) -> Option<Block> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.found.recv_timeout(left) {
                Ok((generation, block)) if Some(generation) == self.current => {
                    return Some(*block);
                }
                // 古い土台の当たり。捨てて待ち続ける。
                Ok(_) => continue,
                // 時間切れ、あるいは全員終わった。
                Err(_) => return None,
            }
        }
    }

    /// 全スレッドの試行回数の合計。
    pub fn attempts(&self) -> u64 {
        self.attempts.load(Ordering::Relaxed)
    }

    /// 動いているスレッドの数。
    pub fn threads(&self) -> usize {
        self.threads
    }
}

impl std::fmt::Debug for MiningPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MiningPool")
            .field("threads", &self.threads)
            .field("attempts", &self.attempts())
            .field("current", &self.current)
            .finish()
    }
}

impl Drop for MiningPool {
    fn drop(&mut self) {
        let jobs = std::mem::take(&mut self.jobs);
        let workers = std::mem::take(&mut self.workers);
        shut_down(&self.generation, jobs, workers);
    }
}

/// 走っている仕事を捨てさせ、口を閉じ、全員の終わりを待つ。
///
/// **順番に意味がある。** 先に世代を進めないと、作業スレッドは仕事を
/// 掘り切るまで口が閉じたことに気付かない。
fn shut_down(generation: &AtomicU64, jobs: Vec<mpsc::Sender<Job>>, workers: Vec<JoinHandle<()>>) {
    generation.fetch_add(1, Ordering::SeqCst);
    drop(jobs);
    for worker in workers {
        let _ = worker.join();
    }
}

/// この作業スレッドが受け持つノンスの範囲 (始まり, 長さ)。
///
/// 64 ビットを等分する。**重ならないので、同じノンスを 2 人で試すことが
/// ない。** 端数は捨てる。1 人あたり 2^64/n 個もあれば、どのみち試し
/// 切る前に次の土台が来る。
fn nonce_range(index: usize, threads: usize) -> (u64, u64) {
    let span = u64::MAX / threads as u64;
    (span * index as u64, span)
}

/// 作業スレッドの本体。
#[allow(clippy::too_many_arguments)]
fn work(
    index: usize,
    threads: usize,
    make_hasher: &HasherFactory,
    jobs: &mpsc::Receiver<Job>,
    found: &mpsc::Sender<(u64, Box<Block>)>,
    generation: &AtomicU64,
    attempts: &AtomicU64,
    ready: &mpsc::Sender<Result<(), String>>,
) {
    // **採掘器はここで建てる。** 呼び出し元のスレッドで建てて持ち込む
    // ことはできない (モジュールの説明を見よ)。
    let hasher = match make_hasher(index) {
        Ok(hasher) => {
            let _ = ready.send(Ok(()));
            hasher
        }
        Err(e) => {
            let _ = ready.send(Err(e));
            return;
        }
    };

    let (start, span) = nonce_range(index, threads);

    // 仕事の口が閉じたら終わる。
    while let Ok(job) = jobs.recv() {
        let mut offset = 0u64;
        while offset < span {
            if generation.load(Ordering::Relaxed) != job.generation {
                break;
            }
            let count = NONCE_CHUNK.min(span - offset);
            let stop = || generation.load(Ordering::Relaxed) != job.generation;
            let outcome = match mine(
                &job.template,
                hasher.as_ref(),
                start.wrapping_add(offset),
                count,
                &stop,
            ) {
                Ok(outcome) => outcome,
                // 難易度 0。この土台では誰も掘れない。次の仕事を待つ。
                Err(_) => break,
            };
            attempts.fetch_add(outcome.attempts(), Ordering::Relaxed);
            offset += count;
            if let MiningOutcome::Found { block, .. } = outcome {
                let _ = found.send((job.generation, block));
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::template::{build_template, TemplateRequest};
    use oag_consensus::lock::Lock;
    use oag_mempool::Mempool;
    use oag_primitives::{hash, Hash, SecretKey};
    use std::sync::atomic::AtomicUsize;

    /// 何を渡しても当たるハッシュ。
    struct AlwaysWins {
        /// 落ちたことを数える。スレッドが終わったかを見るために使う。
        gone: Option<Arc<AtomicUsize>>,
    }

    impl PowHasher for AlwaysWins {
        fn hash(&self, _: &[u8]) -> Hash {
            Hash::from_bytes([0x00; 32])
        }
    }

    impl Drop for AlwaysWins {
        fn drop(&mut self) {
            if let Some(gone) = &self.gone {
                gone.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    /// 決して当たらないハッシュ。
    struct NeverWins;

    impl PowHasher for NeverWins {
        fn hash(&self, _: &[u8]) -> Hash {
            Hash::from_bytes([0xff; 32])
        }
    }

    fn always_wins() -> HasherFactory {
        Arc::new(|_| Ok(Box::new(AlwaysWins { gone: None }) as Box<dyn PowHasher>))
    }

    fn never_wins() -> HasherFactory {
        Arc::new(|_| Ok(Box::new(NeverWins) as Box<dyn PowHasher>))
    }

    fn threads(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
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

    /// 待つ上限。当たるはずの試験で、当たらないまま止まらないように置く。
    const PATIENCE: Duration = Duration::from_secs(10);

    #[test]
    fn two_workers_never_try_the_same_nonce() {
        // 重なれば、その分だけ探索が無駄になる。
        let (start_a, span_a) = nonce_range(0, 4);
        let (start_b, span_b) = nonce_range(1, 4);
        assert_eq!(start_a, 0);
        assert_eq!(start_a + span_a, start_b, "範囲が飛んでいるか重なっている");
        assert_eq!(span_a, span_b, "等分になっていない");

        // 最後の 1 人まで 64 ビットに収まること。
        let (start_last, span_last) = nonce_range(3, 4);
        assert!(start_last.checked_add(span_last).is_some(), "範囲が溢れる");
    }

    #[test]
    fn one_worker_gets_the_whole_space() {
        let (start, span) = nonce_range(0, 1);
        assert_eq!(start, 0);
        assert_eq!(span, u64::MAX);
    }

    #[test]
    fn a_block_comes_back_from_several_threads() {
        let mut pool = MiningPool::spawn(threads(4), always_wins()).unwrap();
        assert_eq!(pool.threads(), 4);

        pool.dispatch(template(1));
        let block = pool.wait(PATIENCE).expect("当たるはずの土台で当たらない");

        // 配った土台の中身がそのまま返ること。
        assert_eq!(block.header.height, 500);
        assert!(!block.transactions.is_empty());
    }

    #[test]
    fn every_thread_builds_its_own_hasher() {
        // **ここが崩れると、1 個の採掘器を複数スレッドで触ることになる。**
        let seen = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&seen);
        let factory: HasherFactory = Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(NeverWins) as Box<dyn PowHasher>)
        });

        let pool = MiningPool::spawn(threads(3), factory).unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 3);
        drop(pool);
    }

    #[test]
    fn the_index_tells_the_threads_apart() {
        // 番号が重なっていると、担当するノンスの範囲も重なる。
        let seen: Arc<std::sync::Mutex<Vec<usize>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = Arc::clone(&seen);
        let factory: HasherFactory = Arc::new(move |index| {
            record.lock().unwrap().push(index);
            Ok(Box::new(NeverWins) as Box<dyn PowHasher>)
        });

        let pool = MiningPool::spawn(threads(4), factory).unwrap();
        drop(pool);

        let mut indexes = seen.lock().unwrap().clone();
        indexes.sort_unstable();
        assert_eq!(indexes, vec![0, 1, 2, 3]);
    }

    #[test]
    fn a_hit_on_an_abandoned_job_is_thrown_away() {
        // 先端が動いたあとに届く当たりは、1 つ前の先端に繋がっている。
        // **出せば自分で分岐を作ることになる。**
        let mut pool = MiningPool::spawn(threads(2), always_wins()).unwrap();
        pool.dispatch(template(1));
        // 当たりが溜まるだけの時間を与える。
        std::thread::sleep(Duration::from_millis(50));
        pool.abandon();

        assert!(
            pool.take_found().is_none(),
            "捨てたはずの世代の当たりを受け取った"
        );
        assert!(pool.wait(Duration::from_millis(50)).is_none());
    }

    #[test]
    fn a_new_job_takes_over_from_the_old_one() {
        let mut pool = MiningPool::spawn(threads(2), never_wins()).unwrap();
        pool.dispatch(template(1_000_000));
        std::thread::sleep(Duration::from_millis(50));
        let before = pool.attempts();
        assert!(before > 0, "掘り始めていない");

        // 当たる土台に差し替える。前の仕事は捨てられ、こちらが当たる。
        pool.dispatch(template(1_000_000));
        std::thread::sleep(Duration::from_millis(50));
        assert!(pool.attempts() > before, "差し替えたあと掘っていない");
    }

    #[test]
    fn nothing_is_tried_until_a_job_arrives() {
        let pool = MiningPool::spawn(threads(2), never_wins()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(pool.attempts(), 0, "仕事を配る前に掘っている");
    }

    #[test]
    fn a_pool_that_cannot_build_its_hasher_does_not_start() {
        // fast モードで 2 GB を確保できないときにここを通る。
        let factory: HasherFactory = Arc::new(|_| Err("memory が足りない".to_string()));
        let error = MiningPool::spawn(threads(2), factory).unwrap_err();
        assert!(
            matches!(&error, PoolError::Hasher(e) if e.contains("memory")),
            "誤りの中身が伝わっていない: {error}"
        );
    }

    #[test]
    fn one_thread_failing_takes_the_whole_pool_down() {
        // 半分だけ動く状態を残さない。
        let factory: HasherFactory = Arc::new(|index| {
            if index == 1 {
                Err("2 本目だけ建たない".to_string())
            } else {
                Ok(Box::new(NeverWins) as Box<dyn PowHasher>)
            }
        });
        assert!(MiningPool::spawn(threads(3), factory).is_err());
    }

    #[test]
    fn dropping_the_pool_ends_every_thread() {
        // 採掘器が落ちた回数で見る。スレッドが残っていれば落ちない。
        let gone = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&gone);
        let factory: HasherFactory = Arc::new(move |_| {
            Ok(Box::new(AlwaysWins {
                gone: Some(Arc::clone(&counter)),
            }) as Box<dyn PowHasher>)
        });

        let mut pool = MiningPool::spawn(threads(3), factory).unwrap();
        pool.dispatch(template(1));
        drop(pool);

        // `drop` は全スレッドの終わりを待ってから返る。
        assert_eq!(
            gone.load(Ordering::SeqCst),
            3,
            "終わっていないスレッドがある"
        );
    }

    #[test]
    fn waiting_gives_up_when_nobody_can_win() {
        let mut pool = MiningPool::spawn(threads(2), never_wins()).unwrap();
        pool.dispatch(template(1_000_000));
        assert!(pool.wait(Duration::from_millis(50)).is_none());
    }
}
