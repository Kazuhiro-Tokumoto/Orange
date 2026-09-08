//! 支払いの組み立てと署名。
//!
//! ノードにも通信にも依存しない。手持ちの UTXO と宛先を渡せば、署名済みの
//! トランザクションが返る。**この形にしているのは、金額の計算を通信なしで
//! 試験できるようにするためである。**
//!
//! # 手数料の決め方
//!
//! 手数料は大きさに比例し、大きさは入力の数で決まる。入力の数は必要な額
//! (= 送る額 + 手数料) で決まる。**堂々巡りになる。**
//!
//! そこで、入力を 1 個ずつ増やしながら**実際に組み立てて測る**。見積もり
//! ではなく実物の大きさを使うため、出来上がったものが料率を下回ることが
//! ない。入力の数はたかだか手持ちの UTXO の数であり、総当たりで困らない。
//!
//! # おつりとダスト
//!
//! おつりがダスト閾値を下回るなら、おつりを作らずに手数料へ回す。
//! ダストは**永久に UTXO セットに残る**うえ、それを使うのに必要な手数料が
//! 額を上回るため、誰も回収しない。作らないのが正しい。

use oag_consensus::codec::Encode;
use oag_consensus::lock::Lock;
use oag_consensus::params;
use oag_consensus::sighash::{sighash, SighashType};
use oag_consensus::tx::{OutPoint, TxInput, CURRENT_TX_VERSION};
use oag_consensus::{Transaction, TxOutput};
use oag_primitives::amount::MAX_SUPPLY_ATOMIC;
use oag_primitives::{Amount, SecretKey};

/// 手持ちの UTXO 1 件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coin {
    /// 出力の参照。
    pub outpoint: OutPoint,
    /// 出力の中身。
    pub output: TxOutput,
    /// この出力を生成したブロックの高さ。
    pub height: u64,
    /// コインベース出力か。成熟判定に用いる。
    pub is_coinbase: bool,
}

impl Coin {
    /// この高さのブロックで使えるか。
    ///
    /// コインベースは [`params::COINBASE_MATURITY`] ブロック経つまで
    /// 使えない。浅いリオーグで消えうる報酬が流通するのを防ぐためである。
    pub fn is_spendable_at(&self, height: u64) -> bool {
        if !self.is_coinbase {
            return true;
        }
        height >= self.height + params::COINBASE_MATURITY
    }
}

/// 組み立ての失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// 送る額が 0。
    #[error("送る額が 0 である")]
    ZeroAmount,
    /// 送る額がダスト閾値を下回る。
    #[error("送る額 {amount} はダス閾値 {threshold} を下回る")]
    BelowDust {
        /// 送ろうとした額。
        amount: Amount,
        /// 閾値。
        threshold: Amount,
    },
    /// 残高が足りない。
    #[error("残高が足りない (使える額 {available}、必要な額 {needed} 以上)")]
    Insufficient {
        /// 使える額の合計。
        available: Amount,
        /// 送る額 (手数料を除く)。
        needed: Amount,
    },
    /// 金額の計算が桁あふれした。
    #[error("金額の計算が桁あふれした")]
    Overflow,
    /// 宛先の支払い条件を、この実装は理解しない。
    #[error("宛先の版数 {version} をこの実装は知らない。送ると資金を失う")]
    UnknownLockVersion {
        /// 宛先の版数。
        version: u8,
    },
    /// 署名に使う鍵が見つからない。
    #[error("{index} 番目の入力に対応する鍵が無い")]
    MissingKey {
        /// 入力の位置。
        index: usize,
    },
    /// sighash を計算できない。
    #[error("sighash を計算できない: {0}")]
    Sighash(String),
    /// 出来上がりが大きすぎる。
    #[error("トランザクションが大きすぎる ({actual} バイト、上限 {max})")]
    TooLarge {
        /// 実際の大きさ。
        actual: usize,
        /// 上限。
        max: usize,
    },
}

/// 支払いの注文。
#[derive(Debug, Clone)]
pub struct Spend {
    /// 宛先の支払い条件。
    pub to: Lock,
    /// 送る額。
    pub amount: Amount,
    /// おつりの受取先。
    pub change_to: Lock,
    /// このトランザクションが入りうる最初のブロックの高さ。
    ///
    /// コインベースの成熟判定に用いる。
    pub next_height: u64,
    /// 料率 (atomic / バイト)。
    pub fee_rate: Amount,
}

/// 組み上がった支払い。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    /// トランザクション。署名はまだ入っていない。
    pub tx: Transaction,
    /// 各入力が参照する出力。sighash の計算に要る。
    pub spent: Vec<TxOutput>,
    /// 実際に払う手数料。
    pub fee: Amount,
    /// おつり。作らなかった場合は 0。
    pub change: Amount,
}

/// 署名を入れるための場所取り。
///
/// BIP340 の署名は 64 バイト固定であり、後から入れても大きさが変わらない。
/// **だからこそ、署名する前に大きさを正確に測れる。**
const SIGNATURE_PLACEHOLDER: [u8; 64] = [0u8; 64];

/// 符号化が最も長くなる額。総発行量を超える額は存在しない。
const MAX_ENCODED_AMOUNT: Amount = Amount::from_atomic_const(MAX_SUPPLY_ATOMIC);

/// 選んだ UTXO で組み立て、その大きさを測る。
fn build_with(selected: &[&Coin], spend: &Spend, with_change: bool) -> (Transaction, usize) {
    let inputs: Vec<TxInput> = selected
        .iter()
        .map(|coin| {
            let mut input = TxInput::new(coin.outpoint);
            input.signature = SIGNATURE_PLACEHOLDER.to_vec();
            input
        })
        .collect();

    let mut outputs = vec![TxOutput::new(spend.amount, spend.to.clone())];
    if with_change {
        // おつりの額はまだ決まっていないが、**符号化長は額によって変わる**
        // (SPEC §5)。取りうる最大の額を仮に置いて測る。こうしておけば、
        // 実際のおつりで縮むことはあっても、はみ出すことはない。
        //
        // 縮んだ分だけ手数料を多めに払うことになるが、差は数バイト分
        // (0.00002 OAG 未満) である。**足りないより多い方が安全**であり、
        // 大きさと手数料が互いを決め合う堂々巡りにも入らない。
        outputs.push(TxOutput::new(MAX_ENCODED_AMOUNT, spend.change_to.clone()));
    }

    let tx = Transaction {
        version: CURRENT_TX_VERSION,
        inputs,
        outputs,
        locktime: 0,
    };
    let size = tx.encode().len();
    (tx, size)
}

/// 支払いを組み立てる。署名はまだ入らない。
///
/// 使える UTXO を額の大きい順に足していき、送る額と手数料をまかなえた
/// ところで止める。入力が少ないほど小さく、手数料も安くなる。
pub fn build(coins: &[Coin], spend: &Spend) -> Result<Draft, BuildError> {
    if spend.amount.to_atomic() == 0 {
        return Err(BuildError::ZeroAmount);
    }
    if spend.amount < params::DUST_THRESHOLD {
        return Err(BuildError::BelowDust {
            amount: spend.amount,
            threshold: params::DUST_THRESHOLD,
        });
    }
    // 理解できない版数へは送らない。未知の版数は誰でも使える扱いになる
    // ため (SPEC §10.4)、有効化前に送ると資金を失う。
    if !spend.to.is_known_version() {
        return Err(BuildError::UnknownLockVersion {
            version: spend.to.version(),
        });
    }

    let mut usable: Vec<&Coin> = coins
        .iter()
        .filter(|c| c.is_spendable_at(spend.next_height))
        .collect();
    // 大きい順。入力の数を減らし、手数料を抑える。
    usable.sort_by_key(|c| std::cmp::Reverse(c.output.amount));

    let available =
        Amount::sum(usable.iter().map(|c| c.output.amount)).ok_or(BuildError::Overflow)?;

    let mut total = Amount::ZERO;
    for take in 1..=usable.len() {
        let selected = &usable[..take];
        total = total
            .checked_add(selected[take - 1].output.amount)
            .ok_or(BuildError::Overflow)?;

        let Some(surplus) = total.checked_sub(spend.amount) else {
            continue;
        };

        // おつりを作る形で測る。
        let (with_change, size_with) = build_with(selected, spend, true);
        let fee_with = spend
            .fee_rate
            .checked_mul(u64::try_from(size_with).map_err(|_| BuildError::Overflow)?)
            .ok_or(BuildError::Overflow)?;

        if let Some(change) = surplus.checked_sub(fee_with) {
            if change >= params::DUST_THRESHOLD {
                let mut tx = with_change;
                tx.outputs[1].amount = change;
                return finish(tx, selected, fee_with, change);
            }
        }

        // おつりを作らない形で測る。余りは丸ごと手数料になる。
        let (without_change, size_without) = build_with(selected, spend, false);
        let fee_without = spend
            .fee_rate
            .checked_mul(u64::try_from(size_without).map_err(|_| BuildError::Overflow)?)
            .ok_or(BuildError::Overflow)?;

        if surplus >= fee_without {
            return finish(without_change, selected, surplus, Amount::ZERO);
        }
    }

    Err(BuildError::Insufficient {
        available,
        needed: spend.amount,
    })
}

fn finish(
    tx: Transaction,
    selected: &[&Coin],
    fee: Amount,
    change: Amount,
) -> Result<Draft, BuildError> {
    let size = tx.encode().len();
    if size > params::MAX_TX_SIZE {
        return Err(BuildError::TooLarge {
            actual: size,
            max: params::MAX_TX_SIZE,
        });
    }
    Ok(Draft {
        tx,
        spent: selected.iter().map(|c| c.output.clone()).collect(),
        fee,
        change,
    })
}

/// 下書きに署名を入れる。
///
/// `key_for` は支払い条件から秘密鍵を引く。引けない入力があれば失敗する。
/// **一部だけ署名して返すことはしない。** 中途半端に署名されたものを
/// 送ってしまうと、資金を動かせないまま手数料を失う。
pub fn sign(
    draft: &Draft,
    key_for: impl Fn(&Lock) -> Option<SecretKey>,
) -> Result<Transaction, BuildError> {
    let mut tx = draft.tx.clone();

    // 先にすべての鍵を引く。1 個でも欠けていれば、署名を始めない。
    let mut keys = Vec::with_capacity(draft.spent.len());
    for (index, output) in draft.spent.iter().enumerate() {
        keys.push(key_for(&output.lock).ok_or(BuildError::MissingKey { index })?);
    }

    for (index, key) in keys.iter().enumerate() {
        let msg = sighash(&tx, &draft.spent, index, SighashType::DEFAULT)
            .map_err(|e| BuildError::Sighash(e.to_string()))?;
        tx.inputs[index].signature = key.sign(&msg).to_bytes().to_vec();
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oag_primitives::Network;

    fn key() -> SecretKey {
        SecretKey::generate()
    }

    fn lock_of(key: &SecretKey) -> Lock {
        Lock::pay_to_pubkey(&key.public_key())
    }

    fn coin(amount_oag: &str, key: &SecretKey, n: u32) -> Coin {
        Coin {
            outpoint: OutPoint {
                txid: oag_primitives::hash::txid(&n.to_le_bytes()),
                index: n,
            },
            output: TxOutput::new(amount_oag.parse::<Amount>().unwrap(), lock_of(key)),
            height: 1,
            is_coinbase: false,
        }
    }

    fn spend_of(amount_oag: &str, to: Lock, change_to: Lock) -> Spend {
        Spend {
            to,
            amount: amount_oag.parse::<Amount>().unwrap(),
            change_to,
            next_height: 1_000,
            fee_rate: params::MIN_RELAY_FEE_RATE_PER_BYTE,
        }
    }

    #[test]
    fn a_simple_payment_balances_exactly() {
        let mine = key();
        let theirs = key();
        let coins = vec![coin("10", &mine, 0)];
        let spend = spend_of("3", lock_of(&theirs), lock_of(&mine));

        let draft = build(&coins, &spend).unwrap();
        // 入力の合計 = 出力の合計 + 手数料。**これが崩れたら金額が
        // 湧いているか消えている。**
        let inputs = Amount::sum(draft.spent.iter().map(|o| o.amount)).unwrap();
        let outputs = Amount::sum(draft.tx.outputs.iter().map(|o| o.amount)).unwrap();
        assert_eq!(inputs, outputs.checked_add(draft.fee).unwrap());
        assert_eq!(draft.tx.outputs[0].amount, spend.amount);
        assert_eq!(draft.tx.outputs[1].amount, draft.change);
    }

    #[test]
    fn the_fee_covers_the_actual_size() {
        let mine = key();
        let coins = vec![coin("10", &mine, 0)];
        let spend = spend_of("3", lock_of(&key()), lock_of(&mine));
        let draft = build(&coins, &spend).unwrap();

        let signed = sign(&draft, |lock| {
            (*lock == lock_of(&mine)).then(|| mine.clone())
        })
        .unwrap();
        // **署名を入れても大きさが変わらないこと。** 変われば、測った
        // 大きさで決めた手数料が実物に足りなくなる。
        assert_eq!(signed.encode().len(), draft.tx.encode().len());

        let required = params::min_relay_fee(signed.encode().len()).unwrap();
        assert!(
            draft.fee >= required,
            "手数料 {} が最低 {} を下回る",
            draft.fee,
            required
        );
    }

    #[test]
    fn the_largest_coins_are_used_first() {
        let mine = key();
        let coins = vec![
            coin("1", &mine, 0),
            coin("50", &mine, 1),
            coin("5", &mine, 2),
        ];
        let spend = spend_of("40", lock_of(&key()), lock_of(&mine));
        let draft = build(&coins, &spend).unwrap();

        assert_eq!(draft.spent.len(), 1, "50 OAG 1 個で足りるはず");
        assert_eq!(draft.spent[0].amount, "50".parse::<Amount>().unwrap());
    }

    #[test]
    fn several_coins_are_combined_when_needed() {
        let mine = key();
        let coins = vec![
            coin("2", &mine, 0),
            coin("2", &mine, 1),
            coin("2", &mine, 2),
        ];
        let spend = spend_of("5", lock_of(&key()), lock_of(&mine));
        let draft = build(&coins, &spend).unwrap();

        assert_eq!(draft.spent.len(), 3);
        let inputs = Amount::sum(draft.spent.iter().map(|o| o.amount)).unwrap();
        let outputs = Amount::sum(draft.tx.outputs.iter().map(|o| o.amount)).unwrap();
        assert_eq!(inputs, outputs.checked_add(draft.fee).unwrap());
    }

    #[test]
    fn dust_change_becomes_fee_instead_of_an_output() {
        let mine = key();
        // 送る額と手数料を引いた残りが、ダスト閾値を下回るように仕組む。
        let coins = vec![coin("3.002", &mine, 0)];
        let spend = spend_of("3", lock_of(&key()), lock_of(&mine));
        let draft = build(&coins, &spend).unwrap();

        assert_eq!(draft.tx.outputs.len(), 1, "ダストのおつりを作っている");
        assert_eq!(draft.change, Amount::ZERO);
        // 余りは丸ごと手数料になる。金額は依然として釣り合う。
        let inputs = Amount::sum(draft.spent.iter().map(|o| o.amount)).unwrap();
        let outputs = Amount::sum(draft.tx.outputs.iter().map(|o| o.amount)).unwrap();
        assert_eq!(inputs, outputs.checked_add(draft.fee).unwrap());
    }

    #[test]
    fn an_immature_coinbase_is_not_spent() {
        let mine = key();
        let mut cb = coin("50", &mine, 0);
        cb.is_coinbase = true;
        cb.height = 100;

        // 高さ 150 では成熟していない (100 + 120 = 220 が必要)。
        let mut spend = spend_of("10", lock_of(&key()), lock_of(&mine));
        spend.next_height = 150;
        assert!(matches!(
            build(&[cb.clone()], &spend),
            Err(BuildError::Insufficient { .. })
        ));

        // 高さ 220 なら使える。
        spend.next_height = 220;
        assert!(build(&[cb], &spend).is_ok());
    }

    #[test]
    fn an_insufficient_balance_is_refused() {
        let mine = key();
        let coins = vec![coin("1", &mine, 0)];
        let spend = spend_of("5", lock_of(&key()), lock_of(&mine));
        assert!(matches!(
            build(&coins, &spend),
            Err(BuildError::Insufficient { .. })
        ));
    }

    #[test]
    fn a_balance_that_only_just_fails_to_cover_the_fee_is_refused() {
        let mine = key();
        // ちょうど送る額だけある。手数料の分が無い。
        let coins = vec![coin("3", &mine, 0)];
        let spend = spend_of("3", lock_of(&key()), lock_of(&mine));
        assert!(
            matches!(build(&coins, &spend), Err(BuildError::Insufficient { .. })),
            "手数料を払えないのに通っている"
        );
    }

    #[test]
    fn a_dust_payment_is_refused() {
        let mine = key();
        let coins = vec![coin("10", &mine, 0)];
        let spend = spend_of("0.0001", lock_of(&key()), lock_of(&mine));
        assert!(matches!(
            build(&coins, &spend),
            Err(BuildError::BelowDust { .. })
        ));
    }

    #[test]
    fn a_zero_payment_is_refused() {
        let mine = key();
        let coins = vec![coin("10", &mine, 0)];
        let mut spend = spend_of("1", lock_of(&key()), lock_of(&mine));
        spend.amount = Amount::ZERO;
        assert_eq!(build(&coins, &spend), Err(BuildError::ZeroAmount));
    }

    #[test]
    fn an_unknown_lock_version_is_refused() {
        // 未知の版数は誰でも使える扱いになる (SPEC §10.4)。有効化前に
        // 送れば資金を失う。ウォレットの側で止める。
        let mine = key();
        let coins = vec![coin("10", &mine, 0)];
        let future = Lock::from_address(
            &oag_primitives::Address::new(Network::Regtest, 9, vec![0u8; 32]).unwrap(),
        );
        let spend = spend_of("1", future, lock_of(&mine));
        assert_eq!(
            build(&coins, &spend),
            Err(BuildError::UnknownLockVersion { version: 9 })
        );
    }

    #[test]
    fn signing_without_the_key_fails_before_anything_is_signed() {
        let mine = key();
        let coins = vec![coin("10", &mine, 0)];
        let spend = spend_of("3", lock_of(&key()), lock_of(&mine));
        let draft = build(&coins, &spend).unwrap();

        assert_eq!(
            sign(&draft, |_| None),
            Err(BuildError::MissingKey { index: 0 })
        );
    }

    #[test]
    fn every_signature_verifies() {
        let a = key();
        let b = key();
        let coins = vec![coin("4", &a, 0), coin("4", &b, 1)];
        let spend = spend_of("7", lock_of(&key()), lock_of(&a));
        let draft = build(&coins, &spend).unwrap();
        assert_eq!(draft.spent.len(), 2);

        let signed = sign(&draft, |lock| {
            if *lock == lock_of(&a) {
                Some(a.clone())
            } else if *lock == lock_of(&b) {
                Some(b.clone())
            } else {
                None
            }
        })
        .unwrap();

        for (index, output) in draft.spent.iter().enumerate() {
            let msg = sighash(&signed, &draft.spent, index, SighashType::DEFAULT).unwrap();
            let pubkey = oag_primitives::PublicKey::from_slice(output.lock.payload()).unwrap();
            let bytes: [u8; 64] = signed.inputs[index].signature.clone().try_into().unwrap();
            assert!(
                pubkey.verify(&msg, &oag_primitives::Signature::from_bytes(bytes)),
                "{index} 番目の署名が検証できない"
            );
        }
    }

    #[test]
    fn a_signature_does_not_verify_against_another_input() {
        // sighash は入力ごとに違う。使い回せてしまうと、別の入力の
        // 署名をそのまま持ってこられる。
        let a = key();
        let b = key();
        let coins = vec![coin("4", &a, 0), coin("4", &b, 1)];
        let spend = spend_of("7", lock_of(&key()), lock_of(&a));
        let draft = build(&coins, &spend).unwrap();

        let m0 = sighash(&draft.tx, &draft.spent, 0, SighashType::DEFAULT).unwrap();
        let m1 = sighash(&draft.tx, &draft.spent, 1, SighashType::DEFAULT).unwrap();
        assert_ne!(m0, m1, "入力が違うのに sighash が同じ");
    }
}
