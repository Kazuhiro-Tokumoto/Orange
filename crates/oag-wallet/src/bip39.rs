//! BIP39 のニーモニック。
//!
//! # 何を守っているか
//!
//! 控えは**人が紙に書き写す**。16 進 64 文字は書き損じても気づけないが、
//! BIP39 の語は 2048 語の辞書に載っているものだけであり、しかも末尾に
//! 検査符号が入る。**綴りを間違えれば復元時に弾かれる。**
//!
//! # 語数
//!
//! 生成は 12 語 (128 ビット) で行う ([`docs/SPEC.md`] の §6.6)。
//! 128 ビットは secp256k1 が実際に持つ強度と一致する。256 ビット曲線に
//! 対する最良の一般攻撃 (Pollard の rho) の計算量は 2^128 であり、
//! 24 語 (256 ビット) の種を用いても、そこから導かれる鍵を守る強度は
//! 2^128 のままである。**種を長くしても曲線より強くはならない。**
//!
//! 読み取りは 12 / 15 / 18 / 21 / 24 語すべてを受け付ける。他のウォレット
//! で作った控えを持ち込めなくする理由が無い。
//!
//! # 追加パスフレーズ
//!
//! BIP39 の任意パスフレーズに対応する。既定は空文字列である。
//!
//! **打ち間違えても失敗として現れない。** 別のパスフレーズは単に別の
//! 有効なウォレットを作る。利用者から見えるのは残高 0 のウォレットだけで、
//! どこにも誤りは表示されない。呼び出し側はこの性質を利用者に伝えること。
//!
//! [`docs/SPEC.md`]: https://github.com/Kazuhiro-Tokumoto/Orange/blob/main/docs/SPEC.md

use sha2::{Digest, Sha256, Sha512};
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// 生成に用いる語数。
pub const WORD_COUNT: usize = 12;

/// 生成に用いるエントロピーの長さ。
pub const ENTROPY_LEN: usize = 16;

/// BIP39 の種の長さ。
pub const SEED_LEN: usize = 64;

/// PBKDF2 の反復回数。BIP39 が定める値であり、変えてはならない。
const PBKDF2_ROUNDS: u32 = 2048;

/// 1 語が担うビット数。2^11 = 2048 語。
const BITS_PER_WORD: usize = 11;

/// 英語の単語表。BIP39 が定めるものをそのまま埋め込む。
const WORDLIST_TEXT: &str = include_str!("bip39-english.txt");

/// 単語表を引く。
fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Box<[&'static str]>> = OnceLock::new();
    LIST.get_or_init(|| WORDLIST_TEXT.lines().collect::<Vec<_>>().into_boxed_slice())
}

/// ニーモニックの読み取りで起きる失敗。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Bip39Error {
    /// 語数が 12 / 15 / 18 / 21 / 24 のいずれでもない。
    #[error("語数は 12 / 15 / 18 / 21 / 24 のいずれかであること (受け取った語数: {found})")]
    BadWordCount {
        /// 受け取った語数。
        found: usize,
    },
    /// 単語表に無い語がある。
    ///
    /// **綴りは伏せない。** 書き写しの誤りを直すには、どの語かが分からねば
    /// ならない。ニーモニック全体ではなく 1 語だけを示す。
    #[error("{position} 番目の語が単語表に無い: {word}")]
    UnknownWord {
        /// 何番目の語か (1 起算)。
        position: usize,
        /// その語。
        word: String,
    },
    /// エントロピーの長さが 16 / 20 / 24 / 28 / 32 バイトのいずれでもない。
    #[error("エントロピーは 16 / 20 / 24 / 28 / 32 バイトのいずれかであること (受け取った長さ: {found})")]
    BadEntropyLength {
        /// 受け取った長さ。
        found: usize,
    },
    /// 検査符号が合わない。
    #[error("検査符号が合わない。どこか 1 語が違っている")]
    BadChecksum,
}

/// BIP39 のニーモニック。
///
/// 中身はエントロピーである。語はここから毎回組み立てる。
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    entropy: Vec<u8>,
}

impl std::fmt::Debug for Mnemonic {
    /// 語を出さない。ログに出れば資金が動く。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mnemonic(<伏せ字>)")
    }
}

impl Mnemonic {
    /// 暗号学的乱数から 12 語のニーモニックを作る。
    pub fn generate() -> Mnemonic {
        let mut entropy = vec![0u8; ENTROPY_LEN];
        oag_primitives::fill_random(&mut entropy);
        Mnemonic { entropy }
    }

    /// エントロピーから作る。
    ///
    /// 長さは 16 / 20 / 24 / 28 / 32 バイトのいずれかであること。
    pub fn from_entropy(entropy: &[u8]) -> Result<Mnemonic, Bip39Error> {
        let words =
            entropy_len_to_word_count(entropy.len()).ok_or(Bip39Error::BadEntropyLength {
                found: entropy.len(),
            })?;
        debug_assert_eq!(word_count_to_entropy_len(words), Some(entropy.len()));
        Ok(Mnemonic {
            entropy: entropy.to_vec(),
        })
    }

    /// 語の並びから読み取る。
    ///
    /// 大文字小文字と空白の詰め方は問わない。**検査符号が合わなければ
    /// 断る。** 1 語の書き違いはここで捕まる。
    pub fn parse(phrase: &str) -> Result<Mnemonic, Bip39Error> {
        let normalized: String = phrase.nfkd().collect::<String>().to_lowercase();
        let words: Vec<&str> = normalized.split_whitespace().collect();
        let entropy_len = word_count_to_entropy_len(words.len())
            .ok_or(Bip39Error::BadWordCount { found: words.len() })?;

        let list = wordlist();
        // 語を 11 ビットずつのビット列に戻す。
        let mut bits = Vec::with_capacity(words.len() * BITS_PER_WORD);
        for (i, word) in words.iter().enumerate() {
            let index = list
                .binary_search(word)
                .map_err(|_| Bip39Error::UnknownWord {
                    position: i + 1,
                    word: (*word).to_string(),
                })?;
            for bit in (0..BITS_PER_WORD).rev() {
                bits.push((index >> bit) & 1 == 1);
            }
        }

        let mut entropy = vec![0u8; entropy_len];
        for (i, chunk) in bits[..entropy_len * 8].chunks(8).enumerate() {
            entropy[i] = chunk.iter().fold(0u8, |acc, &b| (acc << 1) | u8::from(b));
        }

        // 検査符号を確かめる。ここを飛ばすと書き違いが通ってしまう。
        let expected = checksum_bits(&entropy);
        let actual = &bits[entropy_len * 8..];
        if expected != actual {
            entropy.zeroize();
            return Err(Bip39Error::BadChecksum);
        }
        Ok(Mnemonic { entropy })
    }

    /// 語の並び。空白 1 つ区切り。
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.words().join(" "))
    }

    /// 語の一覧。
    pub fn words(&self) -> Vec<&'static str> {
        let list = wordlist();
        let mut bits = Vec::with_capacity(self.entropy.len() * 8 + 8);
        for byte in &self.entropy {
            for bit in (0..8).rev() {
                bits.push((byte >> bit) & 1 == 1);
            }
        }
        bits.extend_from_slice(&checksum_bits(&self.entropy));
        bits.chunks(BITS_PER_WORD)
            .map(|chunk| {
                let index = chunk
                    .iter()
                    .fold(0usize, |acc, &b| (acc << 1) | usize::from(b));
                list[index]
            })
            .collect()
    }

    /// エントロピー。**保存する以外に使ってはならない。**
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// 64 バイトの種を導く。
    ///
    /// `passphrase` は BIP39 の任意パスフレーズである。既定は空文字列。
    /// **打ち間違えても失敗として現れず、別の有効なウォレットができる。**
    pub fn to_seed(&self, passphrase: &str) -> Zeroizing<[u8; SEED_LEN]> {
        let phrase = self.phrase();
        // BIP39 は入力を NFKD で正規化することを定めている。英語の単語表は
        // ASCII なので語の側は変わらないが、パスフレーズは何でも来る。
        // ここを飛ばすと、同じ控えと同じパスフレーズから別の種が出る。
        let salt: Zeroizing<String> =
            Zeroizing::new(format!("mnemonic{}", passphrase.nfkd().collect::<String>()));
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        pbkdf2::pbkdf2_hmac::<Sha512>(
            phrase.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            &mut seed[..],
        );
        seed
    }
}

/// エントロピーの末尾に付ける検査符号のビット列。
///
/// SHA-256 の先頭 (エントロピーのビット数 / 32) ビットである。
fn checksum_bits(entropy: &[u8]) -> Vec<bool> {
    let digest = Sha256::digest(entropy);
    let count = entropy.len() * 8 / 32;
    (0..count)
        .map(|i| (digest[i / 8] >> (7 - i % 8)) & 1 == 1)
        .collect()
}

/// 語数からエントロピーの長さを求める。
fn word_count_to_entropy_len(words: usize) -> Option<usize> {
    match words {
        12 | 15 | 18 | 21 | 24 => Some(words * BITS_PER_WORD / 33 * 4),
        _ => None,
    }
}

/// エントロピーの長さから語数を求める。
fn entropy_len_to_word_count(bytes: usize) -> Option<usize> {
    match bytes {
        16 | 20 | 24 | 28 | 32 => Some(bytes * 8 / 32 * 3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP39 が定める試験ベクタ。追加パスフレーズは "TREZOR"。
    /// (エントロピー, 語, 種)
    const BIP39_VECTORS: &[(&str, &str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        ),
        (
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
        ),
        (
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        ),
        (
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
        ),
        (
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        ),
        (
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        ),
        (
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
        ),
        (
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
        ),
        (
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        ),
        (
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
        ),
        (
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        ),
    ];

    fn from_hex(text: &str) -> Vec<u8> {
        (0..text.len() / 2)
            .map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_official_vectors_pass() {
        // **ここが外れると、他のウォレットで復元できない控えを配ることに
        // なる。** 控えの互換性はこの試験だけが担保している。
        for (entropy, phrase, seed) in BIP39_VECTORS {
            let entropy = from_hex(entropy);
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(&*mnemonic.phrase(), *phrase, "エントロピー → 語");

            let parsed = Mnemonic::parse(phrase).unwrap();
            assert_eq!(parsed.entropy(), &entropy[..], "語 → エントロピー");

            assert_eq!(
                to_hex(&*parsed.to_seed("TREZOR")),
                *seed,
                "語 → 種 ({phrase})"
            );
        }
    }

    #[test]
    fn the_wordlist_is_what_bip39_defines() {
        let list = wordlist();
        assert_eq!(list.len(), 2048);
        // 二分探索で引くため、並びが崩れると別の語を引く。
        assert!(list.windows(2).all(|w| w[0] < w[1]), "辞書順であること");
        // BIP39 は先頭 4 文字で語を一意に定めることを求めている。
        let mut prefixes: Vec<&str> = list.iter().map(|w| &w[..4.min(w.len())]).collect();
        prefixes.sort_unstable();
        let before = prefixes.len();
        prefixes.dedup();
        assert_eq!(prefixes.len(), before, "先頭 4 文字が重なる語がある");
        assert!(
            list.iter()
                .all(|w| w.chars().all(|c| c.is_ascii_lowercase())),
            "英小文字だけであること"
        );
    }

    #[test]
    fn generating_gives_twelve_words() {
        let mnemonic = Mnemonic::generate();
        assert_eq!(mnemonic.words().len(), WORD_COUNT);
        assert_eq!(mnemonic.entropy().len(), ENTROPY_LEN);
        // 読み書きが往復すること。
        let again = Mnemonic::parse(&mnemonic.phrase()).unwrap();
        assert_eq!(again.entropy(), mnemonic.entropy());
    }

    #[test]
    fn two_mnemonics_are_not_the_same() {
        // 乱数を取り違えて定数を返していたら、ここで落ちる。
        let a = Mnemonic::generate();
        let b = Mnemonic::generate();
        assert_ne!(a.entropy(), b.entropy());
    }

    #[test]
    fn a_misspelled_word_is_refused() {
        // 書き写しの誤りを捕まえるのが検査符号の役目である。
        let phrase = BIP39_VECTORS[0].1;
        let broken = phrase.replacen("about", "abount", 1);
        assert_eq!(
            Mnemonic::parse(&broken).unwrap_err(),
            Bip39Error::UnknownWord {
                position: 12,
                word: "abount".to_string(),
            }
        );
    }

    #[test]
    fn swapping_a_word_for_another_real_word_is_refused() {
        // 辞書には載っているが検査符号が合わない場合。**ここを見逃すと、
        // 1 語違う控えで別のウォレットが開いてしまう。**
        let phrase = BIP39_VECTORS[0].1;
        let broken = phrase.replacen("about", "ability", 1);
        assert_eq!(
            Mnemonic::parse(&broken).unwrap_err(),
            Bip39Error::BadChecksum
        );
    }

    #[test]
    fn the_word_count_must_be_one_of_the_allowed_values() {
        assert_eq!(
            Mnemonic::parse("abandon abandon abandon").unwrap_err(),
            Bip39Error::BadWordCount { found: 3 }
        );
    }

    #[test]
    fn case_and_spacing_do_not_matter() {
        let (_, phrase, seed) = BIP39_VECTORS[0];
        let messy = format!("  {}  ", phrase.to_uppercase().replace(' ', "\n  "));
        let parsed = Mnemonic::parse(&messy).unwrap();
        assert_eq!(to_hex(&*parsed.to_seed("TREZOR")), seed);
    }

    #[test]
    fn a_different_passphrase_gives_a_different_seed() {
        // **これが「打ち間違えても失敗として現れない」の中身である。**
        // どちらも有効な種であり、区別する手立ては無い。
        let mnemonic = Mnemonic::parse(BIP39_VECTORS[0].1).unwrap();
        assert_ne!(*mnemonic.to_seed(""), *mnemonic.to_seed("x"));
        assert_ne!(*mnemonic.to_seed("TREZOR"), *mnemonic.to_seed("trezor"));
    }

    #[test]
    fn the_passphrase_is_normalized() {
        // NFKD を飛ばすと、同じ控えと同じ見た目のパスフレーズから
        // 別の種が出る。"é" は 1 文字でも 2 文字でも書ける。
        let mnemonic = Mnemonic::parse(BIP39_VECTORS[0].1).unwrap();
        let composed = "\u{e9}";
        let decomposed = "e\u{301}";
        assert_ne!(composed, decomposed);
        assert_eq!(*mnemonic.to_seed(composed), *mnemonic.to_seed(decomposed));
    }
}
