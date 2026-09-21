//! 記憶域の内訳を実測する。
//!
//! 指定した高さまでコインベースだけのブロックを積み、redb の
//! テーブルごとの実データ量と断片化を出す。PoW は検証しない
//! (`AcceptAnyPow`)。記憶域の中身は PoW とは無関係である。

use oag_chain::chain::{Chain, Retarget};
use oag_chain::scenarios;
use oag_consensus::validate::AcceptAnyPow;
use oag_store::Store;
use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableDefinition};

const TABLES: &[&str] = &[
    "blocks",
    "block_index",
    "block_children",
    "undo",
    "utxo",
    "active_chain",
    "meta",
];

fn main() {
    let height: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2000);

    let dir = std::env::temp_dir().join(format!("oag-breakdown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("chain.redb");

    {
        let store = Store::open(&path).unwrap();
        let mut chain = Chain::open(
            store,
            scenarios::genesis(),
            scenarios::DIFFICULTY,
            Retarget::Enabled,
        )
        .unwrap();

        let mut parent = chain.tip().unwrap().hash;
        for i in 0..height {
            let block = scenarios::build_on(&chain, parent, i as u64);
            parent = block.header.hash();
            chain
                .accept_block(block, &AcceptAnyPow, scenarios::NOW)
                .unwrap();
        }
        println!(
            "built {} blocks (height {})",
            height,
            chain.height().unwrap()
        );
    }

    let file = std::fs::metadata(&path).unwrap().len();

    let db = Database::open(&path).unwrap();
    let txn = db.begin_read().unwrap();

    println!();
    println!(
        "{:<16} {:>10} {:>12} {:>12} {:>8}",
        "table", "rows", "stored", "fragmented", "per blk"
    );
    println!("{}", "-".repeat(62));

    let mut stored_total = 0u64;
    let mut frag_total = 0u64;
    for name in TABLES {
        let def: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new(name);
        let Ok(table) = txn.open_table(def) else {
            continue;
        };
        let rows = table.len().unwrap();
        let stats = table.stats().unwrap();
        let stored = stats.stored_bytes();
        let frag = stats.fragmented_bytes();
        stored_total += stored;
        frag_total += frag;
        println!(
            "{:<16} {:>10} {:>12} {:>12} {:>8}",
            name,
            rows,
            human(stored),
            human(frag),
            format!("{} B", stored / height.max(1) as u64),
        );
    }

    println!("{}", "-".repeat(62));
    println!(
        "{:<16} {:>10} {:>12} {:>12}",
        "sum",
        "",
        human(stored_total),
        human(frag_total)
    );
    println!();
    println!("file on disk     {}", human(file));
    println!(
        "stored / file    {:.1}%",
        stored_total as f64 * 100.0 / file as f64
    );
    println!("per block        {} B", file / height.max(1) as u64);

    drop(txn);
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}

fn human(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.2} MB", n as f64 / (1u64 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{} B", n)
    }
}
