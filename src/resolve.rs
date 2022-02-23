use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Cursor},
    time::{Duration, SystemTime},
};
use tokio::sync::RwLock;
use trust_dns_client::rr::{Record, RecordType};

lazy_static! {
    static ref DENY_ENTRIES: RwLock<HashMap<String, bool>> = Default::default();
    static ref QUERY_CACHE: RwLock<HashMap<(String, RecordType), Answer>> = Default::default();
}
pub async fn is_deny(domain: &str) -> bool {
    DENY_ENTRIES.read().await.contains_key(domain)
}

pub async fn get_cached(domain: String, query_type: RecordType) -> Option<Vec<Record>> {
    let read_lock = QUERY_CACHE.read().await;
    read_lock
        .get(&(domain, query_type))
        .map(|answer| answer.records.clone())
}
pub async fn add_cache(domain: String, query_type: RecordType, records: Vec<Record>) {
    let ttl = Duration::from_secs(records.get(0).map(|a| a.ttl() as u64).unwrap_or(60));
    QUERY_CACHE.write().await.insert(
        (domain, query_type),
        Answer {
            expires: SystemTime::now() + ttl,
            records,
        },
    );
}

#[derive(Debug, Clone)]
struct Answer {
    expires: SystemTime,
    records: Vec<Record>,
}

pub async fn init() {
    let deny_entries = parse_denylist().unwrap();
    *DENY_ENTRIES.write().await = deny_entries;

    tokio::spawn(cache_invalidator());
}

static DENY_LIST: &str = include_str!("../denylist.txt");

fn parse_denylist() -> Option<HashMap<String, bool>> {
    let reader = BufReader::new(Cursor::new(DENY_LIST));
    let mut deny_entries = HashMap::<String, bool>::new();

    for domain in reader.lines().flatten() {
        deny_entries.insert(
            domain
                .trim_start_matches("||")
                .trim_end_matches('^')
                .to_string(),
            true,
        );
    }

    Some(deny_entries)
}

async fn cache_invalidator() {
    loop {
        let now = SystemTime::now();
        QUERY_CACHE
            .write()
            .await
            .retain(|_, answer| answer.expires > now);
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}
