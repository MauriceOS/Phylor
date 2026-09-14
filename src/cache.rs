use crate::scan::ScanResult;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedVerdict {
    Allow,
    Block,
}

impl From<&ScanResult> for CachedVerdict {
    fn from(result: &ScanResult) -> Self {
        if result.is_block() {
            CachedVerdict::Block
        } else {
            CachedVerdict::Allow
        }
    }
}

impl CachedVerdict {
    pub fn is_allow(self) -> bool {
        matches!(self, CachedVerdict::Allow)
    }
}

/// Content-addressed LRU of fast-path allow/block decisions.
pub struct VerdictCache {
    capacity: usize,
    map: HashMap<[u8; 32], CachedVerdict>,
    order: VecDeque<[u8; 32]>,
}

impl VerdictCache {
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity).map(|n| n.get()).unwrap_or(1);
        Self {
            capacity,
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    pub fn hash(content: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.finalize().into()
    }

    pub fn get(&mut self, digest: &[u8; 32]) -> Option<CachedVerdict> {
        let verdict = *self.map.get(digest)?;
        if let Some(pos) = self.order.iter().position(|h| h == digest) {
            self.order.remove(pos);
            self.order.push_back(*digest);
        }
        Some(verdict)
    }

    pub fn insert(&mut self, digest: [u8; 32], verdict: CachedVerdict) {
        if self.map.contains_key(&digest) {
            self.map.insert(digest, verdict);
            if let Some(pos) = self.order.iter().position(|h| h == &digest) {
                self.order.remove(pos);
            }
            self.order.push_back(digest);
            return;
        }
        while self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.map.insert(digest, verdict);
        self.order.push_back(digest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Verdict;

    #[test]
    fn evicts_oldest() {
        let mut cache = VerdictCache::new(2);
        let a = VerdictCache::hash(b"a");
        let b = VerdictCache::hash(b"b");
        let c = VerdictCache::hash(b"c");
        cache.insert(a, CachedVerdict::Allow);
        cache.insert(b, CachedVerdict::Block);
        cache.insert(c, CachedVerdict::Allow);
        assert!(cache.get(&a).is_none());
        assert_eq!(cache.get(&b), Some(CachedVerdict::Block));
        assert_eq!(cache.get(&c), Some(CachedVerdict::Allow));
    }

    #[test]
    fn maps_scan_result() {
        let safe = ScanResult::safe();
        assert_eq!(CachedVerdict::from(&safe), CachedVerdict::Allow);
        let blocked = ScanResult::blocked(Verdict::Malicious, "t", "r", vec![], false);
        assert_eq!(CachedVerdict::from(&blocked), CachedVerdict::Block);
    }
}
