//! LRU-bounded JIT compilation cache for AOT-compiled contracts.
//!
//! Hot contracts stay native. Cold contracts get evicted and re-JIT on next call.
//! Bytecode lives in RocksDB (state) — no duplication on disk.
//!
//! Memory: bounded to `MAX_CACHED` contracts (~25MB for 500 contracts).
//! Miss penalty: ~1ms Cranelift compile (invisible in a 400ms block slot).
//!
//! Flow:
//!   1. Contract called → check LRU cache
//!   2. HIT:  return native fn pointer (0ns)
//!   3. MISS: interpreter executes this call, background compile starts
//!   4. Next call → native (compile finished in background)
//!   5. LRU full → evict least-recently-used (frees JITModule memory)

use pyde_aot::CompiledCode;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

/// Maximum number of compiled contracts kept in memory.
/// 500 contracts × ~50KB each ≈ 25MB of JIT overhead.
const MAX_CACHED: usize = 500;

/// Thread-safe LRU-bounded JIT compilation cache.
pub struct AotCache {
    /// Compiled code: address → native code.
    cache: RwLock<HashMap<[u8; 32], Arc<CompiledCode>>>,
    /// LRU order: front = most recently used, back = eviction candidate.
    lru: RwLock<VecDeque<[u8; 32]>>,
    /// Contracts currently being compiled (prevents duplicate compilations).
    compiling: RwLock<std::collections::HashSet<[u8; 32]>>,
    /// Contracts where AOT failed at runtime (use interpreter permanently).
    blacklisted: RwLock<std::collections::HashSet<[u8; 32]>>,
    /// Maximum cache size.
    max_size: usize,
}

impl AotCache {
    pub fn new() -> Self {
        Self::with_capacity(MAX_CACHED)
    }

    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            lru: RwLock::new(VecDeque::new()),
            compiling: RwLock::new(std::collections::HashSet::new()),
            blacklisted: RwLock::new(std::collections::HashSet::new()),
            max_size,
        }
    }

    /// Get compiled code and promote to front of LRU.
    pub fn get(&self, address: &[u8; 32]) -> Option<Arc<CompiledCode>> {
        let code = self.cache.read().ok()?.get(address).cloned()?;
        // Promote in LRU (move to front)
        if let Ok(mut lru) = self.lru.write() {
            if let Some(pos) = lru.iter().position(|a| a == address) {
                lru.remove(pos);
            }
            lru.push_front(*address);
        }
        Some(code)
    }

    /// Insert compiled code. Evicts the LRU entry if cache is full.
    pub fn insert(&self, address: [u8; 32], code: CompiledCode) {
        // Evict if at capacity
        if let (Ok(mut cache), Ok(mut lru)) = (self.cache.write(), self.lru.write()) {
            while cache.len() >= self.max_size {
                if let Some(evicted) = lru.pop_back() {
                    cache.remove(&evicted);
                    tracing::trace!(
                        contract = hex::encode(evicted),
                        "AOT cache evicted (LRU)"
                    );
                } else {
                    break;
                }
            }
            cache.insert(address, Arc::new(code));
            // Remove if already in LRU (re-insert at front)
            if let Some(pos) = lru.iter().position(|a| *a == address) {
                lru.remove(pos);
            }
            lru.push_front(address);
        }
        // Clear compiling flag
        if let Ok(mut set) = self.compiling.write() {
            set.remove(&address);
        }
    }

    /// Mark a contract as AOT-incompatible (use interpreter permanently).
    #[allow(dead_code)]
    pub fn blacklist(&self, address: [u8; 32]) {
        if let Ok(mut set) = self.blacklisted.write() {
            set.insert(address);
        }
    }

    /// Check if a contract is blacklisted from AOT.
    pub fn is_blacklisted(&self, address: &[u8; 32]) -> bool {
        self.blacklisted.read().map(|s| s.contains(address)).unwrap_or(false)
    }

    /// Check if a contract is already cached or being compiled.
    pub fn is_known(&self, address: &[u8; 32]) -> bool {
        let cached = self.cache.read().map(|c| c.contains_key(address)).unwrap_or(false);
        let compiling = self.compiling.read().map(|c| c.contains(address)).unwrap_or(false);
        cached || compiling
    }

    /// Mark a contract as being compiled (prevents duplicate compilation).
    pub fn mark_compiling(&self, address: [u8; 32]) -> bool {
        if let Ok(mut set) = self.compiling.write() {
            set.insert(address)
        } else {
            false
        }
    }

    /// Number of contracts currently cached.
    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }

    /// Maximum cache capacity.
    pub fn capacity(&self) -> usize {
        self.max_size
    }
}

/// Spawn background JIT compilation for a contract.
/// The compilation result is inserted into the LRU cache when done.
pub fn compile_in_background(
    cache: Arc<AotCache>,
    address: [u8; 32],
    bytecode: Vec<u8>,
) {
    if !cache.mark_compiling(address) {
        return; // already compiling or cached
    }

    std::thread::spawn(move || {
        match pyde_aot::compile_bytecode(&bytecode) {
            Ok(compiled) => {
                cache.insert(address, compiled);
                tracing::debug!(
                    contract = hex::encode(address),
                    cached = cache.len(),
                    capacity = cache.capacity(),
                    "AOT compiled (LRU cache)"
                );
            }
            Err(e) => {
                tracing::debug!(
                    contract = hex::encode(address),
                    error = %e,
                    "AOT compilation failed — interpreter fallback"
                );
                if let Ok(mut set) = cache.compiling.write() {
                    set.remove(&address);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_eviction() {
        let cache = AotCache::with_capacity(2);

        // Compile trivial bytecode for 3 contracts
        let halt = pyde_aot::compile_bytecode(&[0x00; 4]).unwrap(); // minimal valid bytecode
        let addr_a = [0xAA; 32];
        let addr_b = [0xBB; 32];
        let addr_c = [0xCC; 32];

        cache.insert(addr_a, halt);
        assert_eq!(cache.len(), 1);

        let halt = pyde_aot::compile_bytecode(&[0x00; 4]).unwrap();
        cache.insert(addr_b, halt);
        assert_eq!(cache.len(), 2);

        // Insert C — should evict A (oldest)
        let halt = pyde_aot::compile_bytecode(&[0x00; 4]).unwrap();
        cache.insert(addr_c, halt);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&addr_a).is_none(), "A should be evicted");
        assert!(cache.get(&addr_b).is_some(), "B should still be cached");
        assert!(cache.get(&addr_c).is_some(), "C should be cached");
    }

    #[test]
    fn lru_promotion_on_get() {
        let cache = AotCache::with_capacity(2);
        let addr_a = [0xAA; 32];
        let addr_b = [0xBB; 32];
        let addr_c = [0xCC; 32];

        let halt = pyde_aot::compile_bytecode(&[0x00; 4]).unwrap();
        cache.insert(addr_a, halt);
        let halt = pyde_aot::compile_bytecode(&[0x00; 4]).unwrap();
        cache.insert(addr_b, halt);

        // Touch A — promotes it to front
        assert!(cache.get(&addr_a).is_some());

        // Insert C — should evict B (now the LRU, since A was promoted)
        let halt = pyde_aot::compile_bytecode(&[0x00; 4]).unwrap();
        cache.insert(addr_c, halt);
        assert!(cache.get(&addr_a).is_some(), "A promoted, should survive");
        assert!(cache.get(&addr_b).is_none(), "B should be evicted");
        assert!(cache.get(&addr_c).is_some(), "C should be cached");
    }

    #[test]
    fn blacklist_persists() {
        let cache = AotCache::new();
        let addr = [0xFF; 32];
        assert!(!cache.is_blacklisted(&addr));
        cache.blacklist(addr);
        assert!(cache.is_blacklisted(&addr));
    }
}
