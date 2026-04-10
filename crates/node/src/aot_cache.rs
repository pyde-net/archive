//! JIT compilation cache: per-node in-memory cache of AOT-compiled contracts.
//!
//! On first call to a contract:
//!   1. Load bytecode from SMT
//!   2. Spawn background Cranelift compilation
//!   3. Execute on PVM interpreter (immediate, no wait)
//!   4. When compilation finishes → cache populated
//!   5. Subsequent calls → native speed
//!
//! The cache is NOT shared across nodes. Each node compiles independently
//! because native code is architecture-specific (ARM64 vs x86_64).

use pyde_aot::CompiledCode;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Thread-safe JIT compilation cache: contract address → compiled native code.
pub struct AotCache {
    cache: RwLock<HashMap<[u8; 32], Arc<CompiledCode>>>,
    /// Contracts currently being compiled (to avoid duplicate compilations).
    compiling: RwLock<std::collections::HashSet<[u8; 32]>>,
}

impl AotCache {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(HashMap::new()),
            compiling: RwLock::new(std::collections::HashSet::new()),
        }
    }

    /// Get compiled code for a contract, if available.
    pub fn get(&self, address: &[u8; 32]) -> Option<Arc<CompiledCode>> {
        self.cache.read().ok()?.get(address).cloned()
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

    /// Insert compiled code into the cache.
    pub fn insert(&self, address: [u8; 32], code: CompiledCode) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(address, Arc::new(code));
        }
        if let Ok(mut set) = self.compiling.write() {
            set.remove(&address);
        }
    }

    /// Number of cached contracts.
    pub fn len(&self) -> usize {
        self.cache.read().map(|c| c.len()).unwrap_or(0)
    }
}

/// Spawn background JIT compilation for a contract.
/// The compilation result is inserted into the cache when done.
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
                    "AOT background compilation complete"
                );
            }
            Err(e) => {
                tracing::debug!(
                    contract = hex::encode(address),
                    error = %e,
                    "AOT compilation failed — interpreter fallback"
                );
                // Remove from compiling set so it can be retried
                if let Ok(mut set) = cache.compiling.write() {
                    set.remove(&address);
                }
            }
        }
    });
}
