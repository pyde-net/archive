//! Execution trace recording and formatting.
//!
//! Records PVM execution events (calls, storage, deploys, logs) and renders
//! them as a tree with box-drawing characters, similar to Foundry's -vvvvv.
//!
//! Example output:
//! ```text
//!   [PASS] test_increment() (gas: 847)
//!   Traces:
//!     [847] CounterTest::test_increment()
//!       ├─ [523] deploy!(Counter) → Counter@0xab12...
//!       ├─ [156] Counter::increment()
//!       │   └─ SSTORE count: 0 → 1
//!       ├─ [89] Counter::get_count() → 1
//!       └─ ← success
//! ```

use ethnum::U256;

/// Verbosity levels for trace output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verbosity {
    /// No traces (default).
    Silent,
    /// Show call tree only (function calls + returns).
    Calls,
    /// Show calls + storage operations.
    Storage,
    /// Show everything (calls, storage, logs, opcodes).
    Full,
}

impl Verbosity {
    /// Parse from -v flag count: 0=Silent, 1=Calls, 2=Storage, 3+=Full.
    pub fn from_count(v: u8) -> Self {
        match v {
            0 => Verbosity::Silent,
            1 => Verbosity::Calls,
            2 => Verbosity::Storage,
            _ => Verbosity::Full,
        }
    }
}

/// A single trace event recorded during execution.
#[derive(Clone, Debug)]
pub enum TraceEvent {
    /// External function call (CallExt).
    Call {
        /// Target contract address (32 bytes).
        target: [u8; 32],
        /// Function selector (4 bytes).
        selector: u32,
        /// Function name (resolved from selector, or "unknown").
        function_name: String,
        /// Gas at entry.
        gas_start: u64,
        /// Call depth.
        depth: u32,
    },
    /// Return from a call.
    Return {
        /// Whether the call succeeded.
        success: bool,
        /// Gas consumed by this call.
        gas_used: u64,
        /// Return value (first 8 bytes as u64, for display).
        return_value: u64,
        /// Call depth.
        depth: u32,
    },
    /// Storage read.
    SLoad {
        /// Storage key.
        key: U256,
        /// Value read.
        value: u64,
        /// Call depth.
        depth: u32,
    },
    /// Storage write.
    SStore {
        /// Storage key.
        key: U256,
        /// New value written.
        value: u64,
        /// Call depth.
        depth: u32,
    },
    /// Contract deployment.
    Deploy {
        /// New contract address.
        address: [u8; 32],
        /// Bytecode size.
        code_size: usize,
        /// Gas used for deployment.
        gas_used: u64,
        /// Call depth.
        depth: u32,
    },
    /// Event log emitted.
    Log {
        /// Number of topics.
        topic_count: u8,
        /// Data size in bytes.
        data_size: usize,
        /// Call depth.
        depth: u32,
    },
    /// Revert with error data.
    Revert {
        /// Error selector (first 4 bytes of revert data).
        error_selector: Option<u32>,
        /// Error name (resolved).
        error_name: Option<String>,
        /// Call depth.
        depth: u32,
    },
}

/// Collects trace events during execution.
#[derive(Clone, Debug)]
pub struct ExecutionTrace {
    pub events: Vec<TraceEvent>,
    pub depth: u32,
}

impl ExecutionTrace {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            depth: 0,
        }
    }

    pub fn push(&mut self, event: TraceEvent) {
        self.events.push(event);
    }

    pub fn enter_call(&mut self) {
        self.depth += 1;
    }

    pub fn exit_call(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    pub fn current_depth(&self) -> u32 {
        self.depth
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

// ============================================================================
// Tree building and formatting
// ============================================================================

/// A node in the call tree.
#[derive(Clone, Debug)]
pub struct TraceNode {
    pub event: TraceEvent,
    pub children: Vec<TraceNode>,
}

/// Build a tree from flat trace events using depth tracking.
pub fn build_tree(events: &[TraceEvent]) -> Vec<TraceNode> {
    let mut root_nodes: Vec<TraceNode> = Vec::new();
    let mut stack: Vec<TraceNode> = Vec::new();

    for event in events {
        let depth = event_depth(event);
        let node = TraceNode {
            event: event.clone(),
            children: Vec::new(),
        };

        // Pop stack until we find the parent depth
        while stack.len() > depth as usize {
            let child = stack.pop().unwrap();
            if let Some(parent) = stack.last_mut() {
                parent.children.push(child);
            } else {
                root_nodes.push(child);
            }
        }

        match event {
            TraceEvent::Call { .. } | TraceEvent::Deploy { .. } => {
                // Push as potential parent
                stack.push(node);
            }
            TraceEvent::Return { .. } => {
                // Close the current call — pop and attach to parent
                if let Some(mut call_node) = stack.pop() {
                    call_node.children.push(node);
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(call_node);
                    } else {
                        root_nodes.push(call_node);
                    }
                } else {
                    root_nodes.push(node);
                }
            }
            _ => {
                // Leaf events (SLoad, SStore, Log, Revert) — attach to current parent
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else {
                    root_nodes.push(node);
                }
            }
        }
    }

    // Flush remaining stack
    while let Some(node) = stack.pop() {
        if let Some(parent) = stack.last_mut() {
            parent.children.push(node);
        } else {
            root_nodes.push(node);
        }
    }

    root_nodes
}

/// Format a trace tree as a string with box-drawing characters.
pub fn format_tree(nodes: &[TraceNode], verbosity: Verbosity) -> String {
    let mut output = String::new();
    for (i, node) in nodes.iter().enumerate() {
        let is_last = i == nodes.len() - 1;
        format_node(node, &mut output, "", is_last, verbosity);
    }
    output
}

fn format_node(
    node: &TraceNode,
    output: &mut String,
    prefix: &str,
    is_last: bool,
    verbosity: Verbosity,
) {
    let connector = if is_last { "└─ " } else { "├─ " };
    let child_prefix = if is_last {
        format!("{}   ", prefix)
    } else {
        format!("{}│  ", prefix)
    };

    match &node.event {
        TraceEvent::Call { function_name, gas_start, target, .. } => {
            let addr_short = hex_short(target);
            output.push_str(&format!(
                "{}{}[{}] {}::{}()\n",
                prefix, connector, gas_start, addr_short, function_name
            ));
        }
        TraceEvent::Return { success, gas_used, return_value, .. } => {
            if *success {
                if *return_value != 0 {
                    output.push_str(&format!(
                        "{}{}← {} (gas: {})\n",
                        prefix, connector, return_value, gas_used
                    ));
                } else {
                    output.push_str(&format!(
                        "{}{}← success (gas: {})\n",
                        prefix, connector, gas_used
                    ));
                }
            } else {
                output.push_str(&format!("{}{}← revert\n", prefix, connector));
            }
            return; // Returns don't have children
        }
        TraceEvent::SLoad { key, value, .. } => {
            if verbosity >= Verbosity::Storage {
                output.push_str(&format!(
                    "{}{}SLOAD [0x{:x}] → {}\n",
                    prefix, connector, key, value
                ));
            }
            return;
        }
        TraceEvent::SStore { key, value, .. } => {
            if verbosity >= Verbosity::Storage {
                output.push_str(&format!(
                    "{}{}SSTORE [0x{:x}] = {}\n",
                    prefix, connector, key, value
                ));
            }
            return;
        }
        TraceEvent::Deploy { address, code_size, gas_used, .. } => {
            output.push_str(&format!(
                "{}{}deploy! → {}  ({} bytes, {} gas)\n",
                prefix, connector, hex_short(address), code_size, gas_used
            ));
        }
        TraceEvent::Log { topic_count, data_size, .. } => {
            if verbosity >= Verbosity::Full {
                output.push_str(&format!(
                    "{}{}LOG ({} topics, {} bytes data)\n",
                    prefix, connector, topic_count, data_size
                ));
            }
            return;
        }
        TraceEvent::Revert { error_name, .. } => {
            let name = error_name.as_deref().unwrap_or("unknown error");
            output.push_str(&format!("{}{}← revert: {}\n", prefix, connector, name));
            return;
        }
    }

    // Format children
    for (i, child) in node.children.iter().enumerate() {
        let child_is_last = i == node.children.len() - 1;
        format_node(child, output, &child_prefix, child_is_last, verbosity);
    }
}

fn event_depth(event: &TraceEvent) -> u32 {
    match event {
        TraceEvent::Call { depth, .. } => *depth,
        TraceEvent::Return { depth, .. } => *depth,
        TraceEvent::SLoad { depth, .. } => *depth,
        TraceEvent::SStore { depth, .. } => *depth,
        TraceEvent::Deploy { depth, .. } => *depth,
        TraceEvent::Log { depth, .. } => *depth,
        TraceEvent::Revert { depth, .. } => *depth,
    }
}

/// Short hex representation of an address (first 4 bytes).
fn hex_short(addr: &[u8; 32]) -> String {
    if addr.iter().all(|&b| b == 0) {
        "0x0000...".to_string()
    } else {
        format!("0x{}...", hex_encode(&addr[..4]))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
