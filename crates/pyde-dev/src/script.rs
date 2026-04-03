//! Script runner: PVM orchestrator with RPC bridge.
//!
//! The PVM runs the script's internal logic (math, variables, control flow).
//! Every external operation (deploy, call) is intercepted and forwarded to
//! the actual chain via RPC. Return values come from real chain execution.
//!
//! Usage:
//!   pyde-dev script Deploy.oti --network devnet
//!   pyde-dev script Deploy.oti:TokenDeploy --network devnet --from 0x...

use crate::build;
use crate::project;
use ethnum::U256;
use otic::types::Ty;
use pyde_vm::isa::Opcode;
use pyde_vm::vm::{ExecResult, Outcome, Vm};
use std::fs;
use std::path::Path;
use std::time::Instant;

/// Function metadata for view/non-view detection and return type handling.
struct FnInfo {
    name: String,
    is_view: bool,
    return_ty: Ty,
}

/// TODO(M11.4): Replace `--from` address with `--wallet`/`--keystore` once the
/// wallet system is implemented (tasks 0914-0921). Currently uses bare address
/// without transaction signing (devnet mode only).
pub fn run(file: &str, network: &str, from: &str) -> Result<(), String> {
    let (config, root) = project::load_config()?;
    let start = Instant::now();

    // Parse file:Contract format
    let (file_part, contract_filter) = if let Some(colon_pos) = file.rfind(':') {
        let f = &file[..colon_pos];
        let c = &file[colon_pos + 1..];
        if c.is_empty() || colon_pos == 1 {
            (file, None)
        } else {
            (f, Some(c.to_string()))
        }
    } else {
        (file, None)
    };

    // Resolve script file path
    let script_path = if Path::new(file_part).exists() {
        file_part.to_string()
    } else {
        let in_script_dir = root.join("script").join(file_part);
        if in_script_dir.exists() {
            in_script_dir.to_string_lossy().to_string()
        } else {
            return Err(format!("script file not found: {}", file_part));
        }
    };

    // Get network config
    let net = config
        .networks
        .get(network)
        .ok_or_else(|| {
            let available: Vec<&String> = config.networks.keys().collect();
            format!(
                "network '{}' not found in pyde.toml (available: {})",
                network,
                if available.is_empty() { "none".to_string() }
                else { available.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ") }
            )
        })?
        .clone();

    // Build src/ contracts first
    println!("  Building contracts...");
    let build_result = build::build_project(&config, &root)?;
    println!();

    // Read and compile the script
    let source = fs::read_to_string(&script_path)
        .map_err(|e| format!("cannot read {}: {}", script_path, e))?;

    let (tokens, lex_errors) = otic::lexer::Lexer::new(&source).tokenize();
    if !lex_errors.is_empty() {
        return Err(format!("script has lex errors: {:?}", lex_errors[0]));
    }

    let (ast, parse_errors) = otic::parser::Parser::new(tokens).parse();
    if !parse_errors.is_empty() {
        return Err(format!("script has parse errors: {:?}", parse_errors[0]));
    }

    // Compile script using compile_all (handles multi-contract files + inline deploy!).
    // Merge build registry so deploy!(ImportedContract) also works.
    let all_compiled = otic::compile_all(&source);

    // Find the target contract
    let target_name = contract_filter.as_deref()
        .or_else(|| {
            // Auto-detect: find the last contract (usually the script contract)
            all_compiled.last().map(|(name, _)| name.as_str())
        })
        .ok_or_else(|| format!("no contracts found in {}", script_path))?
        .to_string();

    if !all_compiled.iter().any(|(name, _)| name == &target_name) {
        return Err(format!("contract '{}' not found in {}", target_name, script_path));
    }

    // Re-lower the target contract with external registries for deploy! of imported contracts
    let mut merged_registry = build_result.compiled_registry.clone();
    // Add inline-compiled contracts to registry
    for (name, contract) in &all_compiled {
        if name != &target_name {
            let clen = contract.constructor_bytecode.len() as u32;
            let rlen = contract.runtime_bytecode.len() as u32;
            let mut deploy = Vec::with_capacity(8 + clen as usize + rlen as usize);
            deploy.extend_from_slice(&clen.to_le_bytes());
            deploy.extend_from_slice(&rlen.to_le_bytes());
            deploy.extend_from_slice(&contract.constructor_bytecode);
            deploy.extend_from_slice(&contract.runtime_bytecode);
            merged_registry.insert(name.clone(), deploy);
        }
    }

    // Re-lower with merged registry to get correct IR for the script contract
    let mut single = otic::ast::SourceFile { items: Vec::new() };
    for item in &ast.items {
        match item {
            otic::ast::Item::Contract(c) if c.name.name == target_name => {
                single.items.push(item.clone());
            }
            otic::ast::Item::Contract(_) => {}
            _ => single.items.push(item.clone()),
        }
    }
    let mut ir = otic::lower::lower_with_context(
        &single,
        &merged_registry,
        &build_result.contract_functions,
        &build_result.contract_constructors,
    );
    otic::optimize::optimize(&mut ir);

    // Find entry point
    let entry_fn = ir.functions.iter().find(|f| f.is_pub && !f.is_constructor);
    if entry_fn.is_none() {
        return Err(format!("no pub function found in {}", target_name));
    }

    let codegen = otic::codegen::CodeGen::new();
    let compiled = codegen.generate(&ir);

    let sender_addr = parse_address(from)?;

    println!("  Running script: {}", script_path);
    println!("  Network: {} ({})", network, net.rpc_url);
    println!("  From: {}", from);

    // Fetch sender nonce
    let mut nonce = fetch_nonce(&net.rpc_url, from)?;
    println!("  Nonce: {}", nonce);
    println!();

    // Run constructor if present
    let constructor_storage = if !compiled.constructor_bytecode.is_empty() {
        let ctx = pyde_vm::vm::ExecutionContext {
            caller: sender_addr,
            self_address: sender_addr,
            ..Default::default()
        };
        let mut vm = Vm::with_gas_limit_and_context(100_000_000, ctx);
        if let Err(e) = vm.load(&compiled.constructor_bytecode) {
            return Err(format!("script constructor load error: {:?}", e));
        }
        let output = vm.execute();
        if output.outcome != Outcome::Success {
            return Err(format!("script constructor failed: {:?}", output.outcome));
        }
        vm.storage.clone()
    } else {
        std::collections::HashMap::new()
    };

    // Run the script with RPC bridge
    let entry_name = ir.functions.iter()
        .find(|f| f.is_pub && !f.is_constructor)
        .unwrap()
        .name
        .clone();
    let selector = otic::codegen::compute_selector(&entry_name);

    let ctx = pyde_vm::vm::ExecutionContext {
        caller: sender_addr,
        self_address: sender_addr,
        ..Default::default()
    };
    let mut vm = Vm::with_gas_limit_and_context(100_000_000, ctx);
    vm.calldata = selector.to_be_bytes().to_vec();
    if let Err(e) = vm.load(&compiled.runtime_bytecode) {
        return Err(format!("script load error: {:?}", e));
    }
    vm.storage = constructor_storage;

    // Build selector → function info map for view/non-view detection
    let mut selector_info: std::collections::HashMap<u32, FnInfo> = std::collections::HashMap::new();
    for (_, fns) in &build_result.contract_functions {
        for (name, _params, ret_ty) in fns {
            let sel = otic::codegen::compute_selector(name);
            selector_info.insert(sel, FnInfo {
                name: name.clone(),
                is_view: false, // contract_functions doesn't track is_view — conservative default
                return_ty: ret_ty.clone(),
            });
        }
    }
    // Also check IR for view functions
    for func in &ir.functions {
        if func.is_view {
            let sel = otic::codegen::compute_selector(&func.name);
            if let Some(info) = selector_info.get_mut(&sel) {
                info.is_view = true;
            } else {
                selector_info.insert(sel, FnInfo {
                    name: func.name.clone(),
                    is_view: true,
                    return_ty: func.return_ty.clone(),
                });
            }
        }
    }

    // Execute with RPC bridge
    let mut tx_count = 0u32;
    let outcome = execute_with_rpc_bridge(
        &mut vm,
        &sender_addr,
        &net.rpc_url,
        from,
        &mut nonce,
        &mut tx_count,
        &merged_registry,
        &selector_info,
    )?;

    match outcome {
        Outcome::Success => {
            println!("\n  Script completed ({} transactions sent)", tx_count);
        }
        Outcome::Revert => {
            return Err(format!("script reverted after {} transactions", tx_count));
        }
        other => {
            return Err(format!("script failed: {:?} after {} transactions", other, tx_count));
        }
    }

    let elapsed = start.elapsed();
    println!("  Done ({:.2}s)", elapsed.as_secs_f64());
    Ok(())
}

/// Execute the script PVM with an RPC bridge for external operations.
///
/// When the PVM hits Create or CallExt, the operation is forwarded to the
/// chain via RPC. Return values are injected back into PVM registers.
fn execute_with_rpc_bridge(
    vm: &mut Vm,
    script_addr: &[u8; 32],
    rpc_url: &str,
    from: &str,
    nonce: &mut u64,
    tx_count: &mut u32,
    compiled_registry: &std::collections::HashMap<String, Vec<u8>>,
    selector_info: &std::collections::HashMap<u32, FnInfo>,
) -> Result<Outcome, String> {
    vm.clear_journal();
    let client = reqwest::blocking::Client::new();
    let zero_addr = "0x0000000000000000000000000000000000000000000000000000000000000000";

    loop {
        let idx = (vm.pc / 4) as usize;
        let maybe_instr = vm.decoded_cache().get(idx).copied();

        if let Some(d) = maybe_instr {
            // Intercept Create (deploy!) → forward to chain
            if d.opcode == Opcode::Create {
                // Save heap pointer — reclaim after RPC (deploy data no longer needed)
                let heap_before = vm.cpu.read_gp(12);
                let code_ptr = vm.cpu.read_gp(d.rs1) as u32;
                let len_reg = (d.rs2_or_imm & 0xF) as u8;
                let code_len = vm.cpu.read_gp(len_reg) as usize;

                let init_code = vm.memory.checked_read_slice(code_ptr, code_len)
                    .map_err(|_| "failed to read deploy bytecode from memory")?;

                // Match against build registry for the contract name
                let contract_name = find_contract_name(&init_code, compiled_registry);

                // Deploy data is [clen(4 LE)][rlen(4 LE)][constructor][runtime][args].
                // Split into code (constructor+runtime) and args for the RPC.
                let constructor_len = if init_code.len() >= 4 {
                    u32::from_le_bytes(init_code[..4].try_into().unwrap_or([0; 4]))
                } else { 0 };
                let runtime_len = if init_code.len() >= 8 {
                    u32::from_le_bytes(init_code[4..8].try_into().unwrap_or([0; 4]))
                } else { 0 };
                let code_end = 8 + constructor_len as usize + runtime_len as usize;
                // data = constructor + runtime ONLY (no args, no header)
                let code_only = if init_code.len() >= code_end {
                    &init_code[8..code_end]
                } else if init_code.len() >= 8 {
                    &init_code[8..]
                } else {
                    &init_code[..]
                };
                // args = everything after constructor + runtime
                let constructor_args = if init_code.len() > code_end {
                    &init_code[code_end..]
                } else {
                    &[]
                };

                println!("    [{}] deploy {} ({} bytes)", tx_count, contract_name, code_only.len());

                let mut params = serde_json::json!({
                    "from": from,
                    "to": zero_addr,
                    "data": format!("0x{}", hex::encode(code_only)),
                    "gas": 100_000_000,
                    "nonce": *nonce,
                    "value": "0",
                    "constructorLen": constructor_len,
                });
                if !constructor_args.is_empty() {
                    params["constructorArgs"] = serde_json::Value::String(
                        format!("0x{}", hex::encode(constructor_args))
                    );
                }

                let body = serde_json::json!({
                    "jsonrpc": "2.0", "id": *tx_count + 1,
                    "method": "pyde_sendTransaction",
                    "params": [params]
                });

                let resp = client.post(rpc_url).json(&body).send()
                    .map_err(|e| format!("RPC error: {} — is the node running?", e))?;
                let resp_json: serde_json::Value = resp.json()
                    .map_err(|e| format!("invalid RPC response: {}", e))?;

                if let Some(err) = resp_json.get("error") {
                    return Err(format!("deploy failed: {}", err));
                }

                // Extract tx hash from response, then poll receipt for authoritative address.
                // The receipt's returnData contains the actual deployed contract address (32 bytes).
                let result_str = resp_json.get("result").and_then(|v| v.as_str()).unwrap_or("");
                let tx_hash = if let Ok(inner) = serde_json::from_str::<serde_json::Value>(result_str) {
                    inner.get("txHash").and_then(|v| v.as_str())
                        .unwrap_or(result_str).to_string()
                } else {
                    result_str.to_string()
                };

                let contract_addr = poll_receipt_for_address(&client, rpc_url, &tx_hash)?;
                println!("         → 0x{}", hex::encode(&contract_addr[..4]));

                // Write contract address back to PVM wide register
                vm.cpu.write_wide(d.rd, U256::from_le_bytes(contract_addr));
                // Register the deployed bytecode locally so subsequent CallExts
                // to this address during simulation can be identified
                vm.contracts.insert(contract_addr, vec![]);

                *nonce += 1;
                *tx_count += 1;
                // Reclaim heap used for deploy bytecode setup
                vm.cpu.write_gp(12, heap_before);
                vm.pc += 4;
                continue;
            }

            // Intercept CallExt → forward to chain
            if d.opcode == Opcode::CallExt {
                let target: [u8; 32] = vm.cpu.read_wide(d.rd).to_le_bytes();

                // Skip internal calls (to script itself) and cheatcode address
                if target != *script_addr && target != [0xCC; 32] {
                    let calldata_ptr = vm.cpu.read_gp(d.rs1) as u32;
                    let len_reg = (d.rs2_or_imm & 0xF) as u8;
                    let calldata_len = vm.cpu.read_gp(len_reg) as usize;
                    let result_reg = ((d.rs2_or_imm >> 8) & 0xF) as u8;
                    // Save heap pointer — reclaim after RPC (calldata no longer needed)
                    let heap_before = vm.cpu.read_gp(12);

                    let calldata = vm.memory.checked_read_slice(calldata_ptr, calldata_len)
                        .map_err(|_| "failed to read calldata from memory")?;
                    let target_hex = format!("0x{}", hex::encode(target));
                    let calldata_hex = format!("0x{}", hex::encode(&calldata));

                    // Extract selector to determine view vs state-changing
                    let selector = if calldata.len() >= 4 {
                        u32::from_be_bytes(calldata[..4].try_into().unwrap_or([0; 4]))
                    } else {
                        0
                    };
                    let fn_info = selector_info.get(&selector);
                    let is_view = fn_info.map(|f| f.is_view).unwrap_or(false);
                    let fn_name = fn_info.map(|f| f.name.as_str()).unwrap_or("unknown");

                    if is_view {
                        // View call: pyde_call (read-only, no nonce, no state change)
                        println!("    [view] {}.{}()", &target_hex[..10], fn_name);

                        let body = serde_json::json!({
                            "jsonrpc": "2.0", "id": *tx_count + 1,
                            "method": "pyde_call",
                            "params": [{
                                "from": from,
                                "to": target_hex,
                                "data": calldata_hex,
                            }]
                        });

                        let resp = client.post(rpc_url).json(&body).send()
                            .map_err(|e| format!("RPC error: {}", e))?;
                        let resp_json: serde_json::Value = resp.json()
                            .map_err(|e| format!("invalid RPC response: {}", e))?;

                        if let Some(err) = resp_json.get("error") {
                            println!("           → FAILED: {}", err);
                            vm.cpu.write_gp(result_reg, 0);
                        } else {
                            // pyde_call returns result directly as hex string
                            let result_hex = resp_json.get("result")
                                .and_then(|v| v.as_str()).unwrap_or("0x");
                            let return_data = hex::decode(
                                result_hex.strip_prefix("0x").unwrap_or(result_hex)
                            ).unwrap_or_default();

                            inject_return_data(vm, &return_data, fn_info);
                            vm.cpu.write_gp(result_reg, 1);
                            println!("           → {} bytes", return_data.len());
                        }
                        // View calls don't consume nonce
                    } else {
                        // State-changing call: pyde_sendTransaction
                        println!("    [{}] {}.{}()", tx_count, &target_hex[..10], fn_name);

                        let body = serde_json::json!({
                            "jsonrpc": "2.0", "id": *tx_count + 1,
                            "method": "pyde_sendTransaction",
                            "params": [{
                                "from": from,
                                "to": target_hex,
                                "data": calldata_hex,
                                "gas": 100_000_000,
                                "nonce": *nonce,
                                "value": "0"
                            }]
                        });

                        let resp = client.post(rpc_url).json(&body).send()
                            .map_err(|e| format!("RPC error: {}", e))?;
                        let resp_json: serde_json::Value = resp.json()
                            .map_err(|e| format!("invalid RPC response: {}", e))?;

                        if let Some(err) = resp_json.get("error") {
                            println!("         → FAILED: {}", err);
                            vm.cpu.write_gp(result_reg, 0);
                        } else {
                            // Poll receipt for authoritative return data
                            let result_str = resp_json.get("result")
                                .and_then(|v| v.as_str()).unwrap_or("");
                            let tx_hash = extract_tx_hash(result_str);
                            let (success, return_data) = poll_receipt_for_return_data(&client, rpc_url, &tx_hash);
                            if success {
                                inject_return_data(vm, &return_data, fn_info);
                                vm.cpu.write_gp(result_reg, 1);
                                println!("         → ok");
                            } else {
                                println!("         → REVERTED");
                                vm.cpu.write_gp(result_reg, 0);
                            }
                        }

                        *nonce += 1;
                        *tx_count += 1;
                    }
                    // Reclaim heap used for calldata setup — the RPC already read it
                    vm.cpu.write_gp(12, heap_before);
                    vm.pc += 4;
                    continue;
                }
            }
        }

        // Normal PVM step (internal logic)
        match vm.step() {
            Ok(Some(ExecResult::Halt)) => {
                vm.clear_journal();
                return Ok(Outcome::Success);
            }
            Ok(Some(ExecResult::Revert)) => {
                vm.clear_journal();
                return Ok(Outcome::Revert);
            }
            Ok(None) => {}
            Err(pyde_vm::cpu::Trap::OutOfGas) => {
                vm.clear_journal();
                return Ok(Outcome::OutOfGas);
            }
            Err(trap) => {
                vm.clear_journal();
                return Ok(Outcome::Trap(trap));
            }
        }
    }
}

/// Inject return data from RPC response back into PVM registers/memory.
/// Handles GP (u64, bool), wide (u256, Address), and blob (Vec, String, struct) returns.
fn inject_return_data(vm: &mut Vm, return_data: &[u8], fn_info: Option<&FnInfo>) {
    if return_data.is_empty() {
        vm.cpu.write_gp(1, 0);
        vm.cpu.write_gp(2, 0);
        return;
    }

    let is_wide = fn_info.map(|f| matches!(f.return_ty, Ty::U256 | Ty::I256 | Ty::Address | Ty::Contract(_) | Ty::Interface(_))).unwrap_or(false);
    let is_blob = fn_info.map(|f| matches!(f.return_ty, Ty::Vec(_) | Ty::StringTy | Ty::Bytes | Ty::Struct(_))).unwrap_or(false);

    if is_wide && return_data.len() >= 32 {
        // Wide return: write 32 bytes to heap, r1 = ptr, r2 = 32
        let heap = vm.cpu.read_gp(12) as u32;
        let _ = vm.memory.checked_write_slice(heap, &return_data[..32]);
        vm.cpu.write_gp(1, heap as u64);
        vm.cpu.write_gp(2, 32);
    } else if is_blob {
        // Blob return: write full data to heap, r1 = ptr, r2 = len
        let heap = vm.cpu.read_gp(12) as u32;
        let _ = vm.memory.checked_write_slice(heap, return_data);
        vm.cpu.write_gp(1, heap as u64);
        vm.cpu.write_gp(2, return_data.len() as u64);
    } else {
        // GP return: r1 = value (first 8 bytes LE), r2 = 0
        let mut buf = [0u8; 8];
        let len = return_data.len().min(8);
        buf[..len].copy_from_slice(&return_data[..len]);
        vm.cpu.write_gp(1, u64::from_le_bytes(buf));
        vm.cpu.write_gp(2, 0);
    }
}

/// Extract txHash from a sendTransaction result string.
fn extract_tx_hash(result_str: &str) -> String {
    if let Ok(inner) = serde_json::from_str::<serde_json::Value>(result_str) {
        inner.get("txHash").and_then(|v| v.as_str())
            .unwrap_or(result_str).to_string()
    } else {
        result_str.to_string()
    }
}

/// Poll `pyde_getTransactionReceipt` until the receipt is available, then
/// extract the contract address from returnData (32 bytes for deploy txs).
fn poll_receipt_for_address(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Result<[u8; 32], String> {
    let receipt = poll_receipt(client, rpc_url, tx_hash)?;
    let success = receipt.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    if !success {
        return Err(format!("deploy transaction reverted (tx {})", tx_hash));
    }
    let return_data_hex = receipt.get("returnData")
        .and_then(|v| v.as_str()).unwrap_or("");
    let hex = return_data_hex.strip_prefix("0x").unwrap_or(return_data_hex);
    if hex.len() == 64 {
        parse_address(&format!("0x{}", hex))
    } else {
        Err(format!("deploy receipt missing contract address in returnData (got {} bytes)", hex.len() / 2))
    }
}

/// Poll receipt and extract returnData for non-deploy calls.
/// Returns (success, return_data).
fn poll_receipt_for_return_data(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    tx_hash: &str,
) -> (bool, Vec<u8>) {
    let receipt = match poll_receipt(client, rpc_url, tx_hash) {
        Ok(r) => r,
        Err(_) => return (false, vec![]),
    };
    let success = receipt.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
    let hex_str = receipt.get("returnData")
        .and_then(|v| v.as_str()).unwrap_or("");
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    (success, hex::decode(hex).unwrap_or_default())
}

/// Poll `pyde_getTransactionReceipt` with retries until the receipt appears.
fn poll_receipt(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    tx_hash: &str,
) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getTransactionReceipt",
        "params": [tx_hash]
    });
    for attempt in 0..50 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let resp = client.post(rpc_url).json(&body).send()
            .map_err(|e| format!("RPC error polling receipt: {}", e))?;
        let json: serde_json::Value = resp.json()
            .map_err(|e| format!("invalid receipt response: {}", e))?;
        if json.get("error").is_none() {
            if let Some(result) = json.get("result") {
                if !result.is_null() {
                    return Ok(result.clone());
                }
            }
        }
    }
    Err(format!("receipt not available after 5s for tx {}", tx_hash))
}

/// Find a contract name by matching deploy bytecode against the build registry.
fn find_contract_name(
    init_code: &[u8],
    registry: &std::collections::HashMap<String, Vec<u8>>,
) -> String {
    for (name, deploy_bytes) in registry {
        if deploy_bytes == init_code {
            return name.clone();
        }
        // Also check if init_code starts with deploy_bytes (may have args appended)
        if init_code.len() >= deploy_bytes.len() && &init_code[..deploy_bytes.len()] == deploy_bytes.as_slice() {
            return name.clone();
        }
    }
    "unknown".to_string()
}

fn fetch_nonce(rpc_url: &str, address: &str) -> Result<u64, String> {
    let client = reqwest::blocking::Client::new();
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1,
        "method": "pyde_getTransactionCount",
        "params": [address]
    });
    let resp = client.post(rpc_url).json(&body).send()
        .map_err(|e| format!("cannot fetch nonce: {}", e))?;
    let json: serde_json::Value = resp.json()
        .map_err(|e| format!("invalid nonce response: {}", e))?;
    json.get("result").and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| "failed to parse nonce".into())
}

fn parse_address(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(format!("invalid address: expected 64 hex chars, got {}", hex.len()));
    }
    let bytes = hex::decode(hex).map_err(|e| format!("invalid address hex: {}", e))?;
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== parse_address ==========

    #[test]
    fn parse_address_valid() {
        let hex = "0x0101010101010101010101010101010101010101010101010101010101010101";
        let addr = parse_address(hex).unwrap();
        assert_eq!(addr, [0x01; 32]);
    }

    #[test]
    fn parse_address_no_prefix() {
        let hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let addr = parse_address(hex).unwrap();
        assert_eq!(addr, [0xAA; 32]);
    }

    #[test]
    fn parse_address_invalid_length() {
        assert!(parse_address("0x1234").is_err());
    }

    #[test]
    fn parse_address_invalid_hex() {
        let bad = "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";
        assert!(parse_address(bad).is_err());
    }

    // ========== find_contract_name ==========

    #[test]
    fn find_contract_name_exact_match() {
        let mut registry = std::collections::HashMap::new();
        registry.insert("Counter".to_string(), vec![1, 2, 3, 4]);
        assert_eq!(find_contract_name(&[1, 2, 3, 4], &registry), "Counter");
    }

    #[test]
    fn find_contract_name_prefix_match() {
        let mut registry = std::collections::HashMap::new();
        registry.insert("Counter".to_string(), vec![1, 2, 3, 4]);
        // init_code has deploy bytes + constructor args appended
        assert_eq!(find_contract_name(&[1, 2, 3, 4, 5, 6], &registry), "Counter");
    }

    #[test]
    fn find_contract_name_no_match() {
        let registry = std::collections::HashMap::new();
        assert_eq!(find_contract_name(&[1, 2, 3], &registry), "unknown");
    }

    // ========== extract_tx_hash ==========

    #[test]
    fn extract_tx_hash_from_json() {
        let result = r#"{"txHash":"0xaabb"}"#;
        assert_eq!(extract_tx_hash(result), "0xaabb");
    }

    #[test]
    fn extract_tx_hash_plain_string() {
        assert_eq!(extract_tx_hash("0xdeadbeef"), "0xdeadbeef");
    }

    #[test]
    fn extract_tx_hash_with_contract_address() {
        let result = r#"{"txHash":"0x1234","contractAddress":"0xabcd"}"#;
        assert_eq!(extract_tx_hash(result), "0x1234");
    }

    // ========== inject_return_data ==========

    #[test]
    fn inject_gp_return() {
        let mut vm = Vm::new();
        vm.memory.heap_alloc(1024).unwrap(); // make heap space
        let info = FnInfo { name: "get".into(), is_view: true, return_ty: Ty::U64 };
        let data = 42u64.to_le_bytes().to_vec();
        inject_return_data(&mut vm, &data, Some(&info));
        assert_eq!(vm.cpu.read_gp(1), 42);
        assert_eq!(vm.cpu.read_gp(2), 0);
    }

    #[test]
    fn inject_wide_return() {
        let mut vm = Vm::new();
        // Need heap space — advance past code section
        vm.cpu.write_gp(12, pyde_vm::memory::HEAP_START as u64);
        let info = FnInfo { name: "get".into(), is_view: true, return_ty: Ty::U256 };
        let mut data = vec![0u8; 32];
        data[0] = 0xAB;
        data[31] = 0xCD;
        inject_return_data(&mut vm, &data, Some(&info));
        assert_eq!(vm.cpu.read_gp(1), pyde_vm::memory::HEAP_START as u64);
        assert_eq!(vm.cpu.read_gp(2), 32);
    }

    #[test]
    fn inject_blob_return() {
        let mut vm = Vm::new();
        vm.cpu.write_gp(12, pyde_vm::memory::HEAP_START as u64);
        let info = FnInfo { name: "get".into(), is_view: true, return_ty: Ty::StringTy };
        let data = b"hello world".to_vec();
        inject_return_data(&mut vm, &data, Some(&info));
        assert_eq!(vm.cpu.read_gp(1), pyde_vm::memory::HEAP_START as u64);
        assert_eq!(vm.cpu.read_gp(2), 11); // "hello world" = 11 bytes
    }

    #[test]
    fn deploy_macro_produces_create_instruction() {
        // Verify that deploy!(Counter) actually produces CreateContract IR
        // when Counter is in the compiled_contracts registry
        let src = r#"
            contract DeployScript {
                pub fn run() {
                    let c = deploy!(Counter);
                }
            }
        "#;
        let mut registry = std::collections::HashMap::new();
        registry.insert("Counter".to_string(), vec![0x01, 0x02, 0x03, 0x04]);

        let (tokens, _) = otic::lexer::Lexer::new(src).tokenize();
        let (ast, _) = otic::parser::Parser::new(tokens).parse();
        let ir = otic::lower::lower_with_context(
            &ast,
            &registry,
            &std::collections::HashMap::new(),
            &std::collections::HashMap::new(),
        );

        // Check that at least one function has a CreateContract instruction
        let has_create = ir.functions.iter().any(|f| {
            f.blocks.iter().any(|b| {
                b.instructions.iter().any(|inst| {
                    let s = format!("{}", inst);
                    s.contains("create(") || s.contains("create_contract")
                })
            })
        });
        // Debug: print all instructions
        for func in &ir.functions {
            for block in &func.blocks {
                for inst in &block.instructions {
                    eprintln!("  IR: {}", inst);
                }
            }
        }
        assert!(has_create, "deploy!(Counter) should produce a CreateContract instruction");
    }

    #[test]
    fn inject_empty_return() {
        let mut vm = Vm::new();
        inject_return_data(&mut vm, &[], None);
        assert_eq!(vm.cpu.read_gp(1), 0);
        assert_eq!(vm.cpu.read_gp(2), 0);
    }
}
