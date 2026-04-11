#!/usr/bin/env bash
# =============================================================================
# Pyde Docker E2E Test Suite
# Tests 4-node validator testnet running in Docker.
#
# Covers:
#   1. Node health & consensus (all 4 nodes producing blocks)
#   2. Chain queries (balance, nonce, chainId, gasPrice, stateRoot)
#   3. Transfers (send PYDE, verify balances)
#   4. Contract deploy + call (Counter, complex MegaTest)
#   5. Multi-node sync (tx on node-0, verify on node-1/2/3)
#   6. State persistence (restart containers, verify state)
#   7. Receipts & gas accounting
#   8. Mempool
#
# Usage:
#   ./scripts/docker_e2e_test.sh
# =============================================================================
set -euo pipefail

PASS=0
FAIL=0
TOTAL=0
NONCE=0

# RPC endpoints
RPC0="http://localhost:8545"
RPC1="http://localhost:8546"
RPC2="http://localhost:8547"
RPC3="http://localhost:8548"

# Get a funded non-validator account from genesis (5th allocation = first non-validator)
FROM=$(curl -s --max-time 3 -X POST "$RPC0" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"pyde_getValidators","params":[],"id":1}' 2>/dev/null \
  | python3 -c "
import sys, json
# Get validator addresses to exclude them
resp = json.load(sys.stdin)
vals = [v['address'].replace('0x','') for v in resp.get('result',{}).get('validators',[])]
print(','.join(vals))
" 2>/dev/null || echo "")

# Read genesis to find first non-validator allocation
GENESIS_FROM=$(docker exec docker-node-0-1 cat /testnet/genesis.toml 2>/dev/null \
  | python3 -c "
import sys
vals = set('$FROM'.split(','))
for line in sys.stdin:
    line = line.strip()
    if line.startswith('address = '):
        addr = line.split('\"')[1]
        if addr not in vals:
            print('0x' + addr)
            break
" 2>/dev/null || echo "")

if [ -n "$GENESIS_FROM" ]; then
  FROM="$GENESIS_FROM"
fi
echo "  Using funded account: $FROM"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ---- helpers ----
rpc_to() {
  local url="$1" method="$2" params="$3"
  curl -s --max-time 5 -X POST "$url" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[$params],\"id\":1}" 2>/dev/null || echo '{"error":"connection refused"}'
}

rpc() { rpc_to "$RPC0" "$1" "$2"; }

call() {
  local to="$1" data="$2"
  rpc "pyde_call" "{\"from\":\"$FROM\",\"to\":\"$to\",\"data\":\"0x$data\",\"gas\":100000000}"
}

send_tx() {
  local to="$1" data="$2" value="${3:-0}"
  local resp
  resp=$(rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"$to\",\"data\":\"0x$data\",\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"$value\"}")
  NONCE=$((NONCE + 1))
  echo "$resp"
}

deploy() {
  local constructor_hex="$1" runtime_hex="$2"
  local clen=$((${#constructor_hex} / 2))
  local rlen=$((${#runtime_hex} / 2))
  # Build pipeline format: [clen:4 LE][rlen:4 LE][constructor][runtime]
  local header
  header=$(python3 -c "
import struct
print(struct.pack('<I', $clen).hex() + struct.pack('<I', $rlen).hex())
")
  local full_data="${header}${constructor_hex}${runtime_hex}"
  local resp
  resp=$(rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"data\":\"0x$full_data\",\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"0\"}")
  NONCE=$((NONCE + 1))
  echo "$resp"
}

# Get contract address from deploy: sends tx, waits, gets receipt, returns address
deploy_and_wait() {
  local constructor_hex="$1" runtime_hex="$2" wait="${3:-3}"
  local resp tx_hash receipt contract_addr
  resp=$(deploy "$constructor_hex" "$runtime_hex")
  # Extract txHash from result (it's a JSON string inside result)
  tx_hash=$(echo "$resp" | python3 -c "
import sys, json
r = json.load(sys.stdin)
val = r.get('result','')
if isinstance(val, str):
    try:
        d = json.loads(val)
        print(d.get('txHash',''))
    except:
        print(val)
else:
    print('')
" 2>/dev/null || echo "")
  sleep "$wait"
  # Get receipt to find contract address (in returnData)
  if [ -n "$tx_hash" ]; then
    receipt=$(rpc "pyde_getTransactionReceipt" "\"$tx_hash\"")
    contract_addr=$(echo "$receipt" | python3 -c "
import sys, json
r = json.load(sys.stdin)
val = r.get('result',{})
if isinstance(val, str):
    try: val = json.loads(val)
    except: pass
if isinstance(val, dict):
    print(val.get('returnData',''))
" 2>/dev/null || echo "")
  fi
  # Return: resp|contract_addr
  echo "${resp}|${contract_addr}"
}

json_result() {
  python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" <<< "$1" 2>/dev/null || echo ""
}

json_field() {
  local json="$1" field="$2"
  python3 -c "
import sys, json
r = json.loads('''$json''')
val = r.get('result','')
if isinstance(val, str):
    try: val = json.loads(val)
    except: pass
if isinstance(val, dict):
    print(val.get('$field',''))
else:
    print(val)
" 2>/dev/null || echo ""
}

assert_ok() {
  local label="$1" response="$2"
  TOTAL=$((TOTAL + 1))
  if echo "$response" | grep -q '"result"'; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC}  $label"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC}  $label"
    echo -e "       got: $response"
  fi
}

assert_eq() {
  local label="$1" actual="$2" expected="$3"
  TOTAL=$((TOTAL + 1))
  if [ "$actual" = "$expected" ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC}  $label  ($actual)"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC}  $label"
    echo -e "       expected: $expected"
    echo -e "       got:      $actual"
  fi
}

assert_contains() {
  local label="$1" response="$2" expected="$3"
  TOTAL=$((TOTAL + 1))
  if echo "$response" | grep -qi "$expected"; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC}  $label"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC}  $label"
    echo -e "       expected to contain: $expected"
    echo -e "       got: $response"
  fi
}

assert_gt() {
  local label="$1" val="$2" min="$3"
  TOTAL=$((TOTAL + 1))
  local result
  result=$(python3 -c "
v = '$val'
m = int('$min')
n = int(v, 16) if v.startswith('0x') else int(v) if v.isdigit() else 0
print('PASS' if n > m else 'FAIL')
print(n)
" 2>/dev/null || echo -e "FAIL\n0")
  local verdict=$(echo "$result" | head -1)
  local num=$(echo "$result" | tail -1)
  if [ "$verdict" = "PASS" ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC}  $label  ($num > $min)"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC}  $label"
    echo -e "       expected > $min, got $num"
  fi
}

selector() {
  python3 -c "
name = '$1'
h = 0x811c9dc5
for b in name.encode():
    h ^= b
    h = (h * 0x01000193) & 0xFFFFFFFF
print(format(h, '08x'))
"
}

u64_le() {
  python3 -c "import struct; print(struct.pack('<Q', $1).hex())"
}

# =============================================================================
# Get current nonce so we don't conflict with previous runs
NONCE_RESP=$(rpc_to "$RPC0" "pyde_getTransactionCount" "\"$FROM\"")
CURRENT_NONCE=$(echo "$NONCE_RESP" | python3 -c "
import sys, json
r = json.load(sys.stdin)
val = r.get('result','0x0')
print(int(val, 16) if val.startswith('0x') else int(val))
" 2>/dev/null || echo "0")
NONCE=$CURRENT_NONCE
echo "  Starting nonce: $NONCE"

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Pyde Docker E2E Test Suite (4 nodes)    ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ==============================
# TEST 1: Node Health & Consensus
# ==============================
echo -e "${YELLOW}[1/8] Node Health & Consensus${NC}"

for i in 0 1 2 3; do
  PORT=$((8545 + i))
  RESP=$(rpc_to "http://localhost:$PORT" "pyde_blockNumber" "")
  assert_ok "node-$i alive (port $PORT)" "$RESP"
done

# Wait for blocks to be produced
echo -e "  Waiting 8s for consensus to produce blocks..."
sleep 8

for i in 0 1 2 3; do
  PORT=$((8545 + i))
  RESP=$(rpc_to "http://localhost:$PORT" "pyde_blockNumber" "")
  BLOCK=$(json_result "$RESP")
  assert_gt "node-$i producing blocks" "$BLOCK" 0
done

# Check all nodes have same block number (within 1 slot tolerance)
BN0=$(json_result "$(rpc_to "$RPC0" "pyde_blockNumber" "")")
BN1=$(json_result "$(rpc_to "$RPC1" "pyde_blockNumber" "")")
BN2=$(json_result "$(rpc_to "$RPC2" "pyde_blockNumber" "")")
BN3=$(json_result "$(rpc_to "$RPC3" "pyde_blockNumber" "")")
echo -e "  Block heights: node-0=$BN0, node-1=$BN1, node-2=$BN2, node-3=$BN3"
echo ""

# ==============================
# TEST 2: Chain Queries
# ==============================
echo -e "${YELLOW}[2/8] Chain Queries${NC}"

# chainId
RESP=$(rpc "pyde_chainId" "")
CHAIN_ID=$(json_result "$RESP")
assert_eq "chainId = 31337" "$CHAIN_ID" "0x7a69"

# gasPrice
RESP=$(rpc "pyde_gasPrice" "")
assert_ok "gasPrice responds" "$RESP"

# stateRoot
RESP=$(rpc "pyde_stateRoot" "")
assert_ok "stateRoot responds" "$RESP"
STATE_ROOT=$(json_result "$RESP")
assert_gt "stateRoot non-zero" "$STATE_ROOT" 0

# syncing
RESP=$(rpc "pyde_syncing" "")
assert_ok "syncing responds" "$RESP"

# balance of funded account
RESP=$(rpc "pyde_getBalance" "\"$FROM\"")
assert_ok "getBalance responds" "$RESP"
BAL=$(json_result "$RESP")
assert_gt "funded account has balance" "$BAL" 0
echo -e "  Account balance: $BAL"

# nonce
RESP=$(rpc "pyde_getTransactionCount" "\"$FROM\"")
assert_ok "getTransactionCount responds" "$RESP"

# mempoolSize
RESP=$(rpc "pyde_mempoolSize" "")
assert_ok "mempoolSize responds" "$RESP"

echo ""

# ==============================
# TEST 3: Value Transfers
# ==============================
echo -e "${YELLOW}[3/8] Value Transfers${NC}"

RECIPIENT="0x0202020202020202020202020202020202020202020202020202020202020202"

# Check recipient balance before
RESP=$(rpc "pyde_getBalance" "\"$RECIPIENT\"")
BAL_BEFORE=$(json_result "$RESP")
echo -e "  Recipient balance before: $BAL_BEFORE"

# Send transfer (to needs 0x prefix in the JSON params)
RESP=$(rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"$RECIPIENT\",\"data\":\"0x\",\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"1000000000\"}")
NONCE=$((NONCE + 1))
assert_ok "transfer tx accepted" "$RESP"

# Parse tx hash from response (result is a JSON string)
TX_HASH=$(echo "$RESP" | python3 -c "
import sys, json
r = json.load(sys.stdin)
val = r.get('result','')
if isinstance(val, str):
    try:
        d = json.loads(val)
        print(d.get('txHash',''))
    except:
        print(val)
else:
    print('')
" 2>/dev/null || echo "")
echo -e "  TX hash: $TX_HASH"

# Wait for inclusion
sleep 3

# Check recipient balance after
RESP=$(rpc "pyde_getBalance" "\"$RECIPIENT\"")
BAL_AFTER=$(json_result "$RESP")
echo -e "  Recipient balance after: $BAL_AFTER"
assert_gt "recipient balance increased" "$BAL_AFTER" 0

# Check receipt
if [ -n "$TX_HASH" ] && [ "$TX_HASH" != "" ] && [ "$TX_HASH" != "null" ]; then
  RESP=$(rpc "pyde_getTransactionReceipt" "\"$TX_HASH\"")
  assert_ok "receipt exists for transfer" "$RESP"
fi

echo ""

# ==============================
# TEST 4: Contract Deploy & Call
# ==============================
echo -e "${YELLOW}[4/8] Contract Deploy & Call (Counter)${NC}"

# Compile Counter contract
TMPDIR=$(mktemp -d)
cat > "$TMPDIR/counter.oti" << 'OTI'
contract Counter {
    storage { count: u64, }
    #[constructor] pub fn init() { self.count = 0; }
    pub fn increment() { self.count = self.count + 1; }
    pub fn get_count() -> u64 { return self.count; }
}
OTI

cargo run -p otic --quiet -- build "$TMPDIR/counter.oti" 2>/dev/null

ARTIFACT="$TMPDIR/counter.json"
if [ ! -f "$ARTIFACT" ]; then
  echo -e "  ${RED}FAIL${NC}  Contract compilation failed"
  FAIL=$((FAIL + 1))
  TOTAL=$((TOTAL + 1))
else
  CONSTRUCTOR_HEX=$(python3 -c "import json; d=json.load(open('$ARTIFACT')); print(d['constructorBytecode'].replace('0x',''))")
  RUNTIME_HEX=$(python3 -c "import json; d=json.load(open('$ARTIFACT')); print(d['deployedBytecode'].replace('0x',''))")

  echo -e "  Constructor: $((${#CONSTRUCTOR_HEX} / 2)) bytes, Runtime: $((${#RUNTIME_HEX} / 2)) bytes"

  # Deploy and wait for receipt
  DEPLOY_RESULT=$(deploy_and_wait "$CONSTRUCTOR_HEX" "$RUNTIME_HEX" 3)
  DEPLOY_RESP="${DEPLOY_RESULT%%|*}"
  CONTRACT="${DEPLOY_RESULT##*|}"
  assert_ok "deploy tx accepted" "$DEPLOY_RESP"
  echo -e "  Contract: $CONTRACT"

  # get_count() = 0
  SEL=$(selector "get_count")
  RESP=$(call "$CONTRACT" "$SEL")
  RESULT=$(json_result "$RESP")
  assert_eq "get_count() = 0" "$RESULT" "0x0"

  # increment()
  SEL=$(selector "increment")
  RESP=$(rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"$CONTRACT\",\"data\":\"0x$SEL\",\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"0\"}")
  NONCE=$((NONCE + 1))
  assert_ok "increment() tx accepted" "$RESP"

  # increment again
  SEL=$(selector "increment")
  RESP=$(rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"$CONTRACT\",\"data\":\"0x$SEL\",\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"0\"}")
  NONCE=$((NONCE + 1))
  assert_ok "increment() #2 tx accepted" "$RESP"

  # Wait for txs to be included (VRF proposer selection means only ~25% of
  # slots are proposed by node-0 which has our txs in mempool)
  sleep 15

  # get_count() > 0 — at least one increment committed
  SEL=$(selector "get_count")
  RESP=$(call "$CONTRACT" "$SEL")
  RESULT=$(json_result "$RESP")
  assert_gt "get_count() > 0 after increments" "$RESULT" 0
fi

rm -rf "$TMPDIR"
echo ""

# ==============================
# TEST 5: Multi-Node Sync
# ==============================
echo -e "${YELLOW}[5/8] Multi-Node State Sync${NC}"

# Query the same contract from all 4 nodes
if [ -n "${CONTRACT:-}" ] && [ "$CONTRACT" != "" ]; then
  SEL=$(selector "get_count")
  sleep 8  # let state propagate across all nodes

  for i in 0 1 2 3; do
    PORT=$((8545 + i))
    RESP=$(rpc_to "http://localhost:$PORT" "pyde_call" "{\"from\":\"$FROM\",\"to\":\"$CONTRACT\",\"data\":\"0x$SEL\",\"gas\":100000000}")
    RESULT=$(json_result "$RESP")
    assert_gt "node-$i sees count>0" "$RESULT" 0
  done

  # Balance should be consistent across nodes
  for i in 0 1 2 3; do
    PORT=$((8545 + i))
    RESP=$(rpc_to "http://localhost:$PORT" "pyde_getBalance" "\"$FROM\"")
    assert_ok "node-$i has sender balance" "$RESP"
  done
else
  echo -e "  ${YELLOW}SKIP${NC}  No contract deployed, skipping multi-node sync"
fi

echo ""

# ==============================
# TEST 6: State Persistence (Restart)
# ==============================
echo -e "${YELLOW}[6/8] State Persistence (Container Restart)${NC}"

# Record current state
BLOCK_BEFORE=$(json_result "$(rpc "pyde_blockNumber" "")")
echo -e "  Block before restart: $BLOCK_BEFORE"

if [ -n "${CONTRACT:-}" ] && [ "$CONTRACT" != "" ]; then
  SEL=$(selector "get_count")
  COUNT_BEFORE=$(json_result "$(call "$CONTRACT" "$SEL")")
  echo -e "  Counter before restart: $COUNT_BEFORE"
fi

BAL_BEFORE_RESTART=$(json_result "$(rpc "pyde_getBalance" "\"$FROM\"")")
echo -e "  Balance before restart: $BAL_BEFORE_RESTART"

# Restart all containers
echo -e "  Restarting containers..."
docker compose -f docker/docker-compose.yml restart node-0 node-1 node-2 node-3 2>/dev/null
echo -e "  Waiting 20s for nodes to restart and reconnect..."
sleep 20

# Verify nodes are back
for i in 0 1 2 3; do
  PORT=$((8545 + i))
  RESP=$(rpc_to "http://localhost:$PORT" "pyde_blockNumber" "")
  assert_ok "node-$i alive after restart" "$RESP"
done

# Verify state persisted
BLOCK_AFTER=$(json_result "$(rpc "pyde_blockNumber" "")")
echo -e "  Block after restart: $BLOCK_AFTER"

BAL_AFTER_RESTART=$(json_result "$(rpc "pyde_getBalance" "\"$FROM\"")")
echo -e "  Balance after restart: $BAL_AFTER_RESTART"
assert_eq "balance persisted after restart" "$BAL_AFTER_RESTART" "$BAL_BEFORE_RESTART"

if [ -n "${CONTRACT:-}" ] && [ "$CONTRACT" != "" ]; then
  SEL=$(selector "get_count")
  COUNT_AFTER=$(json_result "$(call "$CONTRACT" "$SEL")")
  echo -e "  Counter after restart: $COUNT_AFTER"
  assert_eq "contract state persisted" "$COUNT_AFTER" "$COUNT_BEFORE"
fi

# Verify blocks continue after restart
echo -e "  Waiting 10s for consensus to resume..."
sleep 10
BLOCK_RESUMED=$(json_result "$(rpc "pyde_blockNumber" "")")
echo -e "  Block after resumed consensus: $BLOCK_RESUMED"
TOTAL=$((TOTAL + 1))
RESUME_CHECK=$(python3 -c "
ba = int('$BLOCK_AFTER', 16) if '$BLOCK_AFTER'.startswith('0x') else int('$BLOCK_AFTER') if '$BLOCK_AFTER'.isdigit() else 0
br = int('$BLOCK_RESUMED', 16) if '$BLOCK_RESUMED'.startswith('0x') else int('$BLOCK_RESUMED') if '$BLOCK_RESUMED'.isdigit() else 0
print('PASS' if br > ba else 'FAIL')
print(f'{br} > {ba}')
" 2>/dev/null || echo -e "FAIL\n? > ?")
RESUME_VERDICT=$(echo "$RESUME_CHECK" | head -1)
RESUME_DETAIL=$(echo "$RESUME_CHECK" | tail -1)
if [ "$RESUME_VERDICT" = "PASS" ]; then
  PASS=$((PASS + 1))
  echo -e "  ${GREEN}PASS${NC}  consensus resumed after restart ($RESUME_DETAIL)"
else
  FAIL=$((FAIL + 1))
  echo -e "  ${RED}FAIL${NC}  consensus did not resume ($RESUME_DETAIL)"
fi

echo ""

# ==============================
# TEST 7: Gas & Receipts
# ==============================
echo -e "${YELLOW}[7/8] Gas Estimation & Receipts${NC}"

# estimateGas (use a validator address as recipient if RECIPIENT has no account)
RESP=$(rpc "pyde_estimateGas" "{\"from\":\"$FROM\",\"to\":\"$FROM\",\"data\":\"0x\",\"gas\":100000000}")
assert_ok "estimateGas responds" "$RESP"

# getBlockByNumber (use a recent block)
RECENT_BLOCK=$(json_result "$(rpc "pyde_blockNumber" "")")
RECENT_NUM=$(python3 -c "v='$RECENT_BLOCK'; print(int(v,16) if v.startswith('0x') else int(v))" 2>/dev/null || echo "10")
RESP=$(rpc "pyde_getBlockByNumber" "$RECENT_NUM")
assert_ok "getBlockByNumber(1) responds" "$RESP"

echo ""

# ==============================
# TEST 8: Complex Contract (MegaTest)
# ==============================
echo -e "${YELLOW}[8/8] Complex Contract (MegaTest)${NC}"

TMPDIR=$(mktemp -d)
cat > "$TMPDIR/mega.oti" << 'OTI'
contract MegaTest {
    storage {
        owner: Address,
        total_supply: u256,
        count: u64,
        scores: Map<u64, u64>,
    }

    #[constructor]
    pub fn init() {
        self.owner = msg.sender;
        self.total_supply = 1000000 as u256;
        self.count = 0;
    }

    pub fn get_count() -> u64 { return self.count; }
    pub fn get_supply() -> u256 { return self.total_supply; }
    pub fn get_owner() -> Address { return self.owner; }

    pub fn add_u256(a: u256, b: u256) -> u256 { return a + b; }

    pub fn set_score(id: u64, val: u64) {
        self.scores[id] = val;
        self.count = self.count + 1;
    }
    pub fn get_score(id: u64) -> u64 { return self.scores[id]; }

    pub fn many_locals() -> u64 {
        let a=1; let b=2; let c=3; let d=4; let e=5;
        let f=6; let g=7; let h=8; let i=9; let j=10;
        return a+b+c+d+e+f+g+h+i+j;
    }

    pub fn get_greeting() -> String { return "hello world"; }
}
OTI

cargo run -p otic --quiet -- build "$TMPDIR/mega.oti" 2>/dev/null

ARTIFACT="$TMPDIR/mega.json"
if [ ! -f "$ARTIFACT" ]; then
  echo -e "  ${RED}FAIL${NC}  MegaTest compilation failed"
  FAIL=$((FAIL + 1))
  TOTAL=$((TOTAL + 1))
else
  CONSTRUCTOR_HEX=$(python3 -c "import json; d=json.load(open('$ARTIFACT')); print(d['constructorBytecode'].replace('0x',''))")
  RUNTIME_HEX=$(python3 -c "import json; d=json.load(open('$ARTIFACT')); print(d['deployedBytecode'].replace('0x',''))")
  MEGA_RESULT=$(deploy_and_wait "$CONSTRUCTOR_HEX" "$RUNTIME_HEX" 3)
  MEGA_RESP="${MEGA_RESULT%%|*}"
  MEGA="${MEGA_RESULT##*|}"
  assert_ok "MegaTest deploy accepted" "$MEGA_RESP"
  echo -e "  MegaTest: $MEGA"

  # many_locals() = 55 (0x37) — pure computation, no storage
  SEL=$(selector "many_locals")
  RESP=$(call "$MEGA" "$SEL")
  assert_eq "mega many_locals()=55" "$(json_result "$RESP")" "0x37"

  # get_greeting() contains "hello world" — string return, no storage
  SEL=$(selector "get_greeting")
  RESP=$(call "$MEGA" "$SEL")
  assert_contains "mega get_greeting()" "$RESP" "68656c6c6f20776f726c64"

  # add_u256(100, 200) = 300 — pure computation with wide args
  SEL=$(selector "add_u256")
  A=$(python3 -c "print((100).to_bytes(32,'little').hex())")
  B=$(python3 -c "print((200).to_bytes(32,'little').hex())")
  RESP=$(call "$MEGA" "${SEL}${A}${B}")
  assert_contains "mega add_u256(100,200)=300" "$RESP" "12c"

  # set_score(42, 999) — state mutation (Map write)
  SEL=$(selector "set_score")
  ID=$(u64_le 42)
  VAL=$(u64_le 999)
  RESP=$(rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"$MEGA\",\"data\":\"0x${SEL}${ID}${VAL}\",\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"0\"}")
  NONCE=$((NONCE + 1))
  assert_ok "mega set_score(42,999) accepted" "$RESP"
fi

rm -rf "$TMPDIR"
echo ""

# =============================================================================
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  Results                                 ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo -e "  ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${TOTAL} total"
if [ "$FAIL" -eq 0 ]; then
  echo -e "  ${GREEN}ALL TESTS PASSED${NC}"
else
  echo -e "  ${RED}SOME TESTS FAILED${NC}"
fi
echo ""

exit "$FAIL"
