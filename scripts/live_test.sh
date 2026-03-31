#!/usr/bin/env bash
# =============================================================================
# Pyde Live Test — deploy and call contracts via JSON-RPC (like Anvil/Hardhat)
# Requires: running validator node at localhost:8545
#   cargo run -p pyde-node -- run --role validator --rpc-port 8545
# =============================================================================
set -euo pipefail

RPC="http://localhost:8545"
FROM="0x0101010101010101010101010101010101010101010101010101010101010101"
PASS=0
FAIL=0
NONCE=0

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ---- helpers ----

rpc() {
  local method="$1" params="$2"
  curl -s -X POST "$RPC" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[$params],\"id\":1}"
}

call() {
  local to="$1" data="$2"
  rpc "pyde_call" "{\"from\":\"$FROM\",\"to\":\"$to\",\"data\":\"0x$data\",\"gas\":100000000}"
}

_RESP_FILE=""
send_tx() {
  local to="$1" data="$2"
  _RESP_FILE=$(mktemp)
  rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"$to\",\"data\":\"0x$data\",\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"0\"}" > "$_RESP_FILE"
  NONCE=$((NONCE + 1))
}

deploy() {
  local bytecode="$1" clen="$2"
  _RESP_FILE=$(mktemp)
  rpc "pyde_sendTransaction" "{\"from\":\"$FROM\",\"to\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"data\":\"0x$bytecode\",\"constructorLen\":$clen,\"gas\":100000000,\"nonce\":$NONCE,\"value\":\"0\"}" > "$_RESP_FILE"
  NONCE=$((NONCE + 1))
}

last_resp() {
  cat "$_RESP_FILE"
}

assert_contains() {
  local label="$1" response="$2" expected="$3"
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

assert_result() {
  local label="$1" response="$2" expected="$3"
  local result
  result=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',''))" 2>/dev/null || echo "")
  if [ "$result" = "$expected" ]; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC}  $label  =  $result"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC}  $label"
    echo -e "       expected: $expected"
    echo -e "       got:      $result"
  fi
}

assert_success() {
  local label="$1" response="$2"
  if echo "$response" | grep -q '"result"'; then
    PASS=$((PASS + 1))
    echo -e "  ${GREEN}PASS${NC}  $label"
  else
    FAIL=$((FAIL + 1))
    echo -e "  ${RED}FAIL${NC}  $label"
    echo -e "       got: $response"
  fi
}

# ---- FNV-1a selector (matches codegen) ----
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

# ---- encode helpers ----
u64_le() {
  python3 -c "
import struct
print(struct.pack('<Q', $1).hex())
"
}

u256_le() {
  python3 -c "
v = $1
b = v.to_bytes(32, 'little')
print(b.hex())
"
}

# hex decode helper
hex_decode() {
  python3 -c "print(bytes.fromhex('$1').decode('utf-8', errors='replace'))"
}

# =============================================================================
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  Pyde Live Test Suite${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# ---- Step 0: Check node is alive ----
echo -e "${YELLOW}[1/6] Checking node...${NC}"
RESP=$(rpc "pyde_blockNumber" "")
if ! echo "$RESP" | grep -q "result"; then
  echo -e "${RED}ERROR: Node not reachable at $RPC${NC}"
  echo "Start with: cargo run -p pyde-node -- run --role validator --rpc-port 8545"
  exit 1
fi
echo -e "  Node alive: $RESP"
echo ""

# ---- Step 1: Write the test contract ----
echo -e "${YELLOW}[2/6] Compiling contract...${NC}"

TMPDIR=$(mktemp -d)
cat > "$TMPDIR/mega.oti" << 'OTI'
enum Status { Active, Inactive, Banned }

struct Stats { hp: u64, xp: u64 }
struct Profile { name: String, age: u8, balance: u256, stats: Stats, tags: Vec<String> }

contract MegaTest {
    storage {
        owner: Address,
        total_supply: u256,
        count: u64,
        players: Map<u64, Profile>,
        scores: Map<u64, u64>,
        status_map: Map<u64, Status>,
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
    pub fn mul_u256(a: u256, b: u256) -> u256 { return a * b; }

    pub fn set_player(id: u64) {
        let mut tags = Vec::new();
        tags.push("hero");
        tags.push("warrior");
        let s = Stats { hp: 100, xp: 9999 };
        let p = Profile { name: "Alice", age: 25, balance: 50000 as u256, stats: s, tags: tags };
        self.players[id] = p;
        self.count = self.count + 1;
    }

    pub fn get_hp(id: u64) -> u64 { let p = self.players[id]; return p.stats.hp; }
    pub fn get_xp(id: u64) -> u64 { let p = self.players[id]; return p.stats.xp; }
    pub fn get_player_name(id: u64) -> String { let p = self.players[id]; return p.name; }
    pub fn get_player_balance(id: u64) -> u256 { let p = self.players[id]; return p.balance; }

    pub fn make_scores() -> Vec<u64> {
        let mut v = Vec::new();
        v.push(10); v.push(20); v.push(30);
        return v;
    }

    pub fn sum_vec() -> u64 {
        let mut v = Vec::new();
        v.push(100); v.push(200); v.push(300);
        let mut total = 0;
        let mut i = 0;
        let len = v.len();
        while i < len { total = total + v[i]; i = i + 1; }
        return total;
    }

    pub fn get_greeting() -> String { return "hello world"; }

    pub fn string_arg(s: String) -> u64 { return s.len(); }

    pub fn set_status(id: u64) { self.status_map[id] = Status::Active; }
    pub fn get_status(id: u64) -> Status { return self.status_map[id]; }

    pub fn set_score(id: u64, val: u64) { self.scores[id] = val; }
    pub fn get_score(id: u64) -> u64 { return self.scores[id]; }

    pub fn many_locals() -> u64 {
        let a=1; let b=2; let c=3; let d=4; let e=5;
        let f=6; let g=7; let h=8; let i=9; let j=10;
        let k=11; let l=12; let m=13; let n=14; let o=15;
        return a+b+c+d+e+f+g+h+i+j+k+l+m+n+o;
    }

    pub fn echo_stats(s: Stats) -> Stats { return s; }

    pub fn make_profile() -> Profile {
        let mut tags = Vec::new();
        tags.push("admin"); tags.push("mod");
        let s = Stats { hp: 200, xp: 5000 };
        let p = Profile { name: "Bob", age: 30, balance: 99999 as u256, stats: s, tags: tags };
        return p;
    }

    pub fn make_names() -> Vec<String> {
        let mut v = Vec::new();
        v.push("alice"); v.push("bob"); v.push("charlie");
        return v;
    }
}
OTI

# Compile with otic
cargo run -p otic --quiet -- build "$TMPDIR/mega.oti" 2>&1 | sed 's/^/  /'

# Parse the artifact JSON
ARTIFACT="$TMPDIR/mega.json"
if [ ! -f "$ARTIFACT" ]; then
  echo -e "${RED}ERROR: Artifact not found at $ARTIFACT${NC}"
  exit 1
fi

CONSTRUCTOR_HEX=$(python3 -c "import json; d=json.load(open('$ARTIFACT')); print(d['constructorBytecode'].replace('0x',''))")
RUNTIME_HEX=$(python3 -c "import json; d=json.load(open('$ARTIFACT')); print(d['deployedBytecode'].replace('0x',''))")
CLEN=$((${#CONSTRUCTOR_HEX} / 2))

echo -e "  Constructor: ${CLEN} bytes"
echo -e "  Runtime:     $((${#RUNTIME_HEX} / 2)) bytes"
echo ""

# ---- Step 2: Deploy ----
echo -e "${YELLOW}[3/6] Deploying contract...${NC}"
FULL_BYTECODE="${CONSTRUCTOR_HEX}${RUNTIME_HEX}"
deploy "$FULL_BYTECODE" "$CLEN"
echo -e "  Response: $(last_resp)"

# Extract contract address
CONTRACT=$(python3 -c "
import json
with open('$_RESP_FILE') as f:
    resp = json.load(f)
r = resp.get('result', '')
if isinstance(r, str):
    d = json.loads(r)
    print(d['contractAddress'])
elif isinstance(r, dict):
    print(r['contractAddress'])
else:
    print('PARSE_FAILED')
" 2>/dev/null || echo "PARSE_FAILED")

echo -e "  ${CYAN}Contract: $CONTRACT${NC}"
echo ""

# Wait for deploy block to be produced and committed
echo -e "${YELLOW}[4/6] Waiting for deploy block...${NC}"
sleep 5
echo -e "  Block produced."
echo ""

# ---- Step 3: Read-only calls (pyde_call) ----
echo -e "${YELLOW}[5/6] Running read-only calls...${NC}"
echo ""

# -- get_count() -> 0 --
SEL=$(selector "get_count")
RESP=$(call "$CONTRACT" "$SEL")
assert_result "get_count()" "$RESP" "0x0"

# -- get_supply() -> u256 1000000 (wide return, LE hex) --
SEL=$(selector "get_supply")
RESP=$(call "$CONTRACT" "$SEL")
# 1000000 LE = 40420f0000...
assert_contains "get_supply() = 1000000" "$RESP" "40420f"

# -- get_owner() -> our address (wide return, LE hex) --
SEL=$(selector "get_owner")
RESP=$(call "$CONTRACT" "$SEL")
assert_contains "get_owner()" "$RESP" "0101010101"

# -- add_u256(100, 200) = 300 --
SEL=$(selector "add_u256")
A=$(u256_le 100)
B=$(u256_le 200)
RESP=$(call "$CONTRACT" "${SEL}${A}${B}")
# 300 LE = 2c01000...
assert_contains "add_u256(100,200) = 300" "$RESP" "2c01"

# -- mul_u256(50, 60) = 3000 --
SEL=$(selector "mul_u256")
A=$(u256_le 50)
B=$(u256_le 60)
RESP=$(call "$CONTRACT" "${SEL}${A}${B}")
# 3000 LE = b80b000...
assert_contains "mul_u256(50,60) = 3000" "$RESP" "b80b"

# -- sum_vec() -> 600 (0x258) --
SEL=$(selector "sum_vec")
RESP=$(call "$CONTRACT" "$SEL")
assert_result "sum_vec() = 600" "$RESP" "0x258"

# -- many_locals() -> 120 (0x78) --
SEL=$(selector "many_locals")
RESP=$(call "$CONTRACT" "$SEL")
assert_result "many_locals() = 120" "$RESP" "0x78"

# -- get_greeting() -> blob "hello world" --
SEL=$(selector "get_greeting")
RESP=$(call "$CONTRACT" "$SEL")
# "hello world" hex = 68656c6c6f20776f726c64
assert_contains "get_greeting() = 'hello world'" "$RESP" "68656c6c6f20776f726c64"

# -- make_scores() -> blob Vec<u64> [10,20,30] --
SEL=$(selector "make_scores")
RESP=$(call "$CONTRACT" "$SEL")
assert_success "make_scores() returns blob" "$RESP"

# -- make_names() -> blob Vec<String> --
SEL=$(selector "make_names")
RESP=$(call "$CONTRACT" "$SEL")
assert_success "make_names() returns blob" "$RESP"

# -- make_profile() -> blob Profile --
SEL=$(selector "make_profile")
RESP=$(call "$CONTRACT" "$SEL")
assert_success "make_profile() returns blob" "$RESP"

# -- string_arg("test") -> 4 --
SEL=$(selector "string_arg")
# String calldata: [byte_len:8 LE]["test" bytes][pad to 8]
STR_DATA=$(python3 -c "
import struct
s = b'test'
blob = struct.pack('<Q', len(s)) + s
# pad to 8-byte alignment
while len(blob) % 8 != 0: blob += b'\x00'
print(blob.hex())
")
RESP=$(call "$CONTRACT" "${SEL}${STR_DATA}")
assert_result "string_arg('test') = 4" "$RESP" "0x4"

# -- echo_stats({hp:42, xp:77}) -> blob --
SEL=$(selector "echo_stats")
# Struct calldata: [byte_len:8 LE][hp:8 LE][xp:8 LE]
STATS_DATA=$(python3 -c "
import struct
hp = struct.pack('<Q', 42)
xp = struct.pack('<Q', 77)
blob = hp + xp
header = struct.pack('<Q', len(blob))
print((header + blob).hex())
")
RESP=$(call "$CONTRACT" "${SEL}${STATS_DATA}")
assert_success "echo_stats({hp:42,xp:77}) returns blob" "$RESP"

echo ""

# ---- Step 4: State-mutating txs ----
echo -e "${YELLOW}[6/6] Running state-mutating transactions...${NC}"
echo ""

# -- set_player(1) --
SEL=$(selector "set_player")
ID=$(u64_le 1)
send_tx "$CONTRACT" "${SEL}${ID}"
assert_success "set_player(1) tx accepted" "$(last_resp)"
sleep 1  # wait for block inclusion before next nonce

# -- set_score(1, 150) --
SEL=$(selector "set_score")
ID=$(u64_le 1)
VAL=$(u64_le 150)
send_tx "$CONTRACT" "${SEL}${ID}${VAL}"
assert_success "set_score(1, 150) tx accepted" "$(last_resp)"
sleep 1

# -- set_status(1) --
SEL=$(selector "set_status")
ID=$(u64_le 1)
send_tx "$CONTRACT" "${SEL}${ID}"
assert_success "set_status(1) tx accepted" "$(last_resp)"

echo ""
echo -e "  ${CYAN}Waiting for block to finalize state...${NC}"
sleep 2

# ---- Read back mutated state ----
echo ""
echo -e "  ${CYAN}--- Post-mutation reads ---${NC}"
echo ""

# -- get_count() -> 1 --
SEL=$(selector "get_count")
RESP=$(call "$CONTRACT" "$SEL")
assert_result "get_count() = 1" "$RESP" "0x1"

# -- get_hp(1) -> 100 (0x64) --
SEL=$(selector "get_hp")
ID=$(u64_le 1)
RESP=$(call "$CONTRACT" "${SEL}${ID}")
assert_result "get_hp(1) = 100" "$RESP" "0x64"

# -- get_xp(1) -> 9999 (0x270f) --
SEL=$(selector "get_xp")
ID=$(u64_le 1)
RESP=$(call "$CONTRACT" "${SEL}${ID}")
assert_result "get_xp(1) = 9999" "$RESP" "0x270f"

# -- get_score(1) -> 150 (0x96) --
SEL=$(selector "get_score")
ID=$(u64_le 1)
RESP=$(call "$CONTRACT" "${SEL}${ID}")
assert_result "get_score(1) = 150" "$RESP" "0x96"

# -- get_status(1) -> Active = 0 --
SEL=$(selector "get_status")
ID=$(u64_le 1)
RESP=$(call "$CONTRACT" "${SEL}${ID}")
assert_result "get_status(1) = Active(0)" "$RESP" "0x0"

# -- get_player_name(1) -> "Alice" --
SEL=$(selector "get_player_name")
ID=$(u64_le 1)
RESP=$(call "$CONTRACT" "${SEL}${ID}")
# "Alice" = 416c696365
assert_contains "get_player_name(1) = 'Alice'" "$RESP" "416c696365"

# -- get_player_balance(1) -> u256 50000 (0xc350) --
SEL=$(selector "get_player_balance")
ID=$(u64_le 1)
RESP=$(call "$CONTRACT" "${SEL}${ID}")
# 50000 = 0xc350 (may return as GP or wide depending on value size)
assert_contains "get_player_balance(1) = 50000" "$RESP" "c350"

# =============================================================================
echo ""
echo -e "${CYAN}========================================${NC}"
TOTAL=$((PASS + FAIL))
echo -e "  Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}, ${TOTAL} total"
if [ "$FAIL" -eq 0 ]; then
  echo -e "  ${GREEN}ALL TESTS PASSED${NC}"
else
  echo -e "  ${RED}SOME TESTS FAILED${NC}"
fi
echo -e "${CYAN}========================================${NC}"

# Cleanup
rm -rf "$TMPDIR"

exit "$FAIL"
