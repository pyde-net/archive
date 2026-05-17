#!/usr/bin/env bash
#
# Two-laptop distributed-soak connectivity check.
#
# Run on each laptop with the OTHER laptop's LAN IP as the argument.
# Exits 0 if the partner is reachable on every libp2p P2P port the
# chain needs, non-zero otherwise. Diagnoses the most common
# failure modes (AP isolation on phone hotspots, host firewalls,
# validators not yet started).
#
# Usage:
#   ./scripts/check-lan-connectivity.sh <PARTNER_LAN_IP>
#
# Two complementary modes:
#   * Default — probe the partner from this side. Run AFTER you've
#     started validators on the partner (otherwise port checks fail
#     because nothing's listening).
#   * --serve — open a temporary listener on the P2P ports so the
#     partner can probe BEFORE validators run. Useful for a clean
#     dry-run of the network path itself.
#
# Reads cleanly on both macOS (BSD ping / nc) and Linux Arch
# (iputils / netcat) because it uses bash's /dev/tcp builtin for
# port checks instead of nc flag dialects.

set -u

# ANSI colours (no-op when not a terminal).
if [ -t 1 ]; then
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RED=$'\033[31m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    GREEN=''; YELLOW=''; RED=''; BOLD=''; RESET=''
fi

ok()   { echo "${GREEN}  ✓${RESET} $1"; }
fail() { echo "${RED}  ✗${RESET} $1"; }
note() { echo "${YELLOW}  •${RESET} $1"; }

# Ports the two-laptop topology uses on each side.
#   30303, 30304 — libp2p P2P (validator-to-validator gossip)
#   8545, 8547 — RPC on laptop A (nodes 0, 1)
#   8549, 8551 — RPC on laptop B (nodes 2, 3)
# (`pyde testnet` allocates RPC ports in strides of 2 — each node
#  also binds an admin RPC at port+2 internally.)
P2P_PORTS=(30303 30304)

usage() {
    echo "usage: $0 <PARTNER_LAN_IP>   (default: probe the partner)"
    echo "       $0 --serve            (open temporary listeners on P2P ports)"
    exit 2
}

mode_serve() {
    if ! command -v nc >/dev/null 2>&1; then
        echo "${RED}nc (netcat) not installed — install it or skip the --serve mode${RESET}"
        exit 3
    fi
    echo "${BOLD}Opening temporary listeners on ${P2P_PORTS[*]}${RESET}"
    echo "(partner runs the script in default mode pointing at this laptop's IP)"
    echo "Ctrl-C to stop."
    echo
    # Background a listener per port. Each `nc -l` exits on first connect,
    # so we loop them. PID-tracking lets us kill cleanly on SIGINT.
    pids=()
    cleanup() {
        echo
        echo "stopping listeners..."
        for pid in "${pids[@]}"; do
            kill "$pid" 2>/dev/null || true
        done
        exit 0
    }
    trap cleanup INT TERM
    for port in "${P2P_PORTS[@]}"; do
        ( while true; do nc -l -p "$port" </dev/null >/dev/null 2>&1 || break; done ) &
        pids+=($!)
        ok "listening on :$port (pid ${pids[-1]})"
    done
    wait
}

mode_probe() {
    local PARTNER="$1"
    echo "${BOLD}=== Two-laptop distributed-soak connectivity check ===${RESET}"
    echo "Probing partner: $PARTNER"
    echo

    # ── 1. ICMP ping ──
    echo "${BOLD}[1/2] ICMP ping${RESET}"
    if ping -c 3 -W 2 "$PARTNER" >/dev/null 2>&1 \
       || ping -c 3 -t 2 "$PARTNER" >/dev/null 2>&1; then
        ok "$PARTNER responds to ping"
    else
        fail "$PARTNER does not respond to ping"
        note "Possible causes: wrong IP, ICMP blocked by firewall, AP isolation, partner offline"
    fi
    echo

    # ── 2. TCP libp2p ports ──
    echo "${BOLD}[2/2] TCP libp2p ports (validator gossip)${RESET}"
    local any_p2p_fail=0
    for port in "${P2P_PORTS[@]}"; do
        if timeout 3 bash -c "exec 3<>/dev/tcp/$PARTNER/$port" 2>/dev/null; then
            ok "$PARTNER:$port — reachable"
        else
            fail "$PARTNER:$port — NOT reachable"
            any_p2p_fail=1
        fi
    done
    echo

    if [ "$any_p2p_fail" = 1 ]; then
        echo "${RED}${BOLD}FAIL${RESET}: at least one libp2p P2P port is not reachable."
        echo
        echo "The chain CANNOT advance until 30303 AND 30304 are reachable from"
        echo "each laptop to the other. Most common causes:"
        echo
        echo "  ${BOLD}1. iPhone Personal Hotspot AP isolation${RESET}"
        echo "     iPhone hotspot blocks client-to-client traffic by default and"
        echo "     does not expose a toggle to disable it. If both laptops share"
        echo "     an iPhone hotspot, this is the most likely cause. Switch to a"
        echo "     real Wi-Fi router or use Android (which usually has a"
        echo "     'WiFi tether — allow client devices to communicate' option)."
        echo
        echo "  ${BOLD}2. Host firewall${RESET}"
        echo "     macOS:   System Settings → Network → Firewall → allow pyde"
        echo "              inbound, or temporarily disable for the soak."
        echo "     Linux:   sudo iptables -L (or 'sudo firewall-cmd --list-all')"
        echo "              — open 30303/tcp and 30304/tcp."
        echo
        echo "  ${BOLD}3. Validators not running yet${RESET}"
        echo "     If you haven't launched validators on the partner laptop"
        echo "     yet, nothing is listening. Either start them first or run"
        echo "     this script in --serve mode on the partner."
        echo
        echo "  ${BOLD}4. Wrong partner IP${RESET}"
        echo "     Run 'ifconfig | grep inet' on the partner laptop to confirm"
        echo "     its LAN IP. The IP changes when laptops swap networks."
        exit 1
    fi

    echo "${GREEN}${BOLD}PASS${RESET}: partner is reachable on all P2P ports."
    note "If loadgen will drive both laptops over RPC, also confirm 8545/8547 (laptop A) and 8549/8551 (laptop B) are reachable."
    note "Next step: launch validators (see docs/two-laptop-soak.md)."
}

case "${1:-}" in
    "")
        usage
        ;;
    --serve)
        mode_serve
        ;;
    --help|-h)
        usage
        ;;
    *)
        mode_probe "$1"
        ;;
esac
