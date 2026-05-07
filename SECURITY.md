# Security Policy

Pyde is a post-quantum L1 blockchain headed for public testnet launch.
Vulnerabilities in consensus, cryptography, state, networking, the PVM,
or the public RPC surface can drain user funds, halt the chain, or
compromise validator keys. We take them seriously.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

### Preferred channels

1. **GitHub Security Advisory** —
   <https://github.com/zarah-s/pyde/security/advisories/new>. Gives
   us a private workspace to triage and patch before public
   disclosure.
2. **Email** — `security@zarah.systems`. PGP-encrypted reports
   welcome; the public key fingerprint will be published alongside
   the testnet launch announcement.

### What to include

- Affected version (commit hash or tag — `git rev-parse HEAD` from
  your build).
- A clear description of the vulnerability and its blast radius
  (fund loss, fork, DoS, key disclosure, sandbox escape).
- Reproduction steps or proof-of-concept code.
- Suggested fix or mitigation, if you have one.

### Response timeline

- **Acknowledgement**: within 72 hours.
- **Initial assessment** (severity + plan): within 7 days.
- **Patch + coordinated disclosure**: target 30 days for critical
  findings, 90 days for medium / low.

We will keep you informed throughout and credit you in the disclosure
unless you prefer to remain anonymous.

## Scope

**In scope:**

- Consensus, mempool, state, networking, cryptography crates.
- The `pyde` validator binary and the public RPC surface
  (`pyde_*` JSON-RPC methods, WebSocket subscriptions).
- The Pyde Virtual Machine + AOT compiler (`crates/pvm`,
  `crates/aot`).
- Otigen smart-contract toolchain (`crates/otic`, `crates/pyde-dev`).
- Docker images and the production deployment artifacts in
  `docker/` + `deploy/`.

**Out of scope** (please do not file as security issues):

- Third-party services (faucet UI, block explorer) — those have
  their own repos and disclosure paths.
- Issues in dependencies that have already been ratified upstream
  and that we accept under documented exceptions in `deny.toml`.
- Theoretical attacks without a viable exploitation path.
- The local devnet / `--dev` mode (intentionally accepts unsigned
  transactions for development; gated to `chain_id == 31337`).

## Coordinated disclosure

After a fix ships, we publish a GHSA entry and credit the reporter.
We ask reporters not to publicize the issue until the patch is
broadly adopted — typically 14 days post-release on testnet, 30
days on mainnet once it launches.

## Bug bounty

A formal bug bounty programme will launch alongside the incentivized
testnet. Critical findings reported between now and the bounty launch
are eligible for retroactive payout — please report via the channels
above and reference your report when the programme opens.
