# Pyde

**A Post-Quantum Layer 1 with Native MEV Protection**

Version 0.9 — May 2026
Zarah Systems
Licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

---

## Abstract

Crypto is approaching a transition. The cryptography that secures every major Layer 1 in production today — secp256k1, Ed25519, BLS12-381 — falls to a quantum computer running Shor's algorithm, and the timeline for cryptographically-relevant quantum compresses every year. The MEV market on incumbent chains has hardened into a multi-billion-dollar extraction surface paid by retail users to validator-builder coalitions. The chains chasing throughput have made validation a Wall Street business; the chains chasing decentralization have made throughput unusable. The next default Layer 1 — the chain crypto runs on for the decade after this one — will need to be post-quantum-secure, MEV-free at the protocol layer, sub-second-final, and decentralized on commodity hardware. **No chain in production today is all four.** The major incumbents — Ethereum, Solana, Aptos, Sui, Cardano, Bitcoin — are working on the missing properties through migration roadmaps that are honest multi-year coordinated upgrades across deployed contracts, entrenched wallets, and trillions of dollars of value at risk. NIST's 2024 standardization of FALCON, ML-DSA, and ML-KEM unblocked the cryptographic primitives the field had been waiting for, but the cost of retrofitting them into a live chain is structural, not technological. Pyde is the chain built greenfield to ship every property as the default from genesis. Every signature uses FALCON-512. Every mempool transaction is encrypted under a Kyber-768 threshold key held by a 128-validator committee. Sandwich attacks, frontrunning, and proposer extraction become structurally impossible — not policed, not auctioned, not made more efficient, but eliminated. Validators run on 8 cores and 16 GB of RAM with one vote each regardless of stake; cross-network interactions — calling functions on other chains, querying oracles, requesting off-chain compute — happen through a permissionless parachain layer of decentralized infrastructure providers that follow a Pyde-published spec, stake PYDE, and earn the gas fees from the contracts that call them, with no slot auctions and no separate token to hold. The execution layer is a register-based virtual machine with parallel scheduling driven by declared access lists; the design target is 12,500 sustained TPS at 400 ms slot time, with 4,000 TPS sustained / 7,000 TPS burst measured today on a four-validator laptop devnet against real FALCON signatures at 100 % inclusion. The window for a greenfield chain to occupy the post-quantum, MEV-free, commodity-validated category is open and time-bound. Pyde is the chain built to occupy it.

---

## Executive Summary

### What Pyde is

Pyde is the chain built for what comes after the current generation of L1s. It is a monolithic Layer 1 — consensus and execution share a single binary — built around four properties that the next default Layer 1 will need to have, that no chain in production today has all of, and that this paper defends in technical detail. Each claim below is falsifiable; each is anchored in shipped code in the current branch.

**1. Post-quantum security is the default, not an upgrade.** The major L1s have not been blind to the quantum threat. Ethereum has tracked post-quantum migration in research and roadmap discussions since 2020; Solana, Cardano, and Bitcoin have active working groups exploring migration paths; NIST's 2024 standardization of FALCON, ML-DSA, and ML-KEM has unblocked the cryptographic primitives the field had been waiting for. The structural challenge is retrofitting post-quantum signatures onto chains with deployed contracts, entrenched wallets, and historical signed state — a multi-year coordinated upgrade across every node, every wallet, every signing library, and every contract that hard-codes a key format. Pyde's claim is not that incumbents have ignored the problem. It is that a chain built greenfield does not pay the migration cost. Every signature that secures consensus, every key that authorizes a transaction, every encryption used to hide a transaction's contents from validators uses NIST-standardized lattice-based cryptography from the genesis block. FALCON-512 (NIST FIPS 206) signs consensus votes, transaction authorizations, and validator key registrations. Kyber-768 / ML-KEM (NIST FIPS 203) encrypts mempool transactions. Poseidon2 over the Goldilocks field hashes blocks, transactions, and Merkle nodes. Ed25519 appears only in libp2p's noise transport for peer routing; an attacker who breaks Ed25519 learns which IP addresses validators connect to but cannot forge a block, decrypt a transaction, or steal an account. The chain that ships post-quantum signatures as the default — at production scale, on commodity hardware, with no migration tax — establishes the cryptographic baseline for the era after the one we are currently in. The migration cost the incumbents face is the moat that protects that position.

**2. MEV is removed at the protocol layer.** Transactions enter the mempool encrypted under a threshold public key held jointly by the 128-validator committee. The block proposer publishes a Poseidon2 commitment to the ordering of those encrypted transactions before any of the validators releases a decryption share. After 86 of 128 shares converge, the validators jointly decrypt and execute the block — but the order is already locked, and every decrypted transaction up to the gas limit must appear in the sealed block. A proposer who reorders, drops, or front-runs a transaction is detectable and slashable. Sandwich attacks and frontrunning become ill-defined operations rather than market activities. Every billion dollars extracted via MEV from retail users on incumbent chains is a billion dollars of users learning that the chain they use is not built for them. The chain that removes that tax structurally — not by auctioning it more efficiently — is the chain those users move to as soon as a credible alternative exists.

**3. Sub-second finality with a credible throughput target.** A modified pipelined HotStuff consensus protocol with VRF-based proposer selection produces blocks every 400 ms. Hard finality — an 86-of-128 FALCON quorum certificate on a finality cert — typically lands within one or two slots. Today's measured throughput on a four-validator devnet is 4 K TPS sustained × 10 min and 7 K TPS burst × 30 s, both at 100 % inclusion against full FALCON signature verification. The design target on cloud-class hardware is 12,500 sustained TPS / 50,000 peak; the gas-model ceiling — 400 M target block gas at ~52 K average gas per transaction in a realistic mixed workload — implies ~19 K theoretical TPS, leaving headroom above the design target. Sub-second finality at retail-scale throughput is a category, not a feature. The chain that holds the category becomes the default surface for the consumer applications, payment systems, and high-frequency dApps that today's chains are still bottlenecked behind multi-minute finality or unstable peak throughput from serving.

**4. True decentralization at three layers.** Pyde's mainnet validator hardware spec is 8 cores, 16 GB of RAM, 500 GB of NVMe SSD, and 100 Mbps symmetric network — a developer workstation, not a data-center node. Every committee member has exactly one vote regardless of stake; the 10,000 PYDE bond is anti-sybil, not a power multiplier. Cross-network interactions — calling a function on Solana, querying an oracle, requesting off-chain compute — happen through a permissionless **parachain layer** of decentralized infrastructure providers who implement a Pyde-published specification, stake PYDE as their bond, and earn gas fees from the contracts that call them via the `cross_call!` macro. There are no slot auctions, no parachain-team gatekeeping, no permissioned inclusion; the spec is the contract, the implementations are open source and competitive. Combined gas (Pyde-side + parachain-side) is computed at call time and billed in one transaction, so the parachain layer is invisible to the user. The combined effect is that participation in Pyde — running a node, validating, building or operating a parachain — is a function of will and a small fixed bond, not of access to data-center capital, governance lobbying, or auction proceeds. Decentralization is the asymmetric property: a chain that has become a data-center business cannot become a workstation business without breaking its own validator set. Pyde gets to make this choice once. Incumbents get to fight it forever.

### State of build

Of the 143-task mainnet readiness plan derived from the April 2026 internal audit, 86 are complete, 6 are partial, and 51 are open. What is shipped:

- All 15 production Rust crates compile, test, and run as a single binary.
- Multi-node consensus reaches finality, recovers from leader failure, slashes double-signers, and rotates committees at epoch boundaries (verified across a 4-node devnet).
- The encrypted mempool round-trip — submit, threshold-encrypt, ordering commitment, threshold decrypt, seal — passes end-to-end with state roots converging across all nodes.
- 4 K TPS sustained × 10 min at 100 % inclusion on a four-validator laptop devnet with full FALCON signatures.
- Hardened transaction decoders (audit 301), pinned chain-id RPC and faucet (audits 302, 303), production-rejected dev-mode signature paths (audit 304), Argon2id keystore encryption shared across node, SDK, and developer tools (audit 306).

What runs today is consensus-correct and survives partition-and-heal, double-sign, and 2-of-7 validator-offline tests. What remains for mainnet is the cloud-validated throughput run at the 12.5 K target, a five-track external audit programme, an incentivized testnet, and the 128-validator genesis ceremony.

### What's deferred to post-mainnet

Mainnet ships with committee-only finality. Validators execute every block they vote on, and finality is the FALCON quorum certificate. The post-mainnet roadmap is substantial and deliberately staged: the **parachain layer** for cross-chain routing, oracle networks, indexers, and off-chain compute (~ + 6-to-12 months); **programmable accounts** and **native session keys** for full account abstraction; **STARK execution proofs** as a parallel finality path (~ + 18-30 months); **ZK proofs as a parachain attestation mode** (~ + 24-36 months), unifying Pyde and its parachain layer into a verifiable computation network where every operation can be cryptographically proved when the cost-benefit ratio justifies it; signed mempool censorship commitments with cryptographic slashing; expanded TypeScript SDK coverage. Two-chamber on-chain governance was explicitly evaluated and rejected (§14.2). Section 19 catalogues every post-mainnet item honestly. Investors and auditors who read the original architecture proposals will notice that mainnet ships less than the original ambition contemplated and that the post-mainnet roadmap is on a credible path; we'd rather frame both than be caught by either.

### Tokenomics in one paragraph

PYDE has a 1 billion token genesis supply with a decreasing inflation schedule (5 % year 1 → 3 % → 2 % → 1 %, fixed thereafter). Each validator stakes 10,000 PYDE — one bond per committee seat, 128 seats — and earns from a two-tier reward stream: protocol inflation, plus a 20 % share of every transaction's base fee. Of each base fee, 70 % is burned, 20 % goes to the validator, and 10 % accrues to a multisig-controlled treasury. The fee model is EIP-1559 with elastic 4× blocks and no priority tips — there is no priority signal because the encrypted mempool eliminates the information asymmetry that priority fees price. The combined effect — high blockspace supply at the design target, no priority tips, no MEV tax on the all-in cost, no separate token to hold for oracle or cross-chain calls — is structurally low effective transaction cost at every utilization level (§12.6).

### Governance in one paragraph

Pyde's governance is deliberately off-chain. Protocol changes go through Pyde Improvement Proposals (PIPs) — a public, versioned process modeled on Bitcoin's BIPs and Ethereum's EIPs, ratified by PIP-0001. There is no on-chain stake-weighted voting on protocol upgrades; validators upgrade voluntarily, hard forks happen by social consensus, and the chain that retains 67 %+ of stake is the legitimate continuation. On-chain governance is restricted to treasury spending and emergency operations, both gated by an M-of-N FALCON multisig with a 30-day-bounded emergency-pause primitive.

### UX and DX as protocol surface

Pyde treats user and developer experience as protocol surface, not application work. **Multisig is a native account mode**, not a contract every project re-deploys against subtly different security assumptions. **Programmable accounts** ship as a post-mainnet extension of the same account model — opt-in, sandboxed PVM bytecode policies that express spend limits, time locks, allow-listed recipients, tiered authorization, and recovery flows without a separate account-abstraction stack. **Native session keys** ship alongside, giving dApps the ability to act on a user's behalf within a registered scope (specific contracts, capped spend, slot-bounded duration) without a wallet popup per action — the missing primitive for gaming, AI agents, and consumer apps that has been a hand-rolled retrofit on every major chain to date. **First-class Rust and TypeScript SDKs** ship from day one — the TypeScript SDK is at ethers-equivalent maturity today (provider, FALCON-aware wallet, ABI-aware contract layer, WASM-compiled crypto). The **Otigen smart-contract language** ships with reentrancy blocked by default, checked arithmetic, and protocol-aware primitives. The **`pyde-dev` CLI** mirrors the Foundry / Hardhat developer loop (`build`, `test`, `deploy`, cheatcodes, scripted deployments). The full validator binary is a single executable with one config file. Where other chains require an ecosystem to materialize the developer surface, Pyde ships the surface.

### Use of capital, in shape

The path from this paper to mainnet runs through, in order:

1. Cloud-validated stress testing of the 12.5 K sustained / 50 K peak TPS targets on server-class hardware (the laptop devnet has thermal-bound the test).
2. A five-track external audit programme covering consensus, the PVM, the post-quantum cryptography, networking, and the otic compiler. Each track engages a separate specialist firm; the consolidated programme is the dominant pre-mainnet line item.
3. A 3+ month incentivized testnet with reference dApps (DEX, lending market, NFT marketplace), a fully-funded bug bounty, and remediation of all critical and high findings before launch.
4. A 128-validator genesis ceremony, geo-distributed, with hardware-benchmarked operators who participated in the incentivized testnet.

This whitepaper is the technical credibility document for the testnet-to-mainnet capital deployment. It is not a fundraise prospectus.

---

## 1. Introduction

### 1.1 What L1s left on the table

Seventeen years after Bitcoin's genesis block and eleven years after Ethereum's smart-contract launch, Layer 1 blockchains carry four open architectural debts that the industry has learned to live with but has not solved.

**Quantum risk.** Every major L1 in production today secures consensus signatures with elliptic-curve cryptography — Ed25519 in Solana, Aptos, Sui, and Cardano; secp256k1 in Bitcoin and Ethereum execution; BLS12-381 in Ethereum's beacon chain. All three fall to a sufficiently large quantum computer running Shor's algorithm.

The major L1s have not been blind to this. Ethereum's research community has tracked post-quantum migration since 2020; Vitalik Buterin and others have published on lattice-based signatures and post-quantum-friendly account abstraction, and the broader Ethereum roadmap pre-positions for PQ via state expiry, account abstraction, and Verkle-tree groundwork. Solana has explored PQ alternatives in working groups. Cardano has shipped hash-based signature primitives as building blocks. The Bitcoin community has multiple BIP drafts proposing migration paths. NIST's 2024 standardization of FALCON, ML-DSA (Dilithium), and ML-KEM (Kyber) finalized the cryptographic primitives the entire field had been waiting for. The question is no longer "do we have post-quantum signatures?" — it is "how do we deploy them across chains with deployed contracts, entrenched wallets, signing libraries, and historical signed state already at billions of dollars of value at risk?"

The honest answer for incumbent L1s is migration: a multi-year coordinated upgrade across every node, every wallet, every smart contract that hard-codes a key format, and every historical signature that needs to remain verifiable. Bitcoin's secp256k1-to-anything migration would require coordinating every running node and every UTXO on a chain with hundreds of billions of dollars of market value. Ethereum's path requires consensus-layer changes, wallet support across an enormous EIP surface, and likely a multi-fork transition. These efforts are realistic and underway, and the major L1 teams are competent and well-funded; the constraint is the shape of the problem, not the seriousness of the response. Migration takes years and cannot be rushed without leaving users behind.

Pyde's claim is not that incumbent chains have ignored the problem. It is that a chain built greenfield does not pay the migration cost. Every signature in Pyde is FALCON from the genesis block. Every account address derives from a FALCON public key. Every encryption uses Kyber-768 / ML-KEM. There is no historical secp256k1 or Ed25519 signature to validate, no pre-quantum-derived address to migrate, no deployed contract that hard-codes a pre-quantum key format. The chain is post-quantum because nothing else has ever existed on it, and that property is structural — it cannot be lost without breaking the chain.

The forecast for cryptographically-relevant quantum computers compresses each year. Recent work on lattice reductions has narrowed the timeline. The window in which it is reasonable to launch a new L1 on pre-quantum cryptography is closing; the window in which an existing L1 can finish migration before facing the threat is the harder constraint.

**MEV.** Flashbots quantified MEV on Ethereum at hundreds of millions of dollars extracted per year, and the field's response has been to make the MEV market more efficient — proposer-builder separation, MEV-Boost on Ethereum, Jito on Solana, sealed-bid auction designs in the broader research literature. These are defensible engineering choices given the constraints of existing chains with deployed contracts, entrenched proposer behavior, and validator economics that already depend on MEV revenue; the work going into those designs is serious work, and the field is genuinely better for it. The alternative — removing the underlying information asymmetry at the protocol level rather than auctioning the surplus — requires consensus-protocol changes that are easier to ship at the genesis of a new chain than to retrofit into a live one. Threshold-encrypted mempools have existed in academic literature since 2018 and in research projects since shortly after; the constraint on shipping one as a default has been the cost of changing the proposer's information set on a chain that did not start out that way.

The case for the protocol-level removal — Pyde's choice — is a user case. Every retail swap on a public AMM pays a sandwich tax measurable in basis points; every liquidation on a public lending market is contestable by the proposer; every NFT mint is racing against bots that can read the mempool. The aggregate cost — the surplus extracted from users to fund the sophistication of searchers and to compensate validators for not extracting it themselves — is real money, and it is the user's money. The market-design and protocol-level approaches answer different questions: PBS asks "how should this surplus be distributed?" Pyde asks "is there a protocol that does not produce the surplus in the first place?" Both questions are legitimate. Pyde's bet is that, for a greenfield chain, the second question has a cleaner answer.

**Throughput at finality.** The industry has produced two extremes. Ethereum prioritizes finality at the cost of throughput — roughly 15 sustained TPS at the L1, with finality measured in minutes. Solana prioritizes throughput at the cost of stability — high peak throughput, but seven major outages between 2021 and 2024, several attributed to mempool overload and resource exhaustion. The chains in between — Aptos, Sui, Avalanche — have published throughput claims in lab settings but have not yet demonstrated sustained 12,500 TPS at sub-second hard finality on adversarial mixed workloads in production.

**Validator centralization on premium hardware.** A quieter problem, related to the throughput one, is that the chains optimizing hardest for throughput have ended up making validation a premium-hosting business. Solana's effective real-world validator spec runs to 12 + cores and 256 + GB of RAM, with stated requirements that have grown over time as the chain has scaled — a coherent engineering response to the throughput target Solana set itself. The aggregate effect is that running a Solana validator at production performance is meaningfully a data-center operation, and a smaller number of professional operators run a disproportionate share of stake than the original validator-decentralization vision contemplated. Polkadot's parachain slots are auctioned because shared-security parachains depend on relay-chain validator capacity, which is a finite resource that has to be allocated — a coherent solution to the resource-allocation problem, but one that ends up concentrating slot ownership in well-capitalized parachain teams. Ethereum's L2 ecosystem ships scaling at the cost of fragmenting the user surface across L2s, each with its own sequencer, its own bridge, and its own decentralization timeline. Each of these is a sensible local optimization given the chain's starting position and the constraint set its team was working against; in aggregate, the field has been trading decentralization for throughput at rates the user-facing communication does not always make explicit. A user who picks a chain on the basis of throughput often does not see the implied trust model behind it. None of this is anyone's bad faith — it is what happens when scaling decisions get made one chain at a time and the cumulative cost lands on the user.

These four problems are not independent items on a punch list. They converge in time. NIST's 2024 cryptographic standardization unblocked the post-quantum primitives at the same moment that the MEV literature matured into quantified user-cost numbers; at the same moment that Solana's stability work made the cost of premium-hardware validation visible; at the same moment that the L2 ecosystem's sequencer-trust assumptions started attracting serious public scrutiny. The industry is staring at a four-axis problem, and most of the production answers were architected for a different era — for an era when the quantum threat was theoretical, when MEV was a footnote in academic papers, when Solana's hardware spec was 4 cores and 16 GB, when the only L1 anyone needed was Ethereum. The architecture that wins the next decade does not have to be the one that won the last one. It has to be the one built for what crypto becomes next.

Pyde's premise is that all four are protocol-level problems and all four are best addressed at genesis. Post-quantum cryptography can be migrated into a live chain — Ethereum, Solana, Cardano, and Bitcoin are all on that path — but the migration is a multi-year coordinated upgrade across every running validator, every wallet, every signing library, every contract that hard-codes a key format, and every historical signature that needs to remain verifiable on the new protocol. Encrypted mempools can be added to a chain whose block-builder market depends on visible order, but the political cost of removing validator MEV revenue is part of what any credible proposal has to absorb, and the existing builder-market participants are organized to defend their position. Parallel execution can be retrofitted onto a globally-serial state model — Ethereum's transient-storage and access-list EIPs are concrete steps in that direction — but the access patterns of deployed contracts were written assuming serialization, and a meaningful fraction of value-locked logic has to be re-examined transaction by transaction. All three migrations are doable. None of them are cheap, and none of them are fast. The cost of getting these properties right at launch is meaningfully smaller than the cost of changing them later, and the chain that ships them right at launch occupies the position that the incumbents are migrating toward.

### 1.2 Four first principles

Pyde's design is governed by four axioms. Every other choice in this paper follows from them.

**Axiom 1 — Post-quantum cryptography is the default.** No application-layer signature, encryption, or hash in Pyde uses pre-quantum primitives. FALCON-512 signs every consensus vote, every transaction, every validator key registration. Kyber-768 / ML-KEM encrypts every transaction in the mempool. Poseidon2 over the Goldilocks field hashes every block, transaction, and Merkle node. Ed25519 and X25519 appear only in libp2p's noise transport for peer routing; consensus-critical messages are gated by FALCON signatures verified at the application layer. A quantum attacker who breaks Ed25519 sees the network topology but cannot forge a single block, decrypt a single transaction, or compromise a single validator key.

The trade-off is signature size: a FALCON-512 signature is 600–900 bytes, against 64 bytes for Ed25519, and a Kyber-768 ciphertext is 1,088 bytes against negligible overhead for plaintext. Pyde absorbs this cost in the budget for every layer that matters and avoids it everywhere it does not.

**Axiom 2 — MEV is a protocol bug.** The block proposer must not be able to see, reorder, or selectively include unconfirmed transactions. This is not a market-design problem ("how should we share MEV with users?"); it is a security property ("the proposer's information set is restricted"). Pyde achieves this with three interlocking mechanisms.

First, transactions enter the mempool encrypted under a threshold public key generated by the 128-validator committee. No single validator can decrypt the payload; 86 of 128 must cooperate.

Second, the proposer publishes a Poseidon2 commitment to the ordering of encrypted transactions in the proposed block before any decryption share is released by any validator. The ordering is binding by hash; once the commitment is in the proposed block header, the proposer cannot change it without producing a different block.

Third, after the threshold of 86 decryption shares is reached and the block is decrypted, every successfully decrypted transaction up to the gas limit must appear in the sealed block in the committed order. A validator who detects a missing transaction or a reordered transaction rejects the block; under HotStuff's safety property, false positives cost liveness, not safety. A proposer caught violating mandatory inclusion is slashable.

The net effect: a proposer cannot front-run because they cannot read the mempool; they cannot back-run because the ordering is committed before decryption; they cannot drop because dropped transactions are detectable and slashable; they cannot sandwich because they cannot insert their own transaction into a position they have not committed to in advance.

**Axiom 3 — Throughput requires parallel execution and a monolithic binary.** A monolithic chain — consensus and execution sharing a single process, no separate proving network or auxiliary services — minimizes coordination cost. A parallel scheduler — driven by declared access lists, executing non-conflicting transactions concurrently — minimizes per-transaction wall time. The combination targets 12,500 sustained TPS at 400 ms slot time. The design ceiling is set by the gas model: 400 M target / 1.6 B max block gas, against ~52 K average gas per transaction in a realistic mixed workload of ERC20 transfers (50 %), AMM swaps (25 %), NFT mints (15 %), and plain transfers (10 %). The arithmetic gives ~19 K theoretical TPS at the gas ceiling, leaving 50 % headroom above the design target.

The monolithic-binary choice is contested. Multi-chain ecosystems (Cosmos, Polkadot) and modular stacks (Celestia, EigenLayer) argue that disaggregating execution, consensus, settlement, and data availability lets each layer scale independently. Pyde's counter-argument is that disaggregation is a tax on the application: every cross-layer interaction is an additional protocol surface, an additional trust boundary, an additional latency. Modular wins on heterogeneity; monolithic wins on coherence. For an L1 whose target is high-throughput, low-latency, MEV-free execution at the base layer, coherence is more valuable than heterogeneity. Cross-chain interoperability is added back as a separate, permissionless layer above the coherent base — the parachain layer described under Axiom 4 — rather than as a structural premise that fragments the chain at genesis.

**Axiom 4 — Decentralization is the protocol's burden, not the user's.** A chain is decentralized when the cost to participate as a validator, full node, or extension chain is low enough that participation is open to anyone with an ordinary computer and an internet connection. Pyde holds this property at three layers, by design.

*Validators run on commodity hardware.* Pyde's mainnet validator spec is 8 cores, 16 GB of RAM, 500 GB of NVMe SSD, and 100 Mbps symmetric network — a developer workstation, not a data-center node. The CPU bound during a slot is FALCON signature verification on 86 of 128 incoming committee votes plus Poseidon2 hashing during JMT updates; both are CPU-bound but neither requires a high-end server. A validator can be self-hosted at home or on a low-cost cloud instance with no operational disadvantage versus a professional operator. The contrast with chains that have raised validator hardware specs repeatedly under load is deliberate: when validation becomes a premium-hosting business, decentralization becomes a function of capital, not of will.

*Every validator has exactly one vote.* The 10,000 PYDE validator stake is an anti-sybil cost, not a power multiplier. To gain a second vote, a token holder must register a second validator with separate identity, separate FALCON key material, and separate slashing exposure — economically and operationally identical to recruiting an entirely independent operator. The committee is 128 validators with equal voting weight, and the threshold for hard finality is 86 of 128. There is no chain operation in which a validator with 10,000 PYDE has less voice than a validator with 10 million.

*Parachains are permissionless decentralized infrastructure, not auctioned slots.* Cross-network interactions in Pyde — calling a function on Solana, querying an oracle, requesting off-chain compute, indexing on-chain data — happen through a parachain layer of operators who implement a Pyde-published specification. Any developer can implement the spec in any programming language; any operator who stakes PYDE and runs a conforming implementation can join the operator set for a category. There are no slot auctions, no parachain-team gatekeeping, no permissioned inclusion. The parachain spec is the protocol-level contract; the implementations are public, open source, and competitive. A Pyde contract that uses a parachain via the `cross_call!` macro pays one combined gas fee — covering both Pyde-side execution and parachain-side execution — and parachain operators earn their share of the fee. Cross-chain interaction becomes seamless from the user's perspective and trust-minimized at the protocol level: a permissionless infrastructure layer with on-chain rules, PYDE-staked operators, and on-chain slashing, in place of custodial multisig bridges and oracle-and-relayer trust assumptions. The parachain layer ships post-mainnet on a + 6-to-+ 12-month horizon (Section 19), but the protocol-level surface — the `cross_call!` macro, the `HardFinalityCert` primitive, the unified gas model — is settled at genesis.

The combined effect of the three layers is that the cost of participating in Pyde — running a node, validating, building a parachain — is a function of will and a small fixed bond, not of access to data-center capital, governance lobbying, or auction proceeds. Decentralization in Pyde is built into the architecture rather than added back through tokenomics or social process.

### 1.3 Why this window is open and closing

The strategic window for a greenfield chain to occupy the post-quantum, MEV-free, commodity-validated category rests on three time-bound facts.

**First, NIST's 2024 cryptographic standardization is still recent.** The toolkit is now mature, the primitives are vetted, and the field has the parts it needs to build a post-quantum chain. But no major L1 has shipped a post-quantum-default protocol. That gap will close — Ethereum will eventually ship PQ migration, Solana will eventually rebuild around lattice signatures, the field will converge — but the migration timelines for incumbents are honestly multi-year, and the chain that establishes itself as the post-quantum default before that closure earns the position permanently. Migration cost is symmetric: it protects whoever holds the position as much as it constrains whoever needs to take it. The first chain to ship post-quantum at production scale is the post-quantum chain for the next decade.

**Second, the MEV market on incumbent chains has hardened into a structural extraction.** The user discontent is real and growing — every public AMM swap, every public liquidation, every NFT mint is now visibly contestable by sophisticated searchers — but the incumbents' incentive structure (validators capture MEV revenue, builder markets share it back) makes structural removal politically expensive. A protocol-level fix on Ethereum is not just a code change; it is a renegotiation of who gets what. Pyde does not have that constraint. The chain ships MEV-removed at genesis, so there is no political coalition to overturn, no validator revenue to compensate, no auction market to dismantle. The chain that arrives without the political baggage is the chain that gets to remove the tax cleanly.

**Third, the cost of running validators on premium hardware is now visible and politically expensive.** The Solana validator hardware creep is documented, the data-center concentration is measurable, and the question "who actually validates this chain?" is increasingly being asked by users, regulators, and journalists. The chains that have made validation a professional-operator business cannot become commodity-hardware chains without breaking their own validator set. Pyde gets to make the decentralization choice once. Incumbents get to fight it forever.

These three facts do not stay true forever. Quantum forecasts compress; an incumbent will eventually ship a credible PQ migration; the political cost of MEV will eventually force someone to absorb it; the hardware-cost question will eventually be answered, one way or another. The window is the period between when these problems became visible at the same time and when they get solved one way or another. Inside that window, the chain that ships all four properties first establishes the position the industry's open problems define. The chain that occupies the position becomes the default Layer 1 of the post-quantum, post-MEV-as-market era of crypto.

This paper is the technical case that Pyde is the chain built to occupy it.

### 1.4 What follows

The rest of this paper specifies how the protocol implements each axiom, what is built today, what is honestly deferred, and where Pyde's design diverges from the major L1s.

- **Section 2** — Architecture overview: the single-binary structure, the validator and full-node roles, the commodity-hardware spec, the transaction lifecycle from submit to hard finality.
- **Sections 3–5** — Consensus, cryptography, and MEV protection. The headline mechanisms.
- **Sections 6–9** — The Pyde Virtual Machine, the Otigen smart-contract language, the state model, parallel execution, and networking.
- **Section 10** — Cross-chain interactions and the parachain architecture: hard-finality certificates as bridge inputs, the parachain specification, the unified gas model, the permissionless decentralized-infrastructure model. Architecture established at genesis; spec, reference implementations, and bridges ship post-mainnet on a + 6-to-12-month horizon.
- **Sections 11–13** — The account model, gas and fee model, and tokenomics.
- **Section 14** — Governance and the PIP process.
- **Section 15** — Security: attack surface, defenses, deliberate scope-limits.
- **Section 16** — Performance: measured numbers, methodology, the path to the design target.
- **Section 17** — Comparisons to Ethereum, Solana, Aptos, Sui, Polkadot, Cosmos, and Avalanche.
- **Section 18** — Launch roadmap.
- **Section 19** — Post-mainnet appendix: STARK execution proofs and the verifiable computation network roadmap, parachain specification, programmable accounts, session keys, signed mempool commitments, native bridges, expanded TypeScript SDK coverage.
- **Sections 20–21** — Constants reference and glossary.

The document is written to be skimmable at the section level and rigorous within each section. A reader interested in MEV protection can read Section 5 and the threshold-encryption portions of Section 4 and have a complete picture. A reader interested in the decentralization story can read Sections 2 (commodity hardware), 4 (equal voting in consensus), and 10 (permissionless parachains). A reader doing technical diligence should read it end-to-end.

---

## 2. Architecture Overview

### 2.1 Single binary, two roles

Pyde ships as a single Rust binary, `pyde`, built from a workspace of fifteen library crates plus the binary itself. There is no separate execution-layer service, no proving-network sidecar, no auxiliary indexer required for chain operation. A node operator runs one process, configures it as a validator or a full node via TOML, and points it at a genesis file. Everything that happens on the chain — consensus, transaction execution, mempool management, state commitment, RPC, peer discovery, gossip — happens inside that process.

The motivation is operational simplicity. Distributed systems with N coupled services have N + (N choose 2) failure modes; a chain that ships as one process has one. The motivation is also performance: in-process function calls are cheaper than IPC or network calls, and a JIT-compiled smart contract can call into the state backend with no serialization round-trip. Solana made the same architectural choice; Ethereum's separation of consensus and execution clients is a reflection of its history, not an endorsement of the modular pattern.

The two operational roles, validator and full node, share the same binary and the same execution code path. The differences are local:

| Capability | Validator | Full node |
| --- | --- | --- |
| Receives proposals | Yes | Yes |
| Executes blocks | Yes | Yes |
| Maintains state | Yes | Yes |
| Serves RPC | Optional | Yes |
| Releases threshold-decryption shares | Yes | No |
| Signs and broadcasts FALCON votes | Yes | No |
| Eligible to propose blocks (1/128 slots) | Yes | No |
| Aggregates votes into a quorum certificate | When proposer | No |
| Earns block rewards and fee share | Yes | No |

A full node performs every piece of execution work that a validator does — it has to, in order to maintain the chain — minus the consensus participation. The hardware footprint is therefore comparable; the only validator-specific cost is the per-slot fsync of vote and proposal state to disk (measured at 25.5 µs per write on Apple Silicon NVMe, a 4.2× overhead over async writes), which a full node does not pay.

### 2.2 Hardware spec

The mainnet validator hardware target is:

```
CPU:  8+ cores, modern x86_64 or ARM64
RAM:  16 GB (mempool + JMT in-memory caches + execution state)
Disk: 500 GB NVMe SSD (RocksDB state + receipt store + consensus log)
Net:  100 Mbps symmetric, low jitter (decryption shares + gossipsub)
```

This is a developer workstation, not a data-center node. The CPU bound during a slot is FALCON signature verification (when batching 86+ committee votes) and Poseidon2 hashing during JMT updates; both are CPU-bound but neither requires high-end server hardware. A self-hosted mini-PC, a low-cost cloud instance, or a residential machine on a fiber connection all meet the spec. The contrast with chains that have raised validator requirements upward under load is deliberate: hardware creep is the slow erosion of decentralization, and Pyde absorbs that pressure by building the protocol to fit the budget rather than by raising the budget when the protocol gets heavy.

A full node has the same compute and storage shape minus the per-vote fsync overhead. Lighter participation modes — light clients, RPC-only nodes, archive nodes — are out of scope for mainnet but trivially supported by the same binary with different configuration.

### 2.3 The pyde binary subcommand surface

```
pyde run              # Run as validator or full node
pyde testnet          # Generate a multi-validator testnet directory
pyde default-config   # Print a default node config TOML
pyde default-genesis  # Print a default devnet genesis TOML
pyde faucet           # Run a public faucet HTTP server
```

The subcommand surface is intentionally small. `run` is the production path; the others are bootstrapping tools. Configuration is TOML; genesis is a separate TOML file with validator registration, vesting schedules, airdrop Merkle roots, and protocol constants. A four-validator local devnet bootstraps in under ten seconds:

```
$ pyde testnet --validators 4 --out ./devnet --dev
$ cd devnet && ./run.sh
```

A 16-validator three-region cross-host testnet bootstraps from a published address manifest:

```
$ pyde testnet \
    --validators 16 \
    --out ./testnet \
    --node-addrs ./crates/node/testdata/testnet-16v-3region.toml
```

Both paths use the same code as a mainnet deployment.

### 2.4 Workspace map

The fifteen library crates that compose the binary, in dependency order:

| Crate | Role |
| --- | --- |
| `crypto` | FALCON-512, Kyber-768, Poseidon2, threshold, VRF, PSS — the post-quantum primitives. |
| `slashing` | Slashing constants and evidence types shared across `tx` and `consensus` to break the dependency cycle. |
| `pvm` | The Pyde Virtual Machine: 32-bit ISA, 16 GP + 8 wide registers, 4 MB address space, 62 opcodes. |
| `aot` | Cranelift-based ahead-of-time JIT compiler. PVM bytecode → native at deploy time. |
| `state` | Jellyfish Merkle Tree state, RocksDB backend, witnesses, undo logs. |
| `account` | Accounts, addresses (Poseidon2 of FALCON pubkey), nonce-window bitmap. |
| `tx` | Transaction types, fee market (EIP-1559), gas, parallel execution scheduler, fee distribution. |
| `mempool` | Encrypted mempool, ordering commitment, decryption-share aggregation, block construction. |
| `consensus` | Modified HotStuff, VRF proposer selection, finality certificates, slashing rules. |
| `net` | libp2p transport, gossipsub channels, peer discovery, FALCON peer authentication. |
| `otic` | Otigen smart-contract compiler: lex → parse → typecheck → IR → optimize → codegen → artifact. |
| `node` | The binary entry point: RPC, validator process, genesis, faucet, persistence stores. |
| `pyde-dev` | Developer CLI: build, test, deploy, format, wallet management. |
| `pyde-rust-sdk` | Rust client library for application developers. |
| `pyde-crypto-wasm` | WASM bindings for browser dApps and JS/TS wallets. |

Dependencies flow downward. `consensus` depends on `mempool`, `mempool` on `tx`, `tx` on `account` and `state`, all of them on `crypto`. The slashing constants live in their own leaf crate (`slashing`) so that `tx` and `consensus` can both reference them without forming a cycle. The SDK and dev tools live above the production stack and are not loaded into the validator binary at runtime.

### 2.5 Transaction lifecycle, end to end

A transaction's life from submission to hard finality runs through eight stages:

1. **Construct.** The client (wallet, dApp, dev tool) builds a `Transaction` with sender, recipient, value, calldata, gas limit, nonce, chain ID, and access list. The transaction is FALCON-512-signed by the sender's authorization key.

2. **Encrypt (default for MEV-sensitive paths).** The client wraps the transaction in an `EncryptedTx` envelope: it generates a Kyber-768 ciphertext under the committee's threshold public key, binds the ciphertext to the sender's FALCON public key via a Poseidon2 MAC, and signs the envelope. Plaintext transactions remain valid but are visible to validators in the mempool; encrypted is the default for any transaction touching a public AMM, lending market, or other MEV-sensitive surface.

3. **Submit.** The client sends the (encrypted) transaction to a full node's RPC endpoint via `pyde_sendRawTransaction` or `pyde_sendRawEncryptedTransaction`. The receiving node validates wire format, FALCON signature, chain ID, nonce window, balance ≥ gas + value, gas limit, deadline, access list, and tx size — at the RPC boundary, before the transaction is added to the mempool or gossiped.

4. **Gossip.** A validated transaction is added to the mempool and gossiped on the `pyde/transactions/1` channel (plaintext) or `pyde/encrypted_transactions/1` channel (encrypted). All committee members and full nodes subscribe; the mempool reaches a consistent view within mesh-convergence time (typically under 200 ms on the laptop devnet).

5. **Propose.** When the per-slot VRF selects a proposer, the proposer reads from its local mempool view, applies global / per-sender / TTL caps, sorts by gas-then-FIFO, and assembles a candidate block. For encrypted transactions, the proposer publishes a Poseidon2 commitment to the ordered set of `(encrypted_tx_hash)` in the block header, and broadcasts the proposal to the committee.

6. **Decrypt.** Each committee member, on receiving the proposal, verifies the ordering commitment is well-formed and releases its threshold-decryption share for every encrypted transaction in the proposed block. The shares are gossiped on the consensus channel. Once 86 of 128 shares converge for each ciphertext, the validator decrypts the inner transaction.

7. **Execute and vote.** The validator executes the decrypted block via the parallel scheduler (transactions with disjoint access lists run concurrently; conflicts run serially). The validator computes the post-block state root via the JMT, verifies that the proposer's mandatory-inclusion invariant is satisfied (every successfully decrypted tx up to the gas limit appears in the sealed block in committed order), and signs FALCON-512 votes for the block at the prepare, pre-commit, and commit phases of HotStuff.

8. **Finalize.** Once 86 of 128 commit votes are aggregated by the next proposer into a quorum certificate, the block is hard-finalized. A `HardFinalityCert` carrying the 86 FALCON signatures, the voter bitmap, and the state root is the cross-chain-portable proof of finality. Hard finality typically lands within one or two slot periods of inclusion (~400 – 800 ms).

The only step that introduces latency beyond pure consensus is the threshold-decryption round-trip; this is the cost of MEV protection. On the four-validator devnet, the encrypted-path tax adds ~150 – 300 ms to typical hard-finality latency over the plaintext-path baseline.

---

## 3. Consensus

### 3.1 Modified pipelined HotStuff

Pyde's consensus is a variant of pipelined HotStuff (Yin et al., 2019) chosen for three properties: O(n) message complexity per slot (versus O(n²) for PBFT), responsive optimistic finality (a block can finalize in three message rounds when the network is well-connected), and a clean view-change protocol that does not require an external timing oracle. The Pyde variant adds VRF-based proposer selection, multi-proposer fallback for missed slots, post-quantum FALCON-512 signatures on every vote, and threshold-encrypted mempool integration.

The committee is fixed at 128 validators per epoch. The Byzantine fault tolerance threshold is f ≤ 42; the quorum threshold for safety is 2f + 1 = 86. A block is hard-finalized when 86 of 128 committee members have signed a FALCON commit vote, aggregated into a quorum certificate.

Slot duration is 400 ms. Within a slot, the protocol runs:

```
T = 0       Proposer broadcasts proposed block (with ordering commitment)
T = 0+ε    Validators verify proposal, release decryption shares
T = ε      Validators aggregate shares, decrypt, execute, sign prepare vote
T = 2ε     Next proposer aggregates prepare QC, broadcasts pre-commit
T = 3ε     Committee signs pre-commit votes, aggregated into commit QC
T = 400ms  Slot boundary, next slot begins
```

Hard finality typically lands within one or two slot periods (400 – 800 ms) of block inclusion. Soft finality — the block is included in a chain backed by at least one quorum certificate — lands within the slot itself.

### 3.2 VRF proposer selection

Each slot, every committee member independently computes a VRF score over the input `(epoch_randomness || slot)`. The lowest score wins; that validator is the proposer. The score is unforgeable (only a validator with the secret key can compute it) and verifiable (any party can verify the proof against the public key). No one can predict another validator's score in advance, which means a targeted DoS attack against the next proposer is infeasible — the proposer's identity is unknown until the proof is revealed in the proposed block.

This single-shot selection is augmented with a fallback rule: if the primary proposer fails to broadcast within `PROPOSAL_TIMEOUT_MS = 200`, the validator with the second-lowest VRF score takes over as the fallback proposer for that slot. This means a single validator outage does not trigger a full HotStuff view-change in the typical case — the remaining quorum still covers every slot.

`epoch_randomness` is computed at the epoch boundary by aggregating FALCON signatures from at least `RANDOMNESS_THRESHOLD = 85` of 128 committee members on the input string `"pyde-epoch-randomness-v1" || epoch_number`. The aggregated signature is hashed via Poseidon2 to produce a 256-bit randomness output. Because no individual validator's signature is unique enough to predict the aggregated output without ≥ 85 cooperating, no validator can manipulate the next epoch's proposer schedule.

### 3.3 Hard finality

A finalized block carries a `HardFinalityCert`:

```rust
struct HardFinalityCert {
    slot:         u64,
    block_hash:   Hash,
    state_root:   Hash,
    voter_bitmap: u128,                     // 128-bit bitmap, 86+ bits set
    signatures:   Vec<FalconSignature>,     // 86+ FALCON-512 sigs
}
```

The certificate is the cross-chain-portable proof that "block N was hard-finalized on Pyde at state root R." Verifying it requires the active committee's FALCON public keys (refreshed at epoch boundaries), 86 FALCON verifications (each ~1 ms on commodity hardware), and a single Merkle path verification from the state root to the data of interest. The total verification cost is ~86 ms per accepted finality cert — non-trivial but feasible on any chain with a reasonable VM. This is the surface that makes future light-client bridges to Pyde possible (Section 10).

Hard finality is irreversible under the BFT assumption (f ≤ 42). A reorg of a hard-finalized block requires either > 42 validators to double-sign (slashable, see §3.4) or a long-range attack on a stale validator set (defended by weak-subjectivity, see §3.5).

### 3.4 Slashing

Pyde's slashing rules cover four offense classes with calibrated penalties:

| Offense | Penalty | Detection |
| --- | --- | --- |
| Double-sign (two votes at same height for different blocks) | 100 % of stake (10 000 PYDE) + ejection | Cryptographic evidence (two FALCON-signed votes); any party can submit |
| Invalid proposal (proposer broadcasts block violating consensus rules) | 50 % of stake | Validator-detected; evidence is the proposed block plus violated rule |
| Liveness-major (validator absent for > 50 % of an epoch) | 5 % of stake | Per-epoch participation accounting |
| Liveness-minor (validator absent for > 10 % of an epoch) | 1 % of stake | Per-epoch participation accounting |
| Decryption withhold (validator does not release threshold share within 2 slots) | 2 % of stake per offense | Threshold-share gossip tracking |

A 10 % finder's fee on slashed stake goes to the party that submitted the evidence transaction. Evidence is gossiped on the consensus channel (`pyde/consensus/1`); any validator can act on equivocations they did not witness directly.

Slashing is a first-class on-chain operation. `TransactionType::Slash` (type 8) carries the evidence; the handler verifies the evidence cryptographically, debits the offender's stake, credits the finder's fee, marks the validator `Exited`, and removes them from the active set. A validator who has been slashed can no longer claim rewards or unstake; the slashed stake is split between the finder, the burn pool, and the treasury per the standard fee distribution.

### 3.5 Long-range attacks and weak subjectivity

The classic long-range attack on a proof-of-stake chain is for a coalition of historically-staked-but-now-exited validators to use their old keys to sign an alternate chain that diverges from the canonical chain at a point in deep history. Without a defense, a new node syncing from genesis cannot distinguish the two chains.

Pyde defends with weak-subjectivity checkpoints. At regular intervals (every 64 epochs ≈ 7 hours), a checkpoint is published containing the slot, block hash, state root, and the committee's FALCON public keys at that point. A new node syncing from cold starts at the most recent published checkpoint, not at genesis, and follows the chain forward. Old validator keys cannot sign alternate history because the new node will not accept any chain that diverges from the trusted checkpoint.

Checkpoints are published on the consensus channel and gossiped to every node. They are also signed by the active committee at the time of publication (86 + FALCON signatures), so a node syncing from cold can verify authenticity by validating the signatures against the previous checkpoint's committee. The chain of trust runs forward from a single trusted checkpoint that the operator chooses.

### 3.6 Committee rotation and PSS

The committee rotates at every epoch boundary (every 1,000 slots ≈ 6.6 minutes). Validators register for committee participation by submitting a `StakeDeposit` transaction (type 4) carrying their FALCON public key and 10,000 PYDE bond; they enter the active set at the next epoch boundary. Validators leave by submitting a `StakeWithdraw` transaction (type 5); their stake is locked for the unbonding period (3,024,000 slots ≈ 14 days) and released after that.

The threshold key for mempool encryption rotates with the committee. The protocol uses Proactive Secret Sharing (PSS): at each epoch boundary, the current committee runs a resharing protocol that produces a new sharing of the same secret distributed across the new committee's members. A validator who joins at epoch e + 1 receives a new share of the same secret that was held by the epoch-e committee. The threshold pubkey is unchanged across rotations; in-flight encrypted transactions submitted during epoch e remain decryptable at epoch e + 1.

PSS resharing uses a deterministic aggregation trigger (`RESHARE_AGGREGATION_DELAY_SLOTS = 5`) so that all new committee members aggregate the same set of contributions, preventing the async-arrival convergence failure that an early implementation had (caught and fixed during internal audit). A future post-mainnet upgrade adds Pedersen / KZG commitments to verify that each contribution's constant term matches its claimed share value, defending against committee-member compromise (currently mitigated by detection — a corrupt resharing causes ciphertexts to stop decrypting at the new epoch, which is observable within one slot).

---

## 4. Cryptography

### 4.1 The post-quantum stack

Pyde's cryptography is the lattice-based stack standardized by NIST in 2024:

| Primitive | Algorithm | Standard | Use |
| --- | --- | --- | --- |
| Signatures | FALCON-512 | NIST FIPS 206 | Consensus votes, transaction authorization, validator registration |
| Public-key encryption | Kyber-768 / ML-KEM | NIST FIPS 203 | Threshold-encrypted mempool |
| Hash | Poseidon2 (Goldilocks field) | Academic standard | Block hashes, transaction hashes, Merkle nodes, address derivation |
| VRF | FALCON-512-bound, Poseidon2-derived (Goldilocks) | Pyde construction | Proposer selection, epoch randomness |
| Threshold encryption | Shamir over Goldilocks + Kyber + Poseidon2 MAC | Pyde construction | Mempool encryption, decryption-share aggregation |
| Proactive secret sharing | PSS over the threshold encryption | Pyde construction | Committee rotation, key refresh at epoch boundaries |
| Key derivation | Argon2id | RFC 9106 | Keystore encryption (wallet, validator key) |

Ed25519 / X25519 appear in libp2p's noise transport for peer-to-peer routing. They are not part of the consensus or application security model: a quantum attacker who breaks Ed25519 learns which IP addresses validators connect to, but cannot forge a block, decrypt a transaction, or steal an account.

### 4.2 FALCON-512: signatures

FALCON-512 is a lattice-based signature scheme based on the NTRU lattice problem. It produces signatures of variable length (typically 600 – 900 bytes, hard upper bound 1280 bytes), against 64 bytes for Ed25519 — a roughly 10 – 15× signature-size overhead. Public keys are 897 bytes. Verification cost is ~1 ms on commodity hardware, ~3 – 5× slower than Ed25519 verification but well within a per-vote latency budget at 400 ms slot time.

Pyde signs with FALCON-512 at three layers:

- **Consensus votes.** Every prepare, pre-commit, and commit vote in HotStuff is a FALCON-512 signature over the vote's payload (slot, block hash, phase). Aggregation is the union of signatures into a `voter_bitmap` plus a vector of signatures; there is no signature-aggregation scheme like BLS, because no post-quantum BLS analog has matured yet. This is a deliberate cost: the QC bandwidth is higher than a BLS-aggregated chain by roughly the signature-count factor, and the mainnet bandwidth budget (100 Mbps validator network) is sized to absorb it.

- **Transaction authorization.** Every transaction submitted to Pyde is FALCON-512-signed by the sender's authorization key. The signature is verified at RPC ingress and again at execution time. Multisig accounts carry M-of-N FALCON signatures (max signers = 16) verified in the same pipeline.

- **Validator key registration.** A validator's identity is its FALCON public key. The address derived from that key (via Poseidon2) is the validator's account address; the private key controls staking, slashing, and reward claims.

### 4.3 Kyber-768: encryption

Kyber-768 (ML-KEM in NIST FIPS 203 nomenclature) is a lattice-based key encapsulation mechanism providing IND-CCA2 security. The underlying hard problem is Module-LWE (Module Learning With Errors). Public keys are 1 184 bytes; ciphertexts are 1 088 bytes; the encapsulated shared secret is 32 bytes.

Pyde's only protocol use of Kyber-768 is the threshold-encrypted mempool envelope (§4.5). The committee jointly holds the Kyber-768 secret key, distributed via Shamir secret sharing over the Goldilocks field; the corresponding public key is published as the threshold pubkey at every epoch boundary. There is no per-message ephemeral-key path and no AES-GCM path — every encrypted-mempool envelope encapsulates against the committee's threshold pubkey, and the per-message symmetric primitive is a Poseidon2-derived keystream with a Poseidon2 MAC, both bound to the per-message Kyber ciphertext.

The `ml-kem` dependency is currently pinned at `0.3.0-rc.0` pending an upstream stable release; the pin is tracked as a dependency-watch task. The release-candidate is already a faithful FIPS 203 implementation; the upgrade is a version-string change, not a protocol change.

### 4.4 Poseidon2: hashing

Poseidon2 is an algebraic hash function over the Goldilocks field (p = 2⁶⁴ - 2³² + 1), parameterized for Pyde with state width 8 and 22 internal rounds. It replaces SHA-2 / Keccak in every protocol-internal hash:

- Block hashes (hash of the block header)
- Transaction hashes (Poseidon2 of the wire-format bytes)
- Account address derivation (`address = Poseidon2(falcon_public_key)`)
- Merkle node hashes in the Jellyfish Merkle Tree
- VRF input hashing
- Threshold ciphertext binding (`Poseidon2(sender || nonce || gas || chain || ciphertext_hash)`)

The motivation for Poseidon2 over SHA-2 is performance in finite-field operations, which matters for any future ZK extension (post-mainnet) and which is also faster than Keccak on register-based VMs that already operate in 64-bit field arithmetic. The cost is that Poseidon2 is a younger primitive with less cryptanalytic exposure than SHA-2; the counter-argument is that algebraic hashes have been studied actively since 2018 (Poseidon, Reinforced Concrete, Anemoi, Griffin, Poseidon2) and the cryptanalysis literature has not produced practical attacks at Pyde's parameter set. The Argon2id KDF for keystore encryption (§4.7) is a deliberate departure from Poseidon2, applied where memory-hardness is the relevant property.

### 4.5 Threshold encryption

The mempool-encryption protocol is **reconstruct-then-decapsulate Kyber-768**: the committee jointly holds the Kyber-768 secret key in shared form, partial-decryption shares are combined to reconstruct that secret key, and Kyber's standard decapsulation then runs once against the per-message ciphertext. The 64-byte Kyber secret-key seed is split into eight 8-byte chunks, each interpreted as a Goldilocks field element and independently Shamir-split into 128 shares with reconstruction threshold 86 (the same 86-of-128 threshold as consensus quorum). Each validator therefore holds eight Goldilocks shares — one per seed element. The corresponding Kyber public key is the threshold pubkey published at every epoch boundary; clients use it as the encryption target for any transaction submitted to the encrypted mempool path.

The encryption side is standard Kyber: a client calls `Kyber768.encapsulate(threshold_pubkey)` and gets a per-message Kyber ciphertext plus a 32-byte shared secret. The transaction payload is XOR-encrypted under a Poseidon2-derived keystream keyed on `(shared_secret, kyber_ct)`, and the envelope carries a Poseidon2 MAC over `(shared_secret, kyber_ct, encrypted_payload)`. Keystream and MAC are domain-separated and bound to the per-message Kyber ciphertext so that a hypothetical Kyber-RNG repeat does not collapse two plaintexts onto the same keystream.

The decryption side requires cooperative participation from 86 + committee members, each releasing a partial-decryption share — their eight Goldilocks shares, blinded by a deterministic `(ct_hash, validator_index)` mask — together with a FALCON-512 signature over the share's canonical preimage. After validators verify the proposer's ordering commitment (§5.2), the next proposer collects shares, verifies each FALCON signature, removes the blinding masks, and Lagrange-interpolates each of the eight elements at `x = 0` over Goldilocks. The eight reconstructed field elements assemble the original 64-byte Kyber secret-key seed; running `Kyber768.decapsulate(seed, kyber_ct)` recovers the per-message shared secret, the Poseidon2 MAC is verified, the keystream is derived, and the inner transaction is revealed. The threshold reconstruction operates on the long-lived Kyber secret-key seed, not on per-message ciphertext shares; Kyber's standard decapsulation runs once on the recovered key against each message.

Two security properties matter:

- **MAC integrity.** The threshold ciphertext carries a Poseidon2 MAC binding the ciphertext to the sender's FALCON public key, preventing relay-inflation spam where a malicious relay re-injects copied ciphertexts under a different sender. The MAC is verified in constant time using `subtle::ConstantTimeEq` to prevent timing-based MAC-forgery attacks; an early-exit comparison in a previous version was caught and fixed during internal audit before testnet.

- **Decryption-withhold detection.** A validator who fails to release decryption shares within 2 slots of a proposal is flagged for the decryption-withhold slashing condition (§3.4, 2 % of stake per offense). This is what makes the cooperative-decryption protocol economically sound: a validator who deliberately slows decryption pays a cost.

### 4.6 VRF and PSS

Pyde's VRF is a FALCON-signature-bound construction over Poseidon2. The 256-bit pseudorandom output is `Poseidon2(output_domain || Poseidon2(fingerprint_domain || sk) || input)` — a deterministic Poseidon2 hash of the input under a secret-key-derived fingerprint. The proof is a FALCON-512 signature over `(proof_domain || pk || input || output)`, which makes the output verifiable by anyone holding the public key and inherits FALCON's NIST FIPS 206 post-quantum security. Poseidon2 over the Goldilocks field is the hash primitive throughout; the Goldilocks choice is for in-circuit compatibility with Pyde's other Poseidon2 use sites, not for the VRF's security argument.

The VRF is used at two layers:

- **Proposer selection.** Every committee member computes a VRF score for each slot; the lowest score is the proposer (§3.2).
- **Epoch randomness.** The aggregated VRF outputs of 85 + committee members at the epoch boundary, hashed via Poseidon2, produce the next epoch's randomness seed.

PSS (Proactive Secret Sharing) is the protocol that rotates the threshold key across committee changes. Each committee member at epoch e produces a "resharing contribution" — a polynomial over Goldilocks whose constant term is their share — and broadcasts the sub-shares to the new committee at epoch e + 1. The new committee aggregates contributions deterministically (after `RESHARE_AGGREGATION_DELAY_SLOTS = 5` slots) and derives new shares of the same threshold secret. The threshold public key is unchanged; in-flight encrypted transactions submitted during epoch e remain decryptable at epoch e + 1.

### 4.7 Argon2id: keystore key derivation

Operator keys (validator FALCON keys, wallet keys, dev-tool keys) are stored encrypted on disk. The keystore uses AES-GCM for the bulk encryption and Argon2id for the password-to-key derivation. Argon2id is parameterized with m = 64 MiB, t = 3 iterations, p = 1 lane, producing a derivation cost of ~250 ms per guess on a single core — sufficient to make brute-force attacks against weak passphrases computationally expensive while keeping interactive unlock latency acceptable.

The Argon2id KDF is shared across the validator binary, the Rust SDK, and the developer CLI tools, so a wallet generated by `pyde-dev` decrypts with the same parameters in `pyde-rust-sdk`. The shared-Argon2id design replaced an earlier single-iteration Poseidon2-based KDF that was too fast against weak passphrases — caught and fixed during internal audit before testnet.

---

## 5. MEV Protection

### 5.1 The headline mechanism

MEV — the profit a block proposer can extract by reordering, censoring, or front-running unconfirmed transactions — is a structural problem on chains where the proposer can see the mempool. Every public AMM swap on Ethereum, every public liquidation on a public lending market, every NFT mint with a published reveal — all are exposed to a sophisticated proposer who can read pending transactions and insert their own to extract value. The major L1s have all engaged with the problem: Ethereum's MEV-Boost / proposer-builder separation, Solana's Jito, Cosmos's threshold-encryption proposals, and a wider literature of fair-ordering and commit-reveal designs are all live. The convergent direction in production has been to make the MEV market more efficient (auction the right to reorder) rather than to remove it from the protocol. Pyde takes the harder path: remove the proposer's ability to see, reorder, or selectively include transactions at all.

The mechanism is three interlocking properties:

1. **Encrypted mempool.** Transactions enter the mempool encrypted under a 86-of-128 threshold public key. No single validator can decrypt the payload; 86 of 128 must cooperate.

2. **Pre-decryption ordering commitment.** The proposer publishes a Poseidon2 commitment to the ordering of encrypted transactions in the proposed block before any decryption share is released. The commitment binds the order to a specific hash; the proposer cannot change it without producing a different block.

3. **Mandatory inclusion.** After 86 of 128 decryption shares converge and the block is decrypted, every successfully decrypted transaction up to the gas limit must appear in the sealed block in the committed order. A proposer who omits, reorders, or front-runs is detectable and slashable.

The combined effect: the proposer cannot front-run because they cannot read the mempool; they cannot back-run because the ordering is committed before decryption; they cannot drop because dropped transactions are detectable; they cannot sandwich because they cannot insert their own transaction into a position they have not committed to in advance.

### 5.2 The encrypted-tx lifecycle, in detail

```
CLIENT
  1. Build inner Transaction { from, to, value, data, gas, nonce, ... }
  2. FALCON-512 sign the inner transaction
  3. Fetch threshold pubkey via pyde_getThresholdPublicKey
  4. Kyber768.encapsulate(threshold_pubkey) → (kem_ct, shared_secret)
  5. keystream = Poseidon2-PRF(shared_secret, kem_ct, len)
     enc_msg = inner_tx_bytes XOR keystream
  6. mac = Poseidon2(shared_secret, kem_ct, enc_msg)
     Build EncryptedTx { sender, nonce, gas, chain_id, kem_ct, enc_msg,
                        mac, falcon_signature }
  7. Submit via pyde_sendRawEncryptedTransaction

NETWORK
  8. RPC ingress: validate FALCON sig, sender registration, nonce window,
     balance >= gas, chain ID, deadline, size, MAC (constant-time)
  9. Add to encrypted mempool, gossip on pyde/encrypted_transactions/1
 10. Mempool reaches consistent view across committee + full nodes

PROPOSER (this slot)
 11. Read local encrypted mempool, apply caps + sort, select up to gas-limit
 12. ordering_commitment = Poseidon2(tx_hash_1 || tx_hash_2 || ... || tx_hash_n)
 13. Build proposed block with ordering_commitment in header
 14. Broadcast proposal on pyde/consensus/1

EVERY COMMITTEE MEMBER
 15. Verify proposal signature (FALCON), proposer is correct VRF winner
 16. Verify ordering_commitment matches local view of pending txs
     (or accept if proposer's view differs by within tolerance — see §5.4)
 17. For each EncryptedTx in proposed block:
     a. partial_share = Threshold.share_decrypt(my_share, kem_ct)
     b. Sign and gossip share on pyde/consensus/1
 18. Receive partial shares from other committee members
 19. Once 86 shares collected for a given EncryptedTx:
     a. Lagrange-interpolate to reconstruct Kyber secret-key seed
     b. Kyber768.decapsulate(seed, kem_ct) → shared_secret
     c. Verify Poseidon2 MAC; derive keystream; XOR enc_msg → inner Transaction
     d. Verify inner FALCON signature
 20. Execute decrypted block via parallel scheduler
 21. Verify mandatory-inclusion invariant: every successfully-decrypted tx
     up to gas limit appears in the sealed block in committed order
 22. Compute post-block state root via JMT
 23. Sign FALCON HotStuff prepare/pre-commit/commit votes for the block

PROPOSER (next slot)
 24. Aggregate 86+ commit votes into HardFinalityCert
 25. Block is hard-finalized
```

The whole sequence completes in 1 – 2 slot periods (400 – 800 ms wall-clock) under normal operation.

### 5.3 What this prevents

The major MEV families and how Pyde structurally prevents each:

| Attack | Mechanism | Pyde defense |
| --- | --- | --- |
| Frontrunning | Proposer sees a profitable pending tx and inserts a copy with higher priority | Proposer cannot read encrypted mempool contents |
| Back-running | Proposer sees a pending tx and inserts a follow-up that captures the result | Ordering is committed before decryption; no insertion after the fact |
| Sandwich | Proposer inserts one tx before and one tx after a victim's swap | Both insertion points are pre-committed; victim's tx is invisible until decryption |
| JIT liquidity | Proposer adds liquidity right before a large swap and removes after | Same as sandwich — insertion points are pre-committed |
| Time-bandit | Proposer reorganizes finalized blocks to capture historical MEV | Hard finality is a FALCON QC; reorg requires > 42 validators to double-sign (slashable, 100 % stake loss) |
| Censorship | Proposer drops a tx targeting the proposer's interests | Mandatory inclusion: every decrypted tx up to gas limit must appear |
| Same-block oracle manipulation | Proposer sees an oracle-update tx and inserts trades that exploit | Oracle-update tx is invisible until decryption |

Two attack vectors are partially mitigated rather than structurally eliminated, and the whitepaper is honest about both:

- **Cross-block MEV.** A proposer with multiple consecutive slots could in principle delay a tx into a block they control. Pyde's per-slot VRF makes consecutive proposer slots low-probability (~1/128² ≈ 0.006 % for two in a row); the multi-proposer fallback further reduces the window. The bound is structural but not zero.

- **Censorship via mempool exclusion.** A proposer who never sees a tx in their local mempool view cannot include it. Mainnet ships with local-view enforcement: a committee member rejects a block whose ordering omits a tx that member has seen. False positives cost liveness, not safety, under HotStuff. Post-mainnet adds signed mempool commitments and cryptographic censorship slashing (§19) — a 2 – 3 slice project deferred from launch.

### 5.4 Per-sender rate limits and DoS resistance

Encrypted transactions are an attractive DoS surface — submitting an unbounded number of cheap-to-verify ciphertexts could starve the mempool. Pyde defends with four caps:

- **Per-sender rate limit:** 10 tx/s, 100 concurrent (`pyde-mempool::pool` constants).
- **Per-sender mempool cap:** `MEMPOOL_SENDER_CAP = 128`.
- **Global mempool cap:** `MEMPOOL_GLOBAL_CAP = 100 000` with hard-reject on overflow.
- **TTL eviction:** `MEMPOOL_TX_TTL = 240 s` (~600 slots), periodic sweep evicts older entries.

A sender who exceeds the rate limit gets RPC error `-32009` (per-sender cap exceeded) or `-32011` (global cap exceeded). Exceeded transactions are dropped at RPC ingress before mempool entry.

Each ciphertext is bound to its sender's FALCON public key via the Poseidon2 MAC, so a relay node cannot inflate spam by re-injecting a copied ciphertext under a different sender. The MAC verification is constant-time.

### 5.5 What ships at mainnet versus post-mainnet

The full encryption + ordering-commitment + mandatory-inclusion pipeline ships at mainnet. The end-to-end multi-node lifecycle test (`multi_node_encrypted_lifecycle`) passes 5 of 5 across a four-validator devnet with state-root convergence. Encrypted-path throughput is currently being instrumented; the plaintext path measures 4 K TPS sustained, and the encrypted path adds Kyber + threshold-decrypt overhead being characterized against the same 10-minute soak structure.

Two MEV-related upgrades are tracked as post-mainnet:

- **Signed mempool commitments + censorship slashing.** Each validator periodically signs a hash-set of encrypted_txs they have seen, gossiped to the committee. Replaces local-view vote-rejection with a cryptographic commitment to the committee's collective mempool view. Allows direct slashing of proposers who exclude a tx that ≥ f + 1 committee members signed. Detailed in §19.4.

- **Pedersen / KZG commitments on PSS resharing.** Adds verifiable secret sharing to the committee resharing protocol (§3.6), defending against a corrupt committee member contributing a polynomial whose constant term ≠ their actual share. Currently mitigated by detection (corrupt resharing causes ciphertexts to stop decrypting at the new epoch); cryptographic upgrade is detailed in §19.5.

---

## 6. The Pyde Virtual Machine

### 6.1 Design choices

The Pyde Virtual Machine (PVM) is a register-based VM with a 32-bit fixed-width instruction encoding, 16 general-purpose 64-bit registers, 8 wide 256-bit registers for cryptographic operations, a 4 MB flat address space, and 62 opcodes. The design choices follow from the four axioms.

A **register architecture, not a stack machine**, because parallel-execution scheduling and ahead-of-time compilation are both significantly simpler against an explicit register file. The EVM's stack model forces the JIT to track stack heights symbolically; a register VM hands the AOT compiler a representation that maps directly to native registers. Cranelift, Pyde's AOT backend, was designed for register IR; the impedance match is small.

A **fixed 32-bit instruction encoding**, because variable-length encoding (the EVM, WebAssembly, eBPF as it stands today) complicates instruction decoding on the hot path and introduces alignment hazards in the AOT path. A 32-bit encoding gives 6 bits of opcode (64 opcodes available, 62 used), 4 bits each of `rd / rs1`, and 18 bits of immediate-or-second-source — enough to express the full ISA without prefix bytes or LEB128 decoding. The cost is a slightly larger bytecode size; the mainnet block-gas budget absorbs this comfortably.

A **fully checked arithmetic semantics with trap-on-error**. Integer overflow in arithmetic, out-of-bounds memory access, division by zero, invalid jump target, malformed wide-register reference, and call-depth exhaustion all produce a trap that aborts the current call with `RESULT_TRAP`. This is opt-in safety at the VM level rather than at the language level; an Otigen contract that wants saturating or wrapping arithmetic must explicitly request it via the assembler's wrap-marked opcode variants. The wrap-on-overflow semantics for the `Addi` immediate-add instruction is parity-tested between the interpreter and the AOT path; the otic compiler relies on it for two's-complement negation and `u64::MAX` materialization.

### 6.2 Memory layout

```
0x000000  ┌──────────────────┐  Null-page guard (4 KB, traps on access)
0x001000  ├──────────────────┤  Code segment (read-execute, immutable)
   ...    │                  │
0x010000  ├──────────────────┤  Heap (grows up, mutable, page-allocated)
   ...    │                  │
0x400000  └──────────────────┘  Stack top (grows down, fixed reservation)
```

The 4 MB total address space is sized to fit the entire working set of a typical contract call in CPU L2 cache. Page allocation is on first touch; the page-touch is metered as a gas surcharge (`PAGE_ALLOC_GAS = 200`) to prevent O(1) unbounded reads. EIP-2929-style cold-vs-warm access metering applies to repeated reads of the same page within a single call: the first touch pays the page-allocation gas, subsequent touches pay only the per-access constant.

### 6.3 Opcode set

The 62 opcodes group into nine families:

| Family | Count | Examples |
| --- | --- | --- |
| Arithmetic (checked) | 14 | `Add`, `Addi`, `Sub`, `Mul`, `Div`, `Mod`, `Shl`, `Shr`, `Sar` |
| Arithmetic (wide / 256-bit) | 6 | `WideAdd`, `WideMul`, `WideMod`, `WideEq` |
| Memory | 8 | `Load64`, `Store64`, `Load256`, `Memcpy`, `Memset` |
| Control flow | 7 | `Jump`, `Branch`, `Call`, `Ret`, `Trap` |
| Storage | 4 | `Sload`, `Sstore`, `SloadCold`, `SstoreCold` |
| Cryptographic | 6 | `Poseidon2`, `Poseidon2State`, `MerkleVerify`, `VerifySig`, `Vrf` |
| External call | 4 | `CallExt`, `Delegate`, `Create`, `Create2` |
| Logging / events | 3 | `Log`, `LogTopic`, `LogData` |
| Assertion / abort | 4 | `Assert`, `Revert`, `Trap`, `OutOfGas` |
| Misc | 6 | block info, sender, value, gas left, chain ID, timestamp |

The wide opcodes operate on the 8 × 256-bit register file and are the machine-level primitives that Otigen lowers `u256` arithmetic onto. Memcpy is a single-instruction bulk copy bound by available gas (the gas cost scales with the byte count, drained on every byte rather than amortized — a parity bug between interpreter and AOT was caught and fixed during internal audit). The cryptographic opcodes hand off to native implementations rather than running Poseidon2 or FALCON-verify in pure interpreted code; this is what keeps the per-tx gas budget realistic for cryptography-heavy contracts.

### 6.4 The AOT compiler

Pyde compiles PVM bytecode to native machine code at deploy time using Cranelift as the codegen backend. The compiled code is cached per contract address; subsequent calls execute the compiled function directly via an `extern "C"` function pointer. There is no per-call interpreter overhead for compiled contracts.

The compile pipeline:

```
PVM bytecode  →  analyze (extract basic blocks, infer control flow)
              →  Cranelift IR generation (per-opcode lowering)
              →  Cranelift codegen (register allocation, instruction selection)
              →  JIT linking (extern "C" function pointer)
              →  cache by contract address
```

The headline correctness invariant is that **the AOT-compiled function and the interpreter must agree on every observable result for every reachable input**. This is enforced by a parity-test suite covering opcode semantics, gas metering, memory page-touch costs, storage surcharges, and log dynamic charges. Six distinct interpreter/AOT divergences were caught and closed by the internal audit — each one is now a parity test that runs in CI. The current parity suite covers the Counter contract, cross-contract Factory + Token, an Events contract, u256 arithmetic, and a Vault contract with deposits and balance reads.

The AOT does not speculate: each compiled function is the literal lowering of the bytecode at deploy time, with no runtime profile-guided optimization, no de-virtualization of `CallExt` targets, and no inlining across contract boundaries. The reasoning is determinism: every validator must produce the same execution trace, and speculative compilation introduces nondeterminism that is hard to reproduce across hardware. The performance left on the table is bounded; the determinism guarantee is unconditional.

### 6.5 Limits and call-depth

```
MAX_CODE_SIZE        = 60 KB     (per-contract bytecode size)
MAX_CALLDATA         = 64 KB     (per-call calldata)
MAX_TX_SIZE          = 128 KB    (full encoded transaction including sig)
MAX_EXT_CALL_DEPTH   = 64        (cross-contract recursion limit)
MAX_WITNESS_SIZE     = 1 MB      (per-block state-witness bound)
PAGE_ALLOC_GAS       = 200       (one-time cost per touched 4 KB page)
```

The 64-deep external-call limit is lower than the EVM's 1024. The reasoning is that FALCON verification overhead per call is non-trivial; a 1024-deep nested-call sequence on Pyde would consume orders of magnitude more wall-clock time than on the EVM. 64 is enough to support every realistic application pattern (proxy-impl-impl chains, cross-AMM routing, escrow-of-escrow) with comfortable headroom.

---

## 7. Otigen: The Smart Contract Language

### 7.1 Why a new language

Pyde could have shipped Solidity-on-PVM, Move-on-PVM, or a Rust-compiles-to-PVM toolchain. It ships Otigen — a purpose-built language with Rust-flavored syntax — because the protocol-level properties that Pyde provides (encrypted mempool, threshold decryption, FALCON signatures, Poseidon2 hashing, parallel execution via access lists) require language-level primitives that none of the existing options express well. Solidity's `tx.origin` semantics encode an MEV-friendly trust model. Move's borrow checker is an excellent fit for resource-tracking but not for the access-list inference Pyde's parallel scheduler needs. Rust's full surface area is too large for an audit budget. A purpose-built language with 30 keywords, narrow surface, and protocol-aware primitives is a more honest tool for the job.

### 7.2 The compile pipeline

```
contract.oti  →  lex     (tokens)
              →  parse   (AST)
              →  resolve (symbol table, type bindings)
              →  typeck  (type-check, trait satisfaction, overflow analysis)
              →  safety  (reentrancy, payable guards, bounds)
              →  IR      (mid-level intermediate representation)
              →  optimize(constant fold, dead-code elimination)
              →  codegen (PVM bytecode + ABI JSON)
              →  artifact (.json file with bytecode + ABI + selector table)
```

The CLI surface is small:

```
otic build contract.oti    # Compile to .json artifact (bytecode + ABI)
otic check contract.oti    # Type check only, no codegen
otic test contract.oti     # Run #[test] functions on PVM
otic abi contract.oti      # Output ABI JSON
otic fmt   contract.oti    # Format
otic doc   contract.oti    # Generate docs
```

`otic test` runs the `#[test]`-annotated functions inside a PVM interpreter with cheatcode access (snapshot, warp time, fund, expect-revert). This is the loop a contract developer lives in: write code, run unit tests against the same VM that mainnet runs, deploy.

### 7.3 The type system

Otigen's primitive types at testnet are fixed-width **unsigned** integers from `u8` through `u256`, `bool`, `Address`, and `String`. Composite types are `Vec<T>`, `Map<K, V>`, `Tuple`, `Array<T, N>`, and user-defined `struct` and `enum`. Generics are parametric for collections; user structs are monomorphic.

The integer types are checked by default: `let x: u64 = a + b;` traps on overflow. Wrapping or saturating semantics are explicit: `let x: u64 = a.wrapping_add(b);`. `u256` is a first-class type that lowers to the wide-register ISA in §6.3. There is no implicit numeric coercion: `u32` to `u64` is an explicit `as u64`.

Signed integer types (`i8` through `i256`) are reserved as keywords and recognized by the parser, but the typechecker rejects them today and the PVM ISA does not yet ship signed-arithmetic opcodes (`Sdiv`, `Smul`, `Slt`, `Sgt`). This is a deliberate testnet/mainnet-launch deferral tracked under audit 354: signed types ship in a post-mainnet point release once the ISA additions and their gas-pricing pass audit. Contracts that need signed semantics today encode them explicitly over `u256` (two's-complement, manual sign tests).

`Address` is a 32-byte type derived from `Poseidon2(falcon_pubkey)`. There is no plaintext-key pattern in the language; addresses are opaque values produced by key registration.

### 7.4 Storage, structs, and maps

Contract state lives in declared storage slots:

```otigen
contract Token {
    storage {
        owner:       Address,
        total_supply: u256,
        balances:    Map<Address, u256>,
        allowances:  Map<(Address, Address), u256>,
    }
    ...
}
```

The compiler assigns each storage slot a deterministic hash slot derived from the contract address and the field name. `Map<K, V>` uses `Poseidon2(slot || key_bytes)` to compute the per-key storage location, identical in shape to Solidity's mapping pattern but rooted in Poseidon2 rather than Keccak-256.

Storage reads and writes lower to PVM `Sload` / `Sstore` opcodes. The first touch of a storage slot in a transaction is a "cold" access (`SloadCold`, higher gas); subsequent touches are "warm" (`Sload`, lower gas). This is the same pattern as EIP-2929 in the EVM, ported to Pyde's gas model.

### 7.5 Function attributes

```otigen
#[constructor]            // Runs once at deploy, never callable again
#[view]                   // No state writes; safe to call without a tx
#[payable]                // May receive PYDE
#[reentrant]              // Explicitly opt-in to reentrancy (default: blocked)
#[test]                   // Run by `otic test`, not deployed
```

The `#[reentrant]` attribute is opt-in by design: Pyde's default is non-reentrant function calls, with the runtime tracking re-entry attempts and trapping unless the function is explicitly tagged. This eliminates the entire class of reentrancy bugs (Solidity's most-exploited primitive) by default. The opt-in path exists for the rare cases (typically callback-heavy DeFi composability) where reentrancy is the desired semantics.

### 7.6 Cross-contract calls and selectors

Function selectors are 4-byte FNV-1a hashes of the function name. The encoder produces calldata in the form `[selector:4][argument bytes]`; the dispatcher in the called contract matches on selector and routes to the appropriate function.

Cross-contract calls are typed:

```otigen
let token = Token::at(token_address);
let balance = token.balance_of(user);
```

The compiler extracts function signatures from every contract in a project at compile time, so the call site is type-checked against the actual signature of `Token::balance_of`. The lowered code is a `CallExt` opcode with the encoded selector and arguments.

### 7.7 The `cross_call!` macro

Otigen parses a `cross_call!` macro for cross-chain and oracle interactions through Pyde's parachain layer:

```otigen
cross_call!(
    target:   "ethereum",
    method:   "request_price",
    args:     (pair, address(self)),
    callback: "on_price_received",
);
```

The macro is asynchronous. The originating transaction completes after marking the call as pending in account state and emitting an event with the call ID; the actual cross-chain or oracle work happens off-chain at a parachain operator set, and the result arrives in a separate callback transaction (often many slots later, depending on the target chain's finality and the parachain's internal consensus). The named `callback` function is invoked on the originating contract with the attested result.

Combined gas — the Pyde-side execution plus the parachain-side execution — is computed at call time and billed in a single transaction; the user pays once. There is no separate token to hold for oracle queries, no separate billing flow for bridge calls. §10 specifies the parachain layer that provides this surface.

At mainnet the macro lowers to a runtime "not yet supported" return — the Otigen surface is in place so that contracts written today work without rewriting when the parachain layer ships post-mainnet (~ + 6 to + 12 months, §10.8).

---

## 8. State Model and Parallel Execution

### 8.1 The Jellyfish Merkle Tree

Pyde's authenticated state lives in a Jellyfish Merkle Tree (JMT) — the same data structure that underpins Aptos's state layer, a sparse Merkle variant optimized for incremental updates. JMT replaced an earlier sparse-merkle-tree implementation during the testnet bringup; the swap measured a roughly 40 × improvement in per-block commit latency, which was the proximate enabler for the 4 K TPS sustained throughput now measured on the laptop devnet.

Every state-touching operation — account balance change, storage write, account creation — produces a JMT update. At block end, the tree's root is the state root included in the block header. A light client or a future bridge (§10) can verify a single state cell by checking a Merkle path from the root to the cell against the published root.

The JMT is hashed throughout with Poseidon2. Internal nodes are `Poseidon2(left_hash || right_hash)`; leaves are `Poseidon2(key || value_bytes)`. The choice of Poseidon2 over Keccak is the same finite-field-friendliness argument from §4.4, with an additional benefit: Poseidon2 hashing is comparable in speed to SHA-2 on the 8-core validator hardware spec when the hash work is bounded by per-block gas.

### 8.2 Witnesses and light-client verification

A witness is the set of Merkle paths sufficient to verify every state cell touched by a block, plus the pre-block and post-block state roots. Witnesses are bounded by `MAX_WITNESS_SIZE = 1 MB` per block; the gate is enforced at the block-validation entry point before any proof verification work happens, so a malformed oversize witness cannot burn validator CPU.

A light client (or a future cross-chain bridge contract) needs only the block header (containing the post-block state root), the witness for the touched cells, and the active committee's FALCON public keys to verify any state mutation. There is no need for the light client to re-execute the block.

### 8.3 RocksDB backend

Pyde persists state to RocksDB. The store is segmented by column family:

| Column family | Contents |
| --- | --- |
| `accounts` | Account records (nonce, balance, code hash, storage root) |
| `storage`  | Per-contract storage (keyed by `Poseidon2(contract_addr || slot)`) |
| `code`     | Contract bytecode |
| `jmt_internal` | JMT internal nodes |
| `jmt_leaves`   | JMT leaves |
| `receipts` | Transaction receipts |
| `consensus_log` | Vote log, evidence, checkpoint log (fsync per write) |

LRU caches sit in front of the cold storage tiers (256 K entries each for accounts and storage), absorbing the hot working set in RAM. The 16 GB validator RAM spec is sized to fit the JMT internal-node cache, the LRU layers, the mempool, and the in-flight execution state with comfortable headroom.

Crash safety is guaranteed by `WriteOptions::set_sync(true)` on every consensus-state write (vote log, evidence ingest, checkpoint persistence). The fsync overhead is 25.5 µs per write on Apple Silicon NVMe; the per-slot vote write is a single fsync, the per-slot evidence write happens only on the rare equivocation path. The throughput cost is well under the 12,500 TPS target ceiling.

### 8.4 Parallel execution scheduler

Every Pyde transaction declares an access list — the set of `(contract_address, slot)` storage cells the transaction will read and write. The mempool validates the access list against the actual transaction at ingress (a transaction whose runtime touches a slot not in its declared access list traps); the scheduler uses the declared list to drive parallel execution.

The scheduler builds a directed acyclic graph of conflicts: two transactions conflict if either's write set intersects the other's read or write set. Topologically independent transactions execute concurrently on a worker thread pool sized to the validator's core count; conflict-bound transactions execute serially within their conflict group.

The expected speedup depends on the workload's conflict density. A plaintext-transfer workload (each transaction touches the sender + recipient pair) has a low conflict density and parallelizes well — a stress test of 1,000 parallel non-conflicting transfers completes in 1,000 independent scheduler groups at 100 % commit. An AMM-heavy workload (every swap touches the same pool reserve) has higher conflict density and parallelizes less; the scheduler degrades gracefully to serial execution within the contended group.

### 8.5 The two-phase commit

Block execution runs in two phases. The first phase is the parallel scheduler: transactions execute against a per-block snapshot, producing per-transaction state diffs and receipts. The second phase is the serial finalize: state diffs are applied in canonical order, the JMT updates incrementally, the post-block state root is computed, and the witness is materialized.

The split is deliberate. Parallel execution against a snapshot is cheap; serial JMT update is structured (every leaf update is an O(log N) tree mutation) and runs as fast as a single core can hash. The combination gives parallel throughput where the workload allows, with deterministic state-root computation that every validator independently agrees on.

A per-block undo log captures pre-execution state so that a transaction trap mid-execution can roll back its effects without re-executing prior committed transactions in the block. This is the same pattern as the EVM's journal but rooted in the JMT's per-leaf update model.

---

## 9. Networking

### 9.1 libp2p as the transport

Pyde's peer-to-peer networking is built on libp2p — the same modular networking stack used by Ethereum's beacon chain, Filecoin, IPFS, and Polkadot. The choice is pragmatic: libp2p's gossipsub is the only widely-deployed gossip protocol with the per-topic routing, mesh maintenance, and back-pressure characteristics Pyde needs, and rebuilding the layer would be a multi-engineer-year project against a well-tested incumbent.

The transports are TCP and QUIC, with QUIC preferred where firewall and NAT conditions allow. Connection encryption is the libp2p noise protocol, which uses Ed25519 / X25519 for the transport handshake. As discussed in §4.1, this is the only place pre-quantum crypto appears in Pyde's stack: an attacker who breaks Ed25519 learns the network topology but cannot forge a block, decrypt a transaction, or steal an account. Consensus-critical messages are FALCON-signed at the application layer; encrypted-mempool ciphertexts are Kyber-768 ciphertexts. The libp2p layer carries them, but does not authenticate them.

### 9.2 Channels

Pyde uses five gossipsub topics with distinct subscription and back-pressure characteristics:

| Topic | Subscribers | Content |
| --- | --- | --- |
| `pyde/blocks/1` | All nodes | Proposed and finalized blocks |
| `pyde/consensus/1` | Committee only | Votes, QCs, evidence, decryption shares, checkpoints |
| `pyde/transactions/1` | All nodes | Plaintext transactions |
| `pyde/encrypted_transactions/1` | All nodes | Encrypted-mempool ciphertexts |
| `pyde/sync/1` | Sync requesters + responders | Cold-sync and catch-up block requests |

The committee-only restriction on the consensus channel is enforced cryptographically: a peer that is not a current committee member is dropped from the topic mesh, and any consensus message it broadcasts is rejected at the recipient. This is what makes the gossipsub mesh efficient at 128 validators — committee message volume scales as O(committee × messages_per_slot), not O(network_size × messages_per_slot).

### 9.3 Peer discovery and authentication

Peer discovery uses Kademlia DHT with Pyde-specific bootstrap nodes. New nodes connect to a small set of seed peers from configuration or genesis, exchange peer lists via DHT walk, and form a working peer set within a few seconds.

Peer authentication has two layers. The libp2p noise handshake authenticates each peer's Ed25519 identity at the transport level. The Pyde-specific FALCON handshake binds the libp2p peer ID to a FALCON public key registered on-chain, so that consensus channels can enforce committee membership cryptographically. The FALCON handshake runs once per connection and caches; it does not add per-message overhead. The current design lands the FALCON binding before peer scoring, so a peer that fails the FALCON check is dropped before it can influence the gossip mesh.

### 9.4 Rate limiting and DDoS resistance

Network-layer DDoS resistance is built into the connection lifecycle:

- Maximum 5 new connections per second per source IP.
- Maximum 50 total peer connections.
- Maximum 30 inbound (the rest reserved for outbound dialing).
- Per-peer message rate limits with peer scoring.
- Evidence-channel ingest rate-limited to prevent FALCON-verify CPU burn from garbage-evidence spam.

A peer that fails repeated message-validation checks is downscored and eventually dropped from the mesh. The score thresholds are intentionally conservative for mainnet and tuned for higher selectivity in post-mainnet hardening.

### 9.5 The synchronization protocol

A new node syncing from cold reaches the chain head through a three-phase protocol:

1. **Trust-bootstrap.** Load the most recent published weak-subjectivity checkpoint (§3.5). Verify the FALCON signatures on the checkpoint against the previous checkpoint's committee. The result is a trusted (slot, state root, committee public keys) tuple.

2. **Backfill.** Request blocks from the trusted checkpoint forward to the current chain head via the `pyde/sync/1` channel. Verify each block's proposer signature, ordering commitment, decryption-share aggregation, FALCON quorum certificate, and state-root continuity.

3. **Live-tail.** Once at the head, switch to live participation on `pyde/blocks/1` and (if validating) `pyde/consensus/1`.

A four-validator devnet bootstrap completes in seconds. A larger network's bootstrap is bounded by the bandwidth from the seed peers; the operator can prefetch a snapshot from a published archive to skip the backfill phase entirely.

---

## 10. Cross-Chain Interactions and the Parachain Architecture

This section describes Pyde's cross-chain story. It is a body chapter — the architecture is settled at genesis even though shipping is staged. The parachain layer ships post-mainnet on a + 6-to-+ 12-month horizon, with detail expanded in §19. What this chapter establishes is the protocol-level structure that makes parachains permissionless, the primitive that mainnet ships to enable them, the unified gas model that hides the parachain layer from the user, and the comparison to the cross-chain models in market today.

### 10.1 The thesis

Cross-chain interaction in production crypto today is dominated by two failure modes. The first is custodial multisigs (Wormhole, Ronin, Nomad, Multichain) — every major bridge exploit on record has been a trusted-relay failure, and the cumulative loss across 2021 – 2023 is on the order of $3 B. The second is complex cross-chain protocols (LayerZero, Axelar, IBC) that bolt onto chains designed without cross-chain in mind, with trust models that depend on small operator sets, oracle-relayer coordination assumptions, or chain-specific light-client implementations.

Pyde takes a different path. Cross-chain — and more broadly, every form of decentralized external interaction (oracle networks, indexers, off-chain compute) — happens through a **parachain layer of decentralized infrastructure providers**. A parachain is not a sovereign app-chain in the Polkadot sense. It is a public, open-source implementation of a Pyde-published specification, run by a permissionless operator set that stakes PYDE, follows the spec's rules, and provides a specific service to Pyde contracts via the `cross_call!` macro. The contract-side surface is uniform: a contract calls `cross_call!`, pays a combined gas fee that covers both Pyde execution and parachain execution, and receives an asynchronous callback when the result is available.

### 10.2 The mainnet primitive: HardFinalityCert

The single piece of cross-chain infrastructure that mainnet ships is the `HardFinalityCert` already defined in §3.3. Restating the structure for completeness:

```rust
struct HardFinalityCert {
    slot:         u64,
    block_hash:   Hash,
    state_root:   Hash,
    voter_bitmap: u128,
    signatures:   Vec<FalconSignature>,
}
```

This certificate is the cross-chain-portable proof that "block N was hard-finalized on Pyde at state root R." Any parachain that bridges out of Pyde — or any contract on a counterparty chain that wants to verify a Pyde event — consumes this certificate. The verification cost is 86 FALCON-512 verifications (~86 ms on commodity hardware) plus one Merkle path verification from the state root to the bridged data — feasible on any chain with a reasonable VM. The cert's stability across the chain's lifetime is what makes everything in §10.3 – §10.7 possible without further mainnet protocol work.

### 10.3 Parachains as decentralized functional infrastructure

The Pyde core team publishes a **parachain specification** as part of the protocol. The spec defines:

- The interface a parachain must expose (which operations it serves, what arguments it accepts, what return shape it produces).
- The attestation format (how parachain operators sign their results so Pyde can verify them).
- The callback protocol (how attestations make their way back to the originating contract).
- The gas-metering model (how parachain compute is priced in PYDE compute units, see §10.4).
- The staking rules (PYDE bond per operator, slashing conditions for invalid attestations or downtime).

The specification is the protocol-level contract. Anyone can implement the spec — in Rust, Go, C++, Python, or any other language — and operate the resulting parachain. Multiple independent implementations of the same parachain category are encouraged; redundancy and operator competition are the reliability story. Pyde may publish reference implementations in major languages as starting points, but the reference implementations are not requirements. **All parachain code is open source by design**; the layer has no proprietary boxes, no privileged operators, no closed implementations.

Operator entry is permissionless. To run a parachain, an operator stakes PYDE according to the category's rules, runs a conforming implementation that meets the published hardware spec, and joins the operator set for that category. There is no application process, no slot auction, no parachain-team gatekeeping. An operator that signs invalid attestations is detectable by the rest of the operator set and slashable on Pyde via on-chain evidence.

Each parachain category chooses its own internal consensus mechanism — a small BFT instance among the operators, threshold-signature aggregation, proof-of-authority among the registered set, or whatever fits the category's latency and security requirements. The choice is documented in the category's spec entry; Pyde verifies the resulting attestation against the registered operator set regardless of how the operators agreed on it. This is the same pluggable-consensus design philosophy that Polkadot's BABE-and-GRANDPA split established as a reasonable shape — applied to a different scope (infrastructure providers, not app-chains).

Looking forward, the parachain attestation model is designed to evolve. As Pyde's ZK roadmap matures (§19.1 Phase 3, ~ + 24-36 months post-mainnet), parachain categories will be able to register a ZK circuit that proves correct execution of the category's operations, and the parachain layer will accept ZK-proof attestations alongside the consensus-signed and threshold-signature attestations described above. The implications fundamentally change the parachain trust model: a parachain category that ships ZK proofs no longer needs M-of-N operator honesty for safety — the proof itself is the trust anchor — and operator validation collapses from re-execution to proof-verification, a roughly two-orders-of-magnitude cost reduction for compute-heavy categories. A bridge parachain producing ZK proofs of Pyde state becomes verifiable on chains whose execution budgets cannot afford native FALCON verification, opening trustless interop with the entire crypto ecosystem rather than only with chains gracious enough to host the FALCON verifier. The parachain spec is sized to absorb this evolution without protocol-level changes; Phase 3 of the ZK roadmap is the integration that turns the parachain layer from "decentralized infrastructure with on-chain rules" into "decentralized infrastructure with cryptographic proofs of correctness."

### 10.4 The unified gas model

The most important UX consequence of the parachain architecture is that **the parachain layer is invisible to the user**.

Parachain function logic is gas-metered, just like Pyde's PVM. The category's spec defines the per-operation compute cost in the same compute units the PVM uses. When a Pyde contract calls `cross_call!`, the gas estimator computes the **combined cost** — the Pyde-side execution plus the parachain-side execution — and the user pays one transaction fee that covers both. The parachain operators earn their share of the fee in proportion to the work they perform, settled on-chain when the callback transaction lands.

There is no separate billing, no separate token, no separate wallet flow, no "buy LINK to pay the oracle" step. The user does not need to know that `cross_call!` routes through a parachain layer; they just see "this transaction costs X gas," sign once, and receive the result via the contract's callback function. The composition is seamless from the user's perspective and trust-minimized at the protocol level.

### 10.5 The cross_call! macro and the async callback pattern

An Otigen contract initiates a cross-call:

```otigen
cross_call!(
    target:   "ethereum",
    method:   "request_price",
    args:     (pair, address(self)),
    callback: "on_price_received",
);
```

What happens at the protocol level:

1. The Pyde validator runs the contract, hits the `cross_call!`, marks the call as pending in state, and emits an event referencing a unique call ID. The validator computes the combined gas (Pyde + parachain category) and bills the user.
2. The parachain operators for the target category (in this example, Ethereum-bridge parachains) see the event via gossip on the parachain-coordination channel.
3. The parachain operators execute the requested operation — in this example, calling the `request_price` function on the Ethereum chain via their Ethereum-side relayer, observing the result via Ethereum block headers, and aggregating the result.
4. Once the parachain's internal consensus produces an attestation (M-of-N FALCON sigs, a BFT QC, or whatever the category's consensus produces), an operator submits a callback transaction to Pyde. The callback transaction carries the call ID, the attested result, and the operator-set signatures.
5. The Pyde validator verifies the attestation against the registered parachain's operator set, then invokes the originating contract's callback function (`on_price_received`) with the result. The callback's gas was pre-paid as part of the original transaction.

The pattern is fully asynchronous: the originating transaction completes after marking the call as pending, often many slots before the callback fires (the latency depends on the target chain's finality and the parachain's internal consensus). Contracts that need request-pending semantics implement them as state transitions; the protocol does not constrain how the contract handles the response.

### 10.6 What kinds of parachains people will build

The spec is general enough to accommodate any decentralized service that returns an attested result. Concrete categories the spec is designed to enable:

- **Cross-chain message routers.** Pyde → Solana, Pyde → Ethereum, Pyde → Bitcoin, Pyde → other PoS L1s. Operators run nodes on the target chain and use standard light-client verification or chain-specific proof patterns to attest to Pyde-side observations of the target chain's state.
- **Oracle networks.** Price feeds (ETH/USD, BTC/USD), weather data, sports results, identity attestations, custom data. Operators aggregate from off-chain sources, apply deviation tolerance, and submit attested results via the same callback pattern.
- **Indexers.** Subgraph-style data services that materialize derived state (token holders, governance vote tallies, NFT ownership history) for cheap on-chain reads from contracts that would otherwise pay to scan storage.
- **Off-chain compute.** Zero-knowledge proof generation for compute-heavy operations, ML model inference, custom verifiable computation. The parachain runs the heavy compute and attests to the result; Pyde verifies the attestation cheaply.
- **Anything else that fits the spec.** The architecture is open. Categories that nobody has thought of yet can be built once the spec ships, without protocol changes.

### 10.7 Comparison to other decentralized-infrastructure and cross-chain models

The closest **functional** comparison is to **Chainlink**. Chainlink is a decentralized oracle network — operators run nodes that aggregate off-chain data and post attested results to a target chain. Pyde's parachain architecture extends the same model to all forms of decentralized external interaction (cross-chain bridges, oracles, indexers, off-chain compute) and integrates it natively into the L1's gas model. A Pyde contract calling `cross_call!` to an oracle parachain pays gas the same way it pays for any other operation: no separate token, no separate billing, no third-party SDK. Chainlink-style decentralized infrastructure as a first-class L1 feature.

The closest **scope** comparison is to **Polkadot**. Polkadot's parachain architecture supports sovereign app-chains via auctioned slots and shared validator security; the auction mechanism exists because Polkadot's relay-chain validator capacity is a finite resource that must be allocated. Pyde's parachain architecture has a different scope: not app-chains, but decentralized infrastructure providers organized by function. Operator entry is permissionless and gated by PYDE staking + spec conformance; there is no slot scarcity, no auction, no parachain-team gatekeeping. The two systems share Polkadot's pluggable-consensus design philosophy — BABE / GRANDPA is a precedent for letting parachain operator sets choose their own internal consensus — applied to different scopes.

**LayerZero, Wormhole, Axelar, and other cross-chain protocols** typically rely on an oracle-and-relayer trust model where the oracle (often a small set of operators) and the relayer collude to prove a message. Pyde's parachain operators are publicly known, stake PYDE on-chain, follow a published spec, and are slashable for misbehavior — a structurally different trust model from "oracle and relayer don't collude."

**Cosmos IBC** is the most rigorous cross-chain protocol shipped to date — light-client verification between sovereign zones. Pyde's parachain layer can interface with IBC by running an IBC-light-client parachain that bridges Pyde to Cosmos zones, but the protocol-level surface is different: IBC's primitive is zone-to-zone, Pyde's primitive is "contract-to-anywhere via a parachain layer."

**Ethereum's L2 ecosystem** fragments the user surface across L2s, each with its own sequencer (centralized in production, decentralization on roadmap), its own bridge (custodial trust assumption), and its own decentralization story. Pyde's parachain layer is one open spec, one staking token, one gas model, one set of trust assumptions — applied uniformly across every category.

### 10.8 What ships at mainnet versus post-mainnet

| Capability | Mainnet | Post-mainnet plan |
| --- | --- | --- |
| Sovereign L1 with hard finality | Yes | — |
| `HardFinalityCert` as cross-chain primitive | Yes | Used by every parachain that bridges out of Pyde |
| `cross_call!` Otigen macro | Stub (no-op at runtime) | Wired to the parachain layer when spec ships |
| Parachain specification published | No | ~ + 6 months |
| First reference parachain (likely Ethereum-bridge with FALCON-in-EVM verifier) | No | ~ + 6 to + 9 months |
| Multi-category ecosystem (bridges, oracles, indexers, off-chain compute) | No | ~ + 12 months |
| Multiple competing operators per category | No | ~ + 18 to + 24 months |
| Slot auctions for parachain inclusion | Not applicable | Not applicable — PYDE staking + spec conformance is the entry rule |

Pyde at launch is a sovereign L1 with a published parachain specification but no live parachain implementations. The parachain ecosystem is the post-mainnet surface; the architecture, the gas model, and the contract-side macro are settled at genesis. The implementations follow.

---

## 11. Account Model

### 11.1 Three account types

Every entity on Pyde is one of three account types. All addresses are the 32-byte output of a single Poseidon2 hash; the input bytes vary by derivation scheme:

| Type | Input to `Poseidon2(·) → 32 B` | Authorization |
| --- | --- | --- |
| Externally-owned account (EOA) | 897 B FALCON-512 public-key bytes | FALCON-512 signature(s) under `AuthKeys::Single` or `AuthKeys::Multisig` |
| Contract — nonce-derived (`CREATE`-style) | 32 B `deployer_addr` ‖ 8 B `deployer_nonce` (little-endian `u64`) = 40 B | None at the address; calls are authorized by the call-context sender |
| Contract — salt-derived (`CREATE2`-style) | 1 B `0xFF` ‖ 32 B `deployer_addr` ‖ 32 B `salt` ‖ 32 B `code_hash` = 97 B | Same as nonce-derived |

`code_hash` for `CREATE2` is itself `Poseidon2(deploy_bytecode)`. The leading `0xFF` byte mirrors the EVM's `CREATE2` convention so that `CREATE` and `CREATE2` outputs cannot collide for any deployer/nonce/salt triple. The canonical source is `crates/account/src/address.rs::derive_eoa_address`, `derive_create_address`, and `derive_create2_address`; serialization layouts here match those functions byte for byte.

Two well-known addresses are derived from fixed ASCII byte strings rather than from a key or deployer chain:

| Address | Input to `Poseidon2(·)` | Role |
| --- | --- | --- |
| Treasury | `b"pyde-treasury"` (13 B) | Accumulates the 10 % treasury share of every transaction's base fee (§12.3) |
| Airdrop pool | `b"pyde-airdrop-pool"` (17 B) | Pre-minted at genesis with the total claimable airdrop; debited by `ClaimAirdrop`, swept post-deadline (§11.5) |

Addresses are 32 bytes regardless of type. There is no distinction at the type level between an EOA and a contract from the perspective of a transaction recipient — a transaction sending value to an address that turns out to be a contract triggers the contract's payable-fallback path; sending to an EOA simply credits the balance.

### 11.2 Account record layout

The on-chain account record is 141 bytes fixed plus a variable-length `auth_keys` field:

```
nonce_bitmap:    [u8; 16]   // 16-slot rolling nonce window (no head-of-line blocking)
balance:         u64
storage_root:    [u8; 32]   // JMT root for this account's storage (contracts AND programmable EOAs)
code_hash:       [u8; 32]   // Poseidon2 of attached bytecode (contracts AND programmable EOAs; zero for simple EOAs)
acct_status:     u8         // Active | Exited | Slashed | Vesting | Frozen
auth_keys:       AuthKeys   // Variable: Single(pubkey) | Multisig(M, [pubkey; N]) | Programmable (post-mainnet)
```

The `code_hash` and `storage_root` fields are populated for any account with attached executable code — contracts at mainnet, and programmable EOAs once the post-mainnet feature ships (§11.6). Simple EOAs leave both fields zero. This unification — one set of fields for any account that carries code, regardless of whether it also carries signing keys — is what lets programmable accounts reuse the entire contract-execution machinery (PVM, AOT compiler, gas accounting, parity tests) instead of introducing a separate execution path for authorization policies.

The 16-slot nonce bitmap is the next design choice that needs explanation. A traditional sequential-nonce model (Ethereum) creates head-of-line blocking: if a wallet submits transaction N at high gas and then transaction N+1 at low gas, the chain must process N before N+1, even if N+1 is independent. Under a busy mempool, a stuck transaction freezes the entire account. Pyde's bitmap allows up to 16 in-flight transactions per account in any order within a sliding window; the wallet can submit nonces 50, 51, 52, 60 concurrently, and the chain commits each as gas allows. The window slides forward as the lowest-numbered open nonce commits.

### 11.3 Native multisig

Multisig is not a contract on Pyde; it is a first-class authorization mode. An account whose `auth_keys` is `AuthKeys::Multisig(M, [pubkey_1, ..., pubkey_N])` requires M valid FALCON signatures over the transaction hash, drawn from the listed public keys. The maximum is `MAX_SIGNERS = 16`. Signature verification at execution time produces M FALCON checks; gas cost scales with the signer count.

The motivation is twofold. First, the application surface for multisig (treasury, DAO, exchange custody) is large enough that contract-based multisig (Gnosis Safe and analogues on Ethereum) ends up reimplementing the same logic across many projects with subtle bugs. Second, the protocol-level treasury controls in §14 (`MultisigTx`, `RotateMultisig`) need an M-of-N primitive in the protocol regardless; exposing it to user accounts is incremental work for substantial application benefit.

### 11.4 Vesting and locked balances

Genesis and post-launch token allocations support vesting schedules. An account's record includes an optional vesting field carrying:

- `start_slot` — when vesting begins
- `cliff_slot` — when the first tranche unlocks
- `end_slot` — when full vesting completes
- `total_locked` — the original locked amount

The transaction validator checks every spending transaction against the vested-vs-locked split: only the vested portion at the current slot is spendable. This is enforced at the validation layer (before execution), so a contract-based bypass is structurally impossible — the protocol itself does not permit a transfer that would draw from locked balance. Misconfigured vesting (cliff > end) is rejected at genesis; the runtime prioritizes end-of-vesting over cliff if a contradiction occurs in legacy state.

### 11.5 Airdrop claim

The protocol supports Merkle-tree airdrop claims as a first-class transaction type. A genesis or governance event publishes an airdrop Merkle root and pre-mints the total claimable supply into a dedicated pool address. Each eligible recipient holds `(address, amount, Merkle proof)`; submitting a `ClaimAirdrop` transaction with the proof transfers the amount from the pool to the recipient and records the claim. After a configured deadline, an unclaimed remainder can be swept by the operator to a designated address (treasury or burn).

The on-chain `build_tree()` is public so any off-chain CLI tool can share the leaf and node formulation. The CLI tool itself is post-mainnet (see §19) — the on-chain primitive ships at launch.

### 11.6 Programmable accounts (post-mainnet)

Native multisig is the first step toward a fuller account-abstraction model, with the same opt-in design philosophy: simple EOAs pay nothing extra, while users who want programmable behavior get protocol-native primitives without a separate contract layer.

The post-mainnet roadmap extends `AuthKeys` with a third mode:

```
enum AuthKeys {
    Single(FalconPubkey),
    Multisig(M, Vec<FalconPubkey>),
    Programmable,                    // post-mainnet — bytecode at code_hash, state at storage_root
}
```

The design point: a programmable account is structurally an EOA — it has a signing key (carried by the policy or by an embedded key the policy verifies), a nonce, a balance — that *also* has attached executable code. The policy's bytecode lives at the account's `code_hash` field (the same field a contract uses to reference its bytecode); the policy's runtime state lives at the account's `storage_root` field (the same field a contract uses for its storage); the `AuthKeys::Programmable` marker distinguishes the account from a simple EOA or a regular contract. The unification means the protocol does not need a separate "policy execution" path: the same PVM that runs contract code runs policy code, with a flag indicating policy mode (which restricts state access to the account's own storage during the validation pre-check). The same gas accounting, the same parity tests between interpreter and AOT, and the same upgrade pathways apply. From the protocol's perspective, a programmable EOA is a contract that has signing keys, and a regular contract is a programmable account that has no signing keys.

A programmable account's policy runs on every transaction the account would authorize. The policy receives the candidate transaction (recipient, value, calldata, gas, presented signature set) plus access to its own state slots; it returns Allow or Deny. Concrete patterns people will want to write:

| Policy | What it expresses |
| --- | --- |
| Daily spend limit | At most 1,000 PYDE per 24 hours regardless of which signature is presented |
| Allow-listed recipients | Tx denied unless `tx.to ∈ {set of trusted contracts}` |
| Time lock | Tx denied until `slot > unlock_slot` |
| Tiered authorization | Small txs need 1 signature; medium need 2-of-3; large need 3-of-3 |
| Recovery flow | 2-of-3 sigs OR 1-of-3 after 30-day inactivity window |
| Tagged session caps | Cumulative spend for a tagged session is bounded |

The policy contract is sandboxed by the PVM, gas-metered, and read-restricted to its own account state (it cannot arbitrarily query other accounts during the validation pre-check). Policy execution adds a small per-transaction overhead — one extra PVM call — paid only by accounts that opted into the mode. Simple `Single`-keyed EOAs are unaffected.

The motivation is twofold. First, the user's threat model expands beyond "someone steals my private key." A programmable account with a daily spend limit and an allow-listed recipient set is meaningfully harder to drain even with full key compromise; the worst-case loss is bounded by the policy rather than by the balance. Second, the operator's cognitive load shrinks: the account is the rule book, not just a signing key. A treasury that requires "spend > $100,000 needs 3-of-5 signatures and a 24-hour delay" is one account configuration, not a separate Gnosis-Safe-style contract that has to be deployed, audited, and re-learned by every new signer.

This is account abstraction as a protocol-native mode rather than a contract layer every project re-implements. The native multisig that ships at mainnet is the proof that the architectural direction works; the full programmable mode ships post-mainnet (Section 19).

### 11.7 Session keys (post-mainnet)

A session key is a delegated authorization that lets an application sign a bounded set of transactions on behalf of an account without prompting the master wallet for each one. The use case is dApps where the wallet popup is itself the friction blocking adoption — gaming with hundreds of small actions per minute, AI agents executing strategies on a schedule, social and consumer apps where "sign every action" is unworkable.

The protocol-level shape:

```rust
struct AuthorizedSession {
    session_pubkey:    FalconPubkey,
    valid_until:       u64,                // slot deadline
    scope: SessionScope {
        allowed_contracts: Vec<Address>,    // narrow by default
        allowed_methods:   Vec<u32>,        // 4-byte selectors, allow-listed
        max_per_tx:        u64,             // PYDE cap per session-key tx
        max_total:         u64,             // cumulative session cap
    },
    nonce:             u64,                 // master's nonce when issued
    master_signature:  FalconSignature,     // master signs the above
}
```

The master account issues a session by submitting a `RegisterSession` transaction once. From then on, transactions can be signed by the session key and validated against the master's authorization plus the session's running spend. A session-key-signed transaction carries the session's public key and a signature over the transaction hash; the on-chain `AuthorizedSession` record is referenced by ID.

Validators check, in order: the session's `valid_until` has not passed, the operation falls within the session's allow-listed contracts and methods, the cumulative spend stays under the session caps, and the session key's signature on the transaction hash verifies. The master account's authorization signature is verified once when the session is registered and cached in account state thereafter; it does not need to be re-verified per transaction.

Revocation is instant. The master submits a `RevokeSession` transaction; the session record is marked invalid; subsequent session-key transactions fail validation at the validator's auth layer.

Two design choices keep session keys from becoming a slow-MEV channel. First, defaults are narrow: a session created via the SDK defaults to a single contract, a small allow-list of methods, a 24-hour duration, and a low per-tx cap. A wallet has to make explicit, larger grants explicit to the user; a wallet that quietly auto-creates broad sessions without consent is breaking the social contract that the protocol primitives are designed to surface. Second, every session-key transaction emits an observable event keyed to the master account, so the master (or a watcher process the master configures) can monitor session activity in real time.

Session keys ship post-mainnet (Section 19), as a complement to programmable accounts. The two features together give Pyde dApps the UX surface that has been a hand-rolled retrofit on every major chain to date.

---

## 12. Gas and Fee Model

### 12.1 EIP-1559 inheritance, no priority tips

Pyde's fee model is EIP-1559 with one substantive simplification: there are no priority fees. Every transaction at a given block's `base_fee` pays exactly the same per-gas price; there is no priority lane, no MEV-Boost-style bid, no proposer tip.

The reasoning is structural. EIP-1559 priority fees exist to give wallets a way to signal "this transaction is more time-sensitive than others." On Ethereum, the proposer can see the mempool and prioritize accordingly; the priority fee is the price signal. On Pyde, the proposer cannot see the mempool (encrypted-mempool path, §5), so there is no information channel through which a priority signal could be acted on. Adding a priority field would price an asymmetry that does not exist. The mempool's per-sender rate limits, global cap, and TTL eviction (§5.4) handle congestion; the base fee handles long-run pricing.

### 12.2 Block gas, base fee adjustment

```
GAS_TARGET       = 400_000_000      // 400 M gas per block at equilibrium
GAS_CEILING      = 1_600_000_000    // 1.6 B gas per block at the elastic ceiling (4×)
GENESIS_BASE_FEE = 50_000_000_000   // 50 gwei equivalent (50 × 10⁹ quanta per gas unit)
ADJUSTMENT_DIV   = 8                 // Max ±12.5% base-fee change per block
```

The base fee adjusts each block based on the previous block's gas usage:

```
if used > target:  base_fee_next = base_fee × (1 + (used - target) / target / 8)
if used < target:  base_fee_next = base_fee × (1 - (target - used) / target / 8)
```

The maximum adjustment per block is 12.5 %; the elastic block ceiling is 4 × the target, so under sustained pressure the base fee climbs quickly until equilibrium is restored. This is the same dynamic Ethereum uses; the parameters are tuned for Pyde's 400 ms slot rate (twice as many adjustment opportunities per minute as Ethereum's 12-second slot).

### 12.3 Fee distribution

Every base-fee payment splits 70 / 20 / 10:

- **70 % burn** — permanently removed from supply, contributing to deflationary pressure under sustained activity.
- **20 % validator** — credited to the proposer's reward stream for the block, plus a treasury-defined floor for under-load periods.
- **10 % treasury** — accrues to the treasury account, controlled by the multisig described in §14.

The split is locked in code at the validation layer with constants `FEE_BURN_PCT = 70`, `FEE_VALIDATOR_PCT = 20`, `FEE_TREASURY_PCT = 10`. The constants are referenced from the `tx` and `consensus` crates and from the README; future changes require a coordinated PIP and validator upgrade. There is no per-block governance lever to adjust the split.

### 12.4 Per-opcode gas costs

Sample gas costs for representative opcodes (the full schedule lives in `crates/pvm/src/gas.rs`):

| Operation | Gas cost |
| --- | --- |
| `Add`, `Sub`, `And`, `Or`, `Xor`, comparison | 3 |
| `Mul` | 5 |
| `Div`, `Mod` | 8 |
| `Sload` (warm) | 100 |
| `SloadCold` (first touch) | 2 100 |
| `Sstore` (warm, no change) | 100 |
| `Sstore` (warm, set) | 5 000 |
| `SstoreCold` (first touch, set) | 22 100 |
| `Poseidon2` (1 block) | 36 |
| `MerkleVerify` (per level) | 36 |
| `VerifySig` (FALCON-512 verify) | 30 000 |
| `CallExt` (base) | 700 |
| `Memcpy` (per byte) | 3 |
| Page-touch surcharge | 200 (one-time per 4 KB page) |

The `VerifySig` cost reflects the FALCON-512 verify time; cryptographic primitives are explicit gas line items rather than implicit costs in interpreted code. This is what keeps Pyde's gas accounting honest in the face of post-quantum signature overhead.

### 12.5 Gas tank and paymaster

Two account-abstraction-style features are implemented but production-restricted:

- **Gas tank.** A per-account spending cap that lets a wallet pre-fund a "gas budget" separately from the spending balance. Useful for offboarding gas decisions from the per-tx UX.
- **Paymaster.** A pattern where a third party (typically a dApp) sponsors gas for a user's transaction.

Both features are implemented in the transaction layer. Both are currently rejected on production chain IDs by the validation layer (caught during internal audit). The reason is integration risk: combinations of multisig + paymaster + gas-tank create authorization-flow paths that have not been audited end-to-end. Mainnet ships with these features gated; the gates lift after an additional audit pass in the post-mainnet hardening track.

### 12.6 The effective cost of a transaction

The headline gas price is one input to what a user actually pays. The other inputs — priority tips, MEV extraction, separate-token holdings for oracle and bridge calls — are absent from Pyde by design, and their absence pushes the effective per-transaction cost meaningfully below what comparable chains charge for the same logical operation. Four compounding mechanisms drive this:

**EIP-1559 base fee floats with utilization.** At demand below the 400 M block-gas target, the base fee drops by up to 12.5 % per block, all the way to the genesis base-fee floor (50 gwei equivalent). A chain operating below saturation runs at the floor; users see headline gas prices that look like Ethereum during its quietest hours. Pyde's high design-target throughput (12,500 sustained TPS, ~ 19 K theoretical at the gas ceiling) means that for every realistic demand level except sustained saturation, the chain operates with substantial headroom and the base fee stays low.

**No priority tips means no fee-bump war.** Every transaction in a block pays the same per-gas price. There is no tip-escalation race during congestion, no wallet UI that quietly raises a "recommended tip" by 5 × in a busy moment, no "I tipped $200 in a panic" failure mode. The user pays base — predictably, transparently, equally.

**No MEV tax on the all-in cost.** Sandwich attacks, frontrunning, and JIT liquidity each impose a hidden cost on every public swap on every visible-mempool chain, measurable in basis points per trade and aggregating to multi-billion-dollar annual extraction industry-wide. Pyde's encrypted mempool removes this entire category. The all-in cost of a Pyde DEX swap is the gas, not the gas plus the MEV. For a retail trader doing $1 000 of swap volume per month on a chain with a typical 20-bps MEV tax, this is a $24-per-year saving that no headline gas-price comparison captures.

**No separate token for oracle or cross-chain calls.** When a contract uses `cross_call!` to query an oracle, route a cross-chain message, or request off-chain compute, the user pays one combined gas fee in PYDE — no LINK to hold for oracle access, no separate billing for the bridge layer, no token-conversion friction. The "I need to hold five tokens to use this dApp" failure mode is structurally absent (§10.4).

**The 9-decimal precision keeps low-value transactions sensible.** With 10⁻⁹ PYDE precision (Solana-equivalent), micro-payments, gaming actions, AI-agent ticks, and consumer-app interactions stay economically meaningful at any plausible PYDE valuation. The chain does not price out high-frequency low-stake interactions at the precision floor.

**The honest caveat.** Cheap fees are not a feature; they are an emergent property of supply versus demand. EIP-1559 will move the base fee up exactly the way it does on Ethereum if demand exceeds supply, and there are workloads (genuinely-saturated mainnet, viral consumer apps) where Pyde's fees will rise. Pyde's claim is structural fee economics, not a guarantee of perpetually-low headline numbers — but the structure pushes hard in the user's favor at every level of utilization, and the four mechanisms above are protocol-level rather than market-level. The user does not pay tips, does not pay MEV tax, does not pay a separate oracle token. Whatever the chain is at any moment, it is at least these things cheaper than the chain that does not have these properties.

---

## 13. Tokenomics

### 13.1 The PYDE token

PYDE is the native token of the Pyde chain. It is the only token recognized by the protocol for staking, fee payment, and governance multisig operations. Application tokens (ERC-20-style fungibles, NFTs, etc.) are smart contracts and are first-class citizens, but they are not interchangeable with PYDE for protocol-level functions.

```
GENESIS_SUPPLY        = 1 000 000 000  PYDE  (10¹⁸ quanta)
DECIMALS              = 9                    (1 PYDE = 10⁹ quanta)
VALIDATOR_STAKE       = 10 000  PYDE         (10¹³ quanta)
UNBONDING_PERIOD      = 3 024 000 slots      (~14 days)
```

The 9-decimal precision (rather than the 18-decimal precision common on Ethereum) reflects a practical assumption: per-tx fee precision below 10⁻⁹ PYDE is irrelevant at any plausible PYDE valuation. Storage is correspondingly more compact.

### 13.2 Inflation schedule

Per-block protocol inflation follows a step-down schedule:

| Year | Inflation rate (per epoch, basis points) |
| --- | --- |
| 1 | 5.00 % (500 bps) |
| 2 | 3.00 % (300 bps) |
| 3 | 2.00 % (200 bps) |
| 4+ | 1.00 % (100 bps) |

Inflation is computed per block as a fraction of the prior block's circulating supply, rounded to whole quanta. The minted PYDE is distributed across active validators in proportion to their participation in the previous epoch, plus a treasury share. The 1 % terminal rate is fixed indefinitely; any change requires a PIP-driven validator upgrade.

### 13.3 Validator rewards

A validator earns from two streams, tracked separately:

- **Inflation reward.** The validator's share of the per-block protocol inflation, accumulated per epoch and claimed via `ClaimReward` transactions. The active validator count divisor is monotonic per-epoch (only counts validators present for the full epoch), preventing reward dilution by transient validators.

- **Fee reward.** 20 % of every base-fee payment in blocks the validator successfully proposes or attests to, distributed in proportion to attestation share.

A validator who is `Exited` or `Slashed` cannot claim accrued rewards from prior epochs; the accrued amount is forfeited to the treasury and burn pool. This is the gate that prevents an exited validator from withdrawing stake and then claiming rewards earned during the time they were active — an early implementation had this gap, which the internal audit caught and fixed before testnet.

### 13.4 Genesis allocation

The 1 B PYDE genesis supply is distributed across allocation buckets, with per-bucket caps enforced at genesis validation:

| Bucket | Allocation | Notes |
| --- | --- | --- |
| Foundation reserve | TBD | Long-horizon protocol stewardship; multisig-controlled |
| Validator subsidy | TBD | Pre-mints distributed via the validator subsidy stream over the first N epochs |
| Airdrop pool | TBD | Pre-minted into the airdrop pool address; claimable via Merkle proof |
| Vesting buckets (team, advisors, early backers) | TBD | Per-account vesting schedules: cliff, end, monthly unlock |
| Public sale / ecosystem | TBD | Liquid at genesis |
| Treasury seed | TBD | Initial treasury balance, multisig-controlled, governed via PIP-attached MultisigTx spends |

Specific allocation percentages are governance-set in the genesis TOML and subject to community input before the genesis ceremony. The protocol enforces only the structural constraints: the per-bucket cap arithmetic must equal the genesis supply, the vesting schedules must not be self-contradictory, and the airdrop Merkle root + pool pre-mint must reconcile to the same total. Each of these constraints is enforced at genesis-validation time and was hardened during the internal audit cycle.

### 13.5 Burn dynamics

The 70 % fee-burn rate is the largest deflationary force on the supply. Under sustained activity at the 12,500 TPS design target, with a representative average gas-per-transaction of ~52 K and a base fee of 50 gwei equivalent, the per-second burn is on the order of:

```
12 500 tx/s × 52 000 gas × 50 × 10⁹ quanta / 10⁹ (decimals) × 0.7 (burn share)
= ~22.75 PYDE per second burned
≈ 718 M PYDE per year burned at full saturation
```

This is a design ceiling, not a forecast. Actual burn depends on actual throughput, which depends on actual usage. The point is that the deflationary pressure is calibrated such that, at full network saturation, burn outpaces the 1 % terminal inflation rate by roughly two orders of magnitude. Pyde becomes a deflationary asset under high utilization and a mildly inflationary asset under low utilization. The crossover point is when annual burn equals annual mint, at roughly 0.6 % of the design throughput; beyond that, supply contracts.

A `total_burned` state variable maintains a running audit trail for any party verifying the supply curve.

### 13.6 Design rationale

Pyde's tokenomics is not arbitrary. Each parameter is informed by what the field has tried, what has worked at scale, and where Pyde deliberately diverges. The honest summary, parameter by parameter:

**EIP-1559 base fee + elastic blocks (inherited from Ethereum).** The base-fee + elastic-ceiling mechanism is one of the field's clearest engineering wins. It self-stabilizes under demand spikes without operator intervention, replaces the wasteful first-price auction that preceded it, and gives wallets a predictable price curve to estimate against. Pyde adopts the mechanism wholesale and tunes the parameters (12.5 % adjustment cap per block, 4 × elastic ceiling) for the 400 ms slot rate. The Ethereum research community produced this design; Pyde's contribution is the integration, not the invention.

**70 / 20 / 10 fee distribution (Pyde-specific blend, informed by Ethereum and Bitcoin).** The two endpoints in the design space are well-known: Ethereum burns 100 % of the base fee post-Merge and routes priority tips to validators; Bitcoin pays validators the full transaction fee with no burn. Pyde sits between them — 70 % burned (capturing most of Ethereum's deflationary discipline), 20 % to the validator (income, since there are no priority tips), 10 % to a treasury (protocol-development funding without taxing validators). The split is calibrated to keep validators economically motivated under low-throughput conditions while retaining strong deflationary pressure under high throughput.

**No priority tips (Pyde-novel, justified by encrypted mempool).** Every other major chain charges priority fees because the proposer can read the mempool and prioritize accordingly. Pyde's encrypted mempool eliminates that information asymmetry, so a priority tip would price an asymmetry that does not exist (§12.1). Removing tips also removes a tax that retail users disproportionately pay — sophisticated users tip strategically against measured base-fee curves, retail users tip blindly to "make sure it goes through." The information-asymmetry removal solves the technical problem; the no-tips choice solves the user-cost problem.

**Decreasing inflation schedule, terminal at 1 % (informed by Bitcoin halvings, smoothed).** Bitcoin's halving model established the precedent that monetary policy on a chain can get tighter over time on a known schedule — and that predictability over decades is itself a feature. Bitcoin halves abruptly every four years; Pyde steps down more smoothly (5 → 3 → 2 → 1 % across four years) and then locks at 1 % indefinitely. The terminal 1 % is permanent without a coordinated PIP and validator upgrade — deliberately friction-heavy. This gives long-term holders a predictable monetary policy without Bitcoin's discontinuous halvings or Ethereum's variable-by-staked-ETH post-Merge issuance.

**Fixed 10,000 PYDE validator bond, equal voting (Ethereum's fixed-stake combined with one-validator-one-vote).** Fixed validator stake (in contrast to Cosmos / Solana variable-stake delegation) is Ethereum's choice, and a defensible one — it caps the per-validator capital requirement and makes the validator-set economics legible. Pyde adopts the fixed bond at 10,000 PYDE and combines it with one-validator-one-vote (§1.2 Axiom 4), pushing one step further than Ethereum: stake doesn't influence voting at all. The bond is anti-sybil, not power-multiplier. To gain a second vote, a holder must stand up a second independent validator. This is Pyde's strongest divergence from the rest of the PoS field.

**9-decimal precision (from Solana).** Solana uses 9 decimals (lamports = 10⁻⁹ SOL); Pyde uses 9 decimals (quanta = 10⁻⁹ PYDE). Finer than typical asset-pricing requires, coarser than Ethereum's 18-decimal precision; the balance is between storage compactness and per-tx fee precision. Solana proved 9 decimals is sufficient at production scale, and Pyde inherits the choice.

**14-day unbonding period (informed by Cosmos's 21 days, calibrated to Pyde's checkpoint cadence).** Cosmos chains typically use 21-day unbonding periods to defend against long-range attacks while bounding the cost of validator exit. Pyde uses 14 days — slightly shorter, because Pyde's weak-subjectivity-checkpoint defense (§3.5, every 64 epochs ≈ 7 hours) shrinks the long-range-attack window that the unbonding period needs to cover. The unbonding window is still long enough to expose double-sign evidence on the chain before stake is released.

**Off-chain governance + multisig treasury (from Bitcoin / Ethereum, against Cosmos / Polkadot).** The two precedents are clear and divergent. Bitcoin and Ethereum evolve their protocols through public off-chain proposal processes (BIPs, EIPs) and voluntary client upgrade; the legitimacy is anchored in social consensus. Cosmos and Polkadot use on-chain stake-weighted voting for protocol changes and treasury spends; the legitimacy is anchored in token concentration. Both have track records. Pyde chooses the Bitcoin / Ethereum model — off-chain PIPs for protocol changes (§14.1), multisig treasury with PIP-attached spends for funding (§14.3) — because the Cosmos / Polkadot model has shown coalition dynamics that the off-chain model avoids. This is one of the editorial calls in the design that the user should be able to disagree with cleanly; the §14.2 reasoning argues the case at length.

**Where Pyde deliberately doesn't innovate.** Vesting schedules (cliff + linear unlock), airdrop Merkle claims, the genesis allocation bucket structure, and the reward-claim pattern are all standard. These are well-understood patterns where reinvention adds risk without adding value; Pyde inherits the field's playbook on all of them.

The thesis: tokenomics is one of the easiest places for an L1 to invent unnecessarily. Pyde adopts the field's defensible mechanisms (EIP-1559, fixed bond, 9 decimals, vesting / airdrop / unbonding patterns), diverges where there is a specific reason to (no priority tips because of encrypted mempool, equal voting because stake-weighted voting concentrates power, off-chain governance because on-chain has track-record problems), and stays out of the parts where reinvention adds risk. The result is monetary policy that is honest about its inheritances and specific about its choices.

---

## 14. Governance

### 14.1 The PIP process

Pyde governance is deliberately off-chain. Protocol changes are proposed, debated, and ratified through Pyde Improvement Proposals (PIPs) — a public, versioned process modeled on Bitcoin's BIPs and Ethereum's EIPs, hosted at the `zarah-s/pips` repository, and ratified by PIP-0001 (which establishes the PIP process itself).

PIPs come in three categories:

- **Standards Track** — consensus-breaking changes. A new opcode, a new transaction type, a change to fee distribution, a change to the consensus protocol.
- **Meta** — process changes. Updating the PIP workflow itself, changing the dispute-resolution model.
- **Informational** — design notes, best practices, non-binding analyses.

Standards Track PIPs follow a lifecycle: Draft → Review → Last Call → Accepted → Final (or Rejected, or Withdrawn). A PIP that reaches Accepted status enters a 6.5 M slot (~ 30 day) activation window before validator clients are expected to enable it.

Validator upgrade is voluntary. A validator that disagrees with an Accepted PIP is free to refuse the upgrade; if enough stake (> 33 %) refuses, the PIP fails to activate and the chain continues on the prior protocol. This is the same model as Bitcoin and Ethereum hard forks: rough consensus by social process, executed by individual operator choice.

### 14.2 What governance is *not*

Pyde does not have on-chain stake-weighted voting on protocol changes. There is no PYDE-token-vote referendum that activates a fork, no two-chamber governance system, no on-chain lever that lets a 51 %-of-stake coalition unilaterally change protocol parameters. This is a deliberate choice; the alternative was considered and rejected (rationale catalogued in §19.9).

The reasoning: on-chain stake-weighted governance on consensus-breaking changes makes the chain's evolution a function of token concentration. In every historical instance — Cosmos governance proposals on parameter changes, Polkadot referenda, MakerDAO emergency votes — the median voter ended up being a small coalition of large holders, validators, or delegated voting pools. The political legitimacy of "the chain voted" is not what it appears. Pyde leans the other way: protocol changes go through public technical debate (the PIP process), and validator operators decide individually whether to ship them. Token holders influence the process by being part of the community discussion; they do not have a direct voting right.

The cost is slower decision-making for parameter changes that a stake-weighted vote could ratify in days. The benefit is that controversial changes either earn broad rough consensus or do not happen at all; the chain's evolution is not held by whoever owns the most tokens.

### 14.3 What governance *is* on-chain

On-chain governance is restricted to four operations, all gated by an M-of-N FALCON multisig with the multisig keys held by community-recognized signers:

| Tx type | Operation | Notes |
| --- | --- | --- |
| `MultisigTx` (type 9) | Treasury spending | M-of-N signature; spend transactions reference a `data_digest = hash(pip_file_contents)` for auditable PIP → on-chain linkage |
| `RotateMultisig` (type 10) | Signer rotation | Adds, removes, or replaces signers; same M-of-N gating |
| `EmergencyPause` (type 11) | Halt non-Resume tx classes for a bounded duration | Maximum 30-day window, baked into the signed preimage |
| `EmergencyResume` (type 12) | Lift an emergency pause early | Same M-of-N gating |

The suggested defaults are 7 signers with a threshold of 4. The actual signer set and threshold are governance-set at genesis and rotatable via `RotateMultisig`. The hard maximum is `MAX_MULTISIG_SIGNERS = 16`.

The `data_digest = hash(pip_file_contents)` field on `MultisigTx` is the audit-trail mechanism that links treasury spends back to the PIPs that authorized them. A spend without a corresponding accepted PIP is detectable in the on-chain history; the social process holds the multisig signers accountable for the linkage.

### 14.4 Emergency pause semantics

The `EmergencyPause` primitive exists for the genuinely-rare case where a critical bug requires halting non-essential transactions while a fix ships. The duration is bounded into the signed preimage with a hard 30-day maximum; the pause auto-expires on the deadline regardless of further action. `EmergencyResume` allows early lift if the issue resolves sooner. The pause does not prevent block production, finality, or staking operations — only the affected transaction classes are gated. This is the safety valve, not a governance tool.

The state-writeback clobber protections in the multisig handlers prevent a `MultisigTx` whose target equals the sender from executing; this closes a class of treasury-drain attacks where a malicious signer set could direct a spend to themselves and have the post-execution writeback overwrite the credit.

---

## 15. Security

### 15.1 The attack surface

A blockchain's attack surface is the union of every protocol layer's failure modes. Pyde's surface, with the defense for each entry, fits in one table:

| Attack class | Vector | Defense | Status |
| --- | --- | --- | --- |
| BFT safety violation | > 42 validators double-sign | Hard finality is a 86-of-128 FALCON QC; double-signers are slashable for 100 % of stake (§3.4) | Live |
| Long-range attack | Old validator keys sign alternate history | Weak-subjectivity checkpoints (§3.5); new nodes start from a trusted recent checkpoint | Live |
| Sybil | Many cheap validator identities | 10 000 PYDE bond per validator + equal voting (§3.4, §1.2 Axiom 4) | Live |
| Eclipse | Adversary surrounds a node's peer set | Diverse peer selection via Kademlia DHT; bootstrap-peer fallback; FALCON peer authentication (§9.3) | Live |
| DDoS — connection flood | Mass new-connection spam | 5 conns/s per IP, 50 max peers, 30 inbound (§9.4) | Live |
| DDoS — gossip flood | Mass message spam on a topic | Per-peer rate limits, peer scoring, evidence-channel throttling | Live |
| DDoS — mempool flood | Mass tx submission | Per-sender rate limit (10/s, 100 concurrent), per-sender mempool cap (128), global cap (100 000), TTL eviction (240 s) (§5.4) | Live |
| Frontrunning / MEV | Proposer reads pending txs and inserts trades | Threshold-encrypted mempool + ordering commitment + mandatory inclusion (§5) | Live |
| Censorship | Proposer drops a tx | Mandatory inclusion + local-view enforcement; signed mempool commitments + slashing | Live (local-view); cryptographic upgrade post-mainnet (§19) |
| State manipulation | Adversary forges Merkle proof | Poseidon2-rooted JMT; light-client verification against published state root (§8.2) | Live |
| Quantum cryptanalysis | Adversary breaks ECC consensus or account keys | Post-quantum from genesis: FALCON-512, Kyber-768, Poseidon2 (§4) | Live |
| VM exploit | Crafted bytecode escapes the VM | Checked arithmetic, bounds-checked memory, trap on malformed inputs, parity tests interpreter ↔ AOT (§6) | Live |
| Key compromise (offline) | Operator's keystore stolen | AES-GCM + Argon2id KDF (m = 64 MiB, t = 3) (§4.7) | Live |
| Replay | Old signed tx submitted on a new chain | `chain_id` field bound into signature; nonce window prevents intra-chain replay (§11.2) | Live |
| Treasury drain | Malicious multisig spend | M-of-N FALCON signature + state-writeback clobber protection + 30-day-bounded `EmergencyPause` (§14) | Live |
| Vesting / airdrop drain | Underpaid claim, double-claim, locked-balance bypass | Gas-limit guard on claim/sweep, claim-once enforcement, vesting check at validation layer | Live |
| Decryption withhold | Validator refuses to release threshold share | 2 % per-offense slashing + observable in gossip (§3.4) | Live |
| Resharing manipulation | Corrupt committee member contributes a polynomial whose constant term ≠ their share | Detection via decryption failure at next epoch (mitigation); cryptographic upgrade via Pedersen / KZG commitments | Live (detection); cryptographic upgrade post-mainnet (§19) |

The "Live" status indicates the defense is implemented and tested in the current branch. The two entries with post-mainnet upgrades — censorship slashing and resharing VSS — have working mainnet defenses (local-view enforcement, decryption-failure detection) and tracked future upgrades that strengthen the cryptographic guarantees without re-architecting the protocol.

### 15.2 The audit programme

Pyde's pre-mainnet external audit programme runs across five tracks, each engaging a separate specialist firm. The motivation for splitting is that no single firm covers the full surface — the cryptography track requires lattice-cryptography specialists, the consensus track requires distributed-systems specialists, the PVM track requires VM and JIT specialists, the networking track requires libp2p and gossip specialists, the otic track requires compiler specialists. A single firm purporting to cover all five is a quality-of-engagement red flag.

| Track | Scope | Estimated spend |
| --- | --- | --- |
| Consensus | HotStuff variant, VRF, finality, slashing, weak-subjectivity, PSS | $500 K – $1 M |
| PVM and execution | ISA, interpreter, AOT, gas accounting, parallel scheduler, parity tests | $500 K – $1 M |
| Cryptography | FALCON, Kyber, Poseidon2, threshold encryption, VRF, Argon2id keystore | $500 K – $1 M+ |
| Networking | libp2p, gossipsub, peer auth, DDoS resistance, sync protocol | $300 K – $700 K |
| Otic compiler | Lex/parse/typecheck/codegen, security attributes, cross-contract dispatch | $300 K – $700 K |

The audit programme is the single largest pre-mainnet line item, and the dominant gating concern for a credible launch. Penetration testing (P2P flooding, RPC DoS, eclipse attacks) runs in parallel with the static-analysis tracks. All critical and high findings must be remediated and re-audited before genesis (Phase 8 of the launch plan, §18).

### 15.3 Pre-audit hardening

The current codebase has been through an internal audit cycle producing 308 + tracked findings, of which the substantial majority are remediated in the current branch. Highlights include:

- Wire-format hardening: bounds-checked decoders for `EncryptedTx::from_bytes` and related serialization paths (audit 301).
- RPC ingress validation: `chainId` resolved against node, mismatches rejected (audit 302).
- Faucet `chain_id` pinned at boot, fail-loud on RPC error (audit 303).
- Production rejection of `MultiSig + Paymaster + GasTank` combinations on production chain IDs (audits 304 + 305).
- Argon2id KDF for keystore encryption across all wallets / SDK / dev tools (audit 306).

These are pre-audit hardening rather than substitutes for external audit; they are the work that lets the external audit focus on novel attack surfaces rather than catching trivial issues.

### 15.4 Property tests and fuzzing

Pyde ships 31 property tests across the audit-surfaced state-management code (multisig, emergency pause/resume, airdrop claim, vesting), covering wire formats, logic invariants, and decoder panic-freedom. Running with `PROPTEST_CASES = 256` (the default) executed in CI, these have surfaced and fixed issues that traditional unit tests missed. Extended runs (`PROPTEST_CASES = 10,000`+ as periodic CI workloads) are tracked as post-mainnet hardening.

`cargo-fuzz` scaffolding exists for several entry points:

- `pvm_interpreter` — arbitrary bytecode → `Vm::load + Vm::execute` must not panic.
- `tx_decoder` — arbitrary bytes → `Transaction::from_bytes` must return `Option`, not panic.
- `wire_transaction` — arbitrary bytes → `pyde_node::wire::decode_transaction`.
- `wire_block`, `wire_consensus_message` — same shape, different decoders.
- `otic_parser` and the post-quantum crypto deserializers are queued.

Each target needs to run for 72 + hours pre-mainnet to provide the corpus coverage that justifies launch.

### 15.5 Bug bounty

The bug bounty programme ships in two tiers:

- **Testnet tier.** Smaller payouts, broader scope, runs alongside the incentivized testnet (Phase 9 of the launch plan). Encourages the community to find and report issues against a live network at zero risk.
- **Mainnet tier.** Substantially larger payouts (audit-scale numbers for critical findings), narrower scope, runs continuously after launch.

The two-tier structure is borrowed from Ethereum's and Solana's bounty histories, adjusted for Pyde's scope. Both tiers run on a public coordinated-disclosure timeline.

---

## 16. Performance

### 16.1 Methodology

Pyde's published performance numbers are reproducible against a documented harness rather than a synthetic best-case. The methodology:

- **Topology.** A four-validator local devnet via `pyde testnet --validators 4 --dev` running on a single laptop. All four validators share the host's CPU, RAM, disk, and loopback network.
- **Slot rate.** 400 ms slot time, mainnet target.
- **Signatures.** Real FALCON-512 signatures throughout — consensus votes, transaction authorization. No `chain_id = 31337` dev-mode bypass.
- **Workload.** Configurable mix; the published numbers run a 50 % ERC-20 transfer / 25 % AMM swap / 15 % NFT mint / 10 % plain-PYDE-transfer mix from the bench-contracts spec, encrypted-mempool path for 90 % of the load.
- **Inclusion.** A run is reported only if 100 % of submitted transactions commit within 30 seconds of submission. A drop rate above 5 % is a fail; we do not paper over partial inclusions.

This is a deliberately stricter standard than several published L1 throughput numbers, which often report submitted-tx / second without an inclusion gate.

### 16.2 Measured ceiling

| Test | Target | Result |
| --- | --- | --- |
| Sustained × 10 min, plaintext path | 4 K TPS | **PASS** at 100 % inclusion |
| Burst × 30 s, plaintext path | 7 K TPS | **PASS** at 100 % inclusion |
| 4.5 K TPS sustained × 10 min | — | Thermal cliff: 48 % efficiency (laptop CPU throttle) |
| 8 K TPS burst × 30 s | — | 18 % inclusion (under-provisioned) |
| Encrypted-path sustained | TBD | Lifecycle test passes 5/5; loadgen toggle queued |

The 4.5 K thermal cliff is the operative bound. Beyond ~ 4 K, the laptop's four cores running four validator processes plus the load generator hit thermal throttling and drop efficiency. The cliff is a hardware artifact, not a protocol limit; cloud-class hardware (dedicated cores, no thermal throttle) is required to validate the 12.5 K sustained / 50 K peak design targets.

The encrypted-path measurements are in progress. The end-to-end multi-node lifecycle test (`multi_node_encrypted_lifecycle`) passes 5/5 across the four-validator devnet with state-root convergence; the same `loadgen_sustained` harness is being extended with an encrypted-path toggle to characterize the Kyber-encapsulation + threshold-decrypt overhead under sustained load.

### 16.3 The path to 12,500 TPS

The arithmetic that justifies the 12,500 sustained TPS / 50,000 peak design target:

```
GAS_TARGET                    = 400 000 000 gas/block
SLOT_RATE                     = 2.5 blocks/s     (400 ms slot)
GAS_PER_SECOND_AT_TARGET      = 1 G gas/s

Workload mix average gas/tx   = ~52 K gas/tx
THEORETICAL_TPS_AT_TARGET     = 1 G / 52 K ≈ 19 K TPS

Design target (12.5 K / 19 K) = ~ 65 % of theoretical ceiling
```

The design target leaves ~ 35 % headroom above the gas-derived theoretical ceiling — sufficient buffer for consensus overhead, network propagation, and per-block constant costs. The cloud-validated test will measure the actual achievable fraction; the gap between the laptop measurement and the design target is principally a hardware story, not a protocol story.

### 16.4 Latency profile

Per-stage latency for an encrypted transaction, on the laptop devnet:

| Stage | Latency |
| --- | --- |
| `submit → RPC ack` | < 5 ms (FALCON verify + mempool admit) |
| `submit → first observed in proposed block` | 200 – 400 ms (one slot) |
| `submit → soft-finalized (one QC)` | 400 – 600 ms |
| `submit → hard-finalized (committee QC, all phases)` | 600 – 1 000 ms |
| Encrypted-path overhead vs plaintext | + 150 – 300 ms (Kyber + threshold decrypt) |

Hard-finality latency under one second is the headline UX number. A wallet UI that displays "confirmed" on hard finality can do so within a single network round trip from the user's perspective.

### 16.5 Open performance work

The remaining performance items before mainnet:

- Cloud-validated 12.5 K sustained × 10 min (server-class hardware).
- Cloud-validated 50 K peak × 30 s (same).
- Encrypted-path sustained measurement.
- 128-validator scale test (the laptop devnet is bounded to ~ 8 validators by core count; consensus-message fanout, decryption-share gossip, and view-change msg counts scale ≥ linearly with N).
- Long-running stability (> 3-minute soak) under mixed workload.

These items are the throughput-validation gates between testnet alpha and incentivized testnet (Phases 7 → 9 of the launch plan). They are infrastructure-bound (cloud capacity), not protocol-bound.

---

## 17. Comparison to Other L1s

### 17.1 Comparison matrix

The major L1s, scored on the eight axes that matter for Pyde's positioning. *Roadmap* indicates a published direction without a shipped, default-on protocol; *partial* indicates active mitigations that don't structurally remove the issue; *no* indicates no shipped work in the area. Every assessment is current as of mid-2026 and is subject to the standard disclaimer that other chains' roadmaps move quickly.

| Axis | Pyde | Ethereum (L1) | Solana | Aptos | Sui | Polkadot | Cosmos | Avalanche |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Post-quantum signatures (default) | **Yes** (FALCON-512) | Roadmap | Roadmap | Roadmap | Roadmap | Roadmap | Roadmap | Roadmap |
| Encrypted mempool (default) | **Yes** (Kyber-768 threshold) | No (PBS / MEV-Boost is auction, not encryption) | No (Jito is auction) | No | No | No | Threshold-encryption proposals in IBC track | No |
| Sandwich-attack prevention | **Structural** | Partial (PBS) | Partial (Jito) | Partial | Partial | N/A (relay-chain blockspace) | Partial | Partial |
| Sustained throughput | 12.5 K TPS design / 4 K measured | ~ 15 TPS | High (peak); outage history | Lab high; production lower | Lab high; production lower | Variable (per-parachain) | Variable (per-zone) | High (per-subnet) |
| Hard-finality time | < 1 s (committee QC) | ~ 12 min | Probabilistic (32 slots ~ 13 s) | < 1 s | < 1 s | ~ 12 – 60 s | ~ 6 s | ~ 1 s |
| Validator hardware | 8 cores / 16 GB / 500 GB / 100 Mbps | Modest | 12 + cores / 256 + GB | Modest | Modest | Modest (validator tier) | Modest (per zone) | Modest |
| Equal validator voting | **Yes** (1 = 1) | Stake-weighted | Stake-weighted | Stake-weighted | Stake-weighted | Stake-weighted | Stake-weighted | Stake-weighted |
| Permissionless decentralized infrastructure layer (parachains as oracles, bridges, indexers, off-chain compute) | Roadmap (~ + 6-to-12 mo, spec + open implementations, PYDE-staked, unified gas) | L2 ecosystem (per-L2 sequencer); third-party oracle networks (Chainlink) | Third-party (Pyth, Switchboard) | No | No | App-chains via auctioned slots | IBC zone-to-zone (no integrated infra layer) | Subnet model (sovereign chains, not infra layer) |

Each chain in the table is competently engineered by serious teams. The differences are choices, not capability gaps. The matrix exists to make those choices visible, not to imply a ranking.

### 17.2 Ethereum

Ethereum is the dominant smart-contract platform and the chain whose research output most directly shapes the field. Pyde converges with Ethereum on the EIP-1559 fee model, the account-abstraction direction, and the general posture that a proposer should not extract value from users. Pyde diverges on three fronts:

**Post-quantum.** Ethereum's PQ migration is real research (Vitalik's writing on lattice signatures, account-abstraction primitives that pre-position for key migration, beacon-chain BLS being a planned upgrade target) but no PQ signature is the default for any consensus or execution path on mainnet today. The migration is constrained by the size of the deployed surface — every wallet, every signing library, every contract that hard-codes a key format. Pyde absorbs the cost up front; Ethereum amortizes it over a longer horizon. Both are reasonable engineering choices for their respective starting positions.

**MEV.** Ethereum's response is proposer-builder separation: a structured market in which builders compete to sell bundles of transactions to proposers. The mechanism makes the market more efficient and (debatably) shares the surplus more equitably. Pyde's response is to remove the underlying information asymmetry at the protocol level — the proposer cannot see the mempool, so there is no surplus to extract, share, or auction. The two designs answer different questions: PBS asks "how should MEV be priced and distributed?" Pyde asks "is there a protocol that doesn't have this problem?"

**Throughput at L1.** Ethereum's L1 throughput is intentionally modest (~ 15 TPS) because the strategy is to push throughput to L2 rollups. Pyde's strategy is to scale at L1; the parachain layer provides decentralized infrastructure (cross-chain routing, oracles, indexers, off-chain compute) rooted in light-client verification rather than custodial bridges (§10). The L2 ecosystem has succeeded as a scaling story; it has done so at the cost of fragmenting the user surface across L2s with their own sequencers and trust assumptions. Pyde's bet is that a unified L1 with a permissionless parachain layer is a cleaner end state than L1 + N rollups + N bridges.

### 17.3 Solana

Solana is the high-throughput benchmark. Pyde converges with Solana on the monolithic-binary architecture — consensus and execution share one process — and on the parallel-execution-via-access-lists strategy. Pyde diverges on hardware and MEV.

**Hardware.** Solana's documented validator spec has crept upward across releases, settling at a real-world-effective 12 + cores and 256 + GB of RAM. The result is that running a Solana validator is a data-center operation, and a small number of professional operators run a disproportionate share of stake. Pyde's mainnet validator spec is 8 cores, 16 GB RAM, 500 GB NVMe — a developer workstation. The protocol design is calibrated against this budget rather than the hardware being calibrated against the protocol. The cost is throughput headroom (Pyde's 12.5 K design target is below Solana's claimed peak); the benefit is that validation is genuinely accessible to non-professional operators.

**MEV.** Solana's Jito client is a builder market analogous to MEV-Boost on Ethereum — an auction over reorder rights, with revenue shared back to validators. Pyde's encrypted-mempool design removes the underlying surface. The frame is the same as the Ethereum comparison: distribute MEV efficiently versus prevent it from arising.

**Outage history.** Solana has had seven major outages between 2021 and 2024, several attributed to mempool overload, resource exhaustion, or consensus liveness under specific traffic patterns. The chain's stability work has been substantial and the recent track record is improved. Pyde's testnet bringup explicitly stress-tests the same surfaces (mempool overload via `loadgen_sustained`, resource exhaustion via 1 K parallel transfers, consensus liveness under partition-and-heal). The stability-versus-throughput trade is something Pyde takes very seriously precisely because Solana has demonstrated where the failure modes live.

### 17.4 Aptos and Sui

Aptos and Sui are the two leading Move-based chains, with sub-second finality, parallel execution, and modern language ergonomics. They are the closest peers to Pyde in design philosophy if not in cryptographic posture. Pyde converges with both on parallel execution and sub-second finality. Pyde diverges on MEV protection, post-quantum cryptography, and the specifics of parallel scheduling.

**Parallel execution.** Aptos's Block-STM is optimistic concurrency — execute speculatively, detect conflicts, retry. Sui's object-centric model encodes ownership in the transaction structure, so non-owned objects can run in parallel by construction. Pyde's declared-access-list model is closer to Solana's: the transaction commits up front to the storage cells it will touch, and the scheduler builds a conflict DAG from those declarations. Each design has merits — Block-STM hides complexity from the developer, Sui's model rewards careful object design, Pyde's model gives the scheduler the most up-front information at the cost of requiring access-list authoring (which the otic compiler can infer for many cases).

**MEV.** Neither Aptos nor Sui ships an encrypted mempool as the default. Both have research and proposals; neither is the default protocol path today.

**Post-quantum.** Same picture as the Ethereum and Solana comparisons — both chains have PQ research, neither has PQ signatures as the default for consensus or accounts.

### 17.5 Polkadot, Cosmos, Avalanche, and the decentralized-infrastructure layer

Polkadot, Cosmos, and Avalanche are multi-chain ecosystems rather than monolithic L1s. Pyde positions itself as a different shape of system at launch — monolithic L1 with a permissionless parachain layer of decentralized infrastructure providers ( + 6-to- + 12-month roadmap item) — so the comparison is structural rather than feature-by-feature.

**Polkadot's** parachain architecture is the most direct point of name comparison to Pyde's parachain layer, but the scope is different. Polkadot's parachains are sovereign app-chains backed by relay-chain validator capacity, allocated via slot auctions because validator capacity is finite. Pyde's parachains are decentralized infrastructure providers (cross-chain message routers, oracle networks, indexers, off-chain compute) organized by function rather than by application. Operator entry is permissionless and gated by PYDE staking + spec conformance — there is no slot scarcity, no auction, no parachain-team gatekeeping. The two systems share the pluggable-consensus design philosophy that Polkadot's BABE / GRANDPA split established: each parachain operator set chooses its own internal consensus mechanism, and the host chain verifies the resulting attestation regardless of how it was produced.

**Cosmos** zones connect via IBC, which is genuinely excellent cross-chain protocol design. Each Cosmos zone is its own trust island — its validator set, its security, its governance, unrelated to the validator sets of the zones it talks to. Pyde's parachains are structurally different: they are infrastructure providers within Pyde's economic security (operators stake PYDE, are slashable under Pyde rules), not sovereign zones with independent trust models. A parachain can interface with IBC by running an IBC-light-client parachain that bridges Pyde to Cosmos zones, but Pyde's primitive is "contract-to-anywhere via a parachain layer," whereas IBC's primitive is "zone-to-zone."

**Avalanche's** subnet model lets anyone launch a subnet with custom rules — closer in spirit to Polkadot's app-chain model than to Pyde's infrastructure-provider model. Avalanche subnets do not natively share security with the primary Avalanche network; each subnet's validator set is its own. Pyde's parachain operators stake PYDE and are slashable under Pyde rules, unifying the economic security across the chain and the parachain layer.

The most useful **functional** comparison is to the decentralized-infrastructure ecosystem that exists alongside the L1 ecosystem. **Chainlink** is the closest reference: a decentralized oracle network where operators run nodes that aggregate off-chain data and post attested results on-chain. Pyde's parachain architecture extends the same model to all forms of decentralized external interaction (oracles, cross-chain bridges, indexers, off-chain compute) and integrates it natively into the L1's gas model — a Pyde contract calling `cross_call!` to an oracle parachain pays gas the same way it pays for any other operation, with no separate token to hold. **LayerZero, Wormhole, Axelar** typically rely on an oracle-and-relayer trust model where small operator sets coordinate to prove a message; Pyde's parachain operators are publicly known, on-chain-staked, slashable, and bound by a published specification — a structurally different trust model.

None of the multi-chain ecosystems and none of the cross-chain protocols ships an encrypted mempool or post-quantum signatures as the default. Pyde's positioning against this group is on the four-axiom claim collectively rather than on parachain architecture alone.

### 17.6 What Pyde owes the field

Pyde does not invent every wheel. Each of the chains in this comparison contributed innovations that Pyde adopts, adapts, or builds on. The honest version of Pyde's positioning is that the chain stands on a foundation the rest of the industry built — and the strategic claim is not that other chains are wrong, but that the time has come to integrate the field's best ideas into a single greenfield design.

**Bitcoin** invented the field. Digital scarcity, proof-of-work consensus, the principle of an immutable distributed ledger, and the social model of a permissionless monetary base layer all begin with Satoshi's paper. Bitcoin established that a public chain with hard rules and minimal trust assumptions is a thing that can exist; everything in this whitepaper presupposes that demonstration. Pyde inherits the philosophy of public, rule-bound, trust-minimized infrastructure that Bitcoin made the default expectation.

**Ethereum** invented the programmable blockchain and shaped most of the design vocabulary the field still uses. Smart contracts, EVM execution semantics, the EIP process, the EIP-1559 fee market, the Verkle-tree research, the entire MEV literature, the proposer-builder-separation direction, the account-abstraction roadmap, and the L2 ecosystem are all Ethereum-originated work that the field has absorbed. Pyde adopts the EIP-1559 base-fee + elastic-block design (with the priority-tip removal that the encrypted mempool makes possible), the EIP-process structure for off-chain governance, and the spirit of formal protocol-improvement workflow. Vitalik Buterin's published thinking on lattice signatures and post-quantum-friendly account abstraction is part of the intellectual backdrop against which Pyde's PQ-default design is intelligible.

**Solana** proved at scale that a monolithic-binary L1 with parallel execution can deliver retail-scale throughput, and that consensus and execution sharing one process is operationally viable. Pyde's monolithic architecture, its access-list-driven parallel scheduler, and its commitment to sub-second finality are the same family of design choices that Solana legitimized in production. Solana's stability work — the mempool-overload mitigations, the consensus liveness fixes, the gossipsub tuning — is the production reference for what hardening a high-throughput chain looks like, and Pyde's testnet bringup explicitly stresses the same surfaces because Solana's outage history made the failure modes visible.

**Aptos** and the broader Move ecosystem produced the Jellyfish Merkle Tree (JMT) that Pyde adopts as its state structure — the swap from a previous SMT implementation to JMT during testnet bringup was the proximate enabler of the 4 K TPS sustained measurement on the laptop devnet. Aptos's parallel-execution work via Block-STM is one of the field's two leading approaches to the parallelism problem; Pyde's choice favors declared access lists, but the Aptos team's exploration of the optimistic-concurrency design space is what made every other chain's parallelism choice better-informed.

**Sui's** object-centric model is one of the cleanest expressions of "ownership encoded in the transaction structure" the field has produced. Pyde's parallel scheduler operates against declared access lists rather than encoded ownership, but the Sui team's design work helped establish that parallelism is a function of how the transaction format is shaped, not just of how the scheduler is implemented.

**Polkadot** pioneered pluggable consensus (the BABE / GRANDPA split) and the parachain architecture as a first-class concept. Pyde's parachain layer applies the pluggable-consensus philosophy to a different scope — decentralized infrastructure providers, not app-chains — and the architectural precedent for "let each parachain category choose its own internal consensus mechanism, the host chain just verifies the resulting attestation" is Polkadot's contribution. The parachain-architecture-as-a-first-class-protocol-feature framing came from Polkadot before Pyde.

**Cosmos** built the most rigorous cross-chain protocol shipped to date in IBC, and proved that sovereign-zone interconnection can work at scale via light-client verification rather than custodial bridges. Pyde's parachain layer can interface with IBC where the use case calls for it; the IBC team's work on light-client verification is the intellectual ancestor of Pyde's `HardFinalityCert`-based bridge primitive. The principle that cross-chain interaction should be cryptographically verifiable rather than custodially trusted is a Cosmos-originated commitment that Pyde inherits.

**Avalanche** demonstrated that subnet-style horizontal scaling is operationally tractable and that Snowman / Avalanche consensus can deliver sub-second finality at scale. Pyde's design goals on finality and parachain composition share a vocabulary with Avalanche's subnet work; the proof that the multi-chain architecture is viable at production scale was made before Pyde shipped a line of code.

**Cardano** has shipped hash-based signature primitives as building blocks toward post-quantum readiness, and the chain's commitment to formal-methods research (alongside Tezos and others) is part of the field's broader maturation toward verified protocol implementations. Pyde's pre-audit hardening process — property tests, parity tests between interpreter and AOT, fuzz scaffolding — is in the same lineage as the formal-methods culture that Cardano helped normalize.

**Chainlink** built the production reference for decentralized oracle networks — the operator-set staking model, the deviation-tolerance attestation pattern, the off-chain-data-on-chain bridge, the per-feed reputation system. Pyde's parachain layer extends the same model to all forms of decentralized external interaction (cross-chain bridges, oracles, indexers, off-chain compute), but the proof that decentralized infrastructure with permissionless operator entry is a viable production category is Chainlink's contribution. Pyde's parachain spec is the integration of Chainlink-style decentralization into an L1's gas model; the original demonstration is older than Pyde.

**Filecoin** and the broader libp2p / IPFS ecosystem produced the modular networking stack that Pyde uses as transport. The years of work that went into making libp2p production-grade — connection lifecycle, gossipsub mesh maintenance, peer scoring, transport multiplexing, the noise handshake — are what makes Pyde's networking layer credible as a launch component rather than a multi-year engineering project. Pyde's net-layer crate is integration work over a stack the field built.

The list is not exhaustive. Tezos, Near, Algorand, Mina, Aleo, Tendermint, Diem, the Move language design team, the entire ZK-rollup research community, the Flashbots team, the libp2p maintainers, the Rust language and async-runtime ecosystems, the cryptographic standards bodies (NIST, IETF), and many others all shaped how Pyde was designed. The field that built this much in a decade and a half is not a field that has been wrong. It is a field that has been doing the work that lets the next chain be possible.

Where Pyde diverges — post-quantum-from-genesis, encrypted-mempool-by-default, equal voting, commodity hardware, the permissionless parachain layer with unified gas — is where the bet sits. Every chain in the comparison matrix is well-engineered, by serious teams, against the constraints of the moment they were built in. Every one of them has at least one structural property that would require a multi-year coordinated migration to add. **Pyde is the only chain in the table that needs no migration to ship all four.**

The pitch is not that Pyde is better than Ethereum. Ethereum was built for the era it was built for; the chain has earned the position it holds, and the engineering that took it there is among the field's finest work. The same is true of Solana, Aptos, Sui, Polkadot, Cosmos, Avalanche, Cardano, Chainlink, and every other chain in this comparison. The pitch is that the next default Layer 1 — the chain that the next decade of crypto runs on — needs all four of these properties at the protocol layer; that the only honest path to a chain with all four is greenfield; that the strategic window for a greenfield chain to ship the answer first is open and closing; and that Pyde is the chain built to ship it, on a foundation the rest of the industry built.

---

## 18. Launch Roadmap

### 18.1 Status as of this paper

Pyde's mainnet readiness work runs against a 143-task plan derived from a 2026-04 internal audit. Of the 143 tasks, 86 are complete, 6 are partial, and 51 are open. The breakdown by phase:

| Phase | Done | Partial | Open | Total | Status |
| --- | --- | --- | --- | --- | --- |
| 1 — Critical safety fixes | 20 | 0 | 1 | 21 | Substantially complete |
| 2 — Documentation reconciliation | 0 | 0 | 9 | 9 | Deferred (documentation rewrite at end of mainnet work) |
| 3 — MEV end-to-end integration | 11 | 0 | 0 | 11 | Complete |
| 4 — Governance + tokenomics | 18 | 0 | 0 | 18 | Complete |
| 5 — Hardening + CI | 9 | 4 | 2 | 15 | Substantially complete |
| 6 — Devnet + multi-node tests | 13 | 0 | 0 | 13 | Complete |
| 7a — Mempool bug batch | 7 | 0 | 1 | 8 | Substantially complete |
| 7b — Mempool production hardening | 6 | 0 | 0 | 6 | Complete |
| 7 — Testnet alpha | 2 | 2 | 11 | 15 | In progress (cloud-bound stress tests) |
| 8 — External audits | 0 | 0 | 9 | 9 | Pre-funded; engaged firms TBD |
| 9 — Incentivized testnet | 0 | 0 | 8 | 8 | Sequenced after Phase 8 |
| 10 — Mainnet genesis | 0 | 0 | 10 | 10 | Sequenced after Phase 9 |
| **Total** | **86** | **6** | **51** | **143** | — |

The critical path runs through Phase 7 → Phase 8 → Phase 9 → Phase 10. Phases 2 (documentation) and the later subset of Phase 5 (extended fuzz runs) can land in parallel with the critical path; they do not gate launch.

### 18.2 The path to mainnet

The remaining work, in execution order:

1. **Cloud-validated throughput.** Move the laptop-bound 4 K TPS sustained / 7 K burst measurements to server-class hardware. Validate the 12.5 K sustained / 50 K peak design targets. Characterize the encrypted-path loadgen overhead. (~ 4 – 8 weeks once cloud capacity is in place.)
2. **External audit programme.** Engage five specialist firms across consensus, PVM, cryptography, networking, and otic compiler. Remediate all critical and high findings; re-audit remediation. (~ 16 – 24 weeks.)
3. **Incentivized testnet.** Deploy reference dApps (DEX, lending, NFT marketplace), fund the bug bounty at mainnet-tier scale, run for 3 + months, document community-found issues. Critical and high severity must be fixed before launch. (~ 12 – 16 weeks of soak; required by the launch-strategy criterion.)
4. **128-validator genesis.** Recruit and validate genesis operators with documented hardware benchmarks and Phase 9 participation proof. Geo-distribute across 3 + regions. Coordinate validator DKG for the threshold pubkey. Sign the genesis block. Publish the chain hash. (~ 4 – 8 weeks of coordinated execution.)

Adding integration buffer, the execution distance from this paper to mainnet is approximately 9 – 12 months of focused work, gated principally on (1) cloud capacity for stress validation and (2) audit-firm calendar and capacity.

### 18.3 Funding sequence

Pyde's roadmap is structured around a testnet-MVP → fundraise → audit → mainnet sequence rather than a fundraise-first model. The reasoning is straightforward: the technical surface this paper describes is more credible to investors when most of it is shipped. The current branch's 86-of-143 task completion, 4 K TPS measurement, and end-to-end MEV pipeline tests are the substance the fundraise rests on; the capital deployment then funds the audit programme, the cloud-validated stress runs, and the incentivized-testnet operations.

This whitepaper is the technical credibility document for that sequence. It is not a prospectus; specific token-allocation figures and capital-raise structure are out of scope here and live in separate fundraise material.

### 18.4 Current testnet limitations

The shipping testnet is the substrate for this whitepaper's claims, but it is not yet mainnet. Section 19 catalogues capabilities that are explicitly post-mainnet by design; this section is the honest counterpart for capabilities that ship at mainnet but operate in a reduced or unvalidated form on the current testnet. Operators running validators against the testnet, dApp authors targeting it, and auditors evaluating the surface should treat the items below as known gaps to be closed on the path-to-mainnet (§18.2), not as design choices.

| Area | Testnet today | Mainnet target | Reference |
| --- | --- | --- | --- |
| Throughput validation | 4 K TPS sustained / 7 K burst on a four-validator laptop devnet (thermal-bound at ~ 4.5 K) | 12.5 K sustained / 50 K peak on cloud-class hardware × 10 min soak | §16.2, §18.2 |
| Encrypted-path throughput | Lifecycle test passes 5/5; sustained measurement TBD | Characterized under sustained load with the same 10-minute soak structure as the plaintext path | §5.1, §16.2 |
| Threshold-key generation | Centralized `threshold_keygen` (caller sees all shares) — fine for devnet/testnet under a trusted operator | Multi-party DKG ceremony followed by PSS epoch refresh that dissolves the genesis trust after epoch 1 | §4.5, §3.6 |
| Validator key custody | Argon2id-encrypted on-disk keystore | HSM-backed signing as the recommended operator path; keystore remains the fallback | §4.7 |
| Fuzzing and proptest soak | Default `PROPTEST_CASES = 256` in CI; fuzz targets exist but no 72 + hour corpus runs yet | `PROPTEST_CASES = 10,000` periodic CI + 72 + hour `cargo-fuzz` runs with corpus accumulation pre-mainnet | §15.4, §19.11 |
| Otigen signed integers | Reserved keywords (`i8`–`i256`) parsed but rejected at typecheck (audit 354) | Signed types ship in a post-mainnet point release once the PVM ISA additions for signed arithmetic pass audit | §7.3 |
| Mempool censorship slashing | Local-view enforcement only — committee members reject blocks omitting txs they have seen (safety holds; liveness is the only failure mode) | Signed mempool commitments + cryptographic slashing of proposers excluding txs in ≥ f + 1 commitments (audit 026, §19.4) | §5.3, §19.4 |
| Networking stack | libp2p 0.54 with 7 RUSTSEC advisories ignored | libp2p 0.56 + (clears the ignores) before mainnet; verified against the same multi-node lifecycle suite | §9.1 |
| Reorg / Byzantine harness | Single-tier reorg + double-sign + 2-of-7-offline tests pass | Two-tier reorg-Byzantine harness covering simultaneous-SIGKILL recovery for ≥ 4 of 4 validators (CHURN_RESIDUAL.md) | §15.4 |
| Mainnet chain id | Provisional `MAINNET_CHAIN_ID = 1` — collides with Ethereum mainnet under chainlist.org / EIP-155, surfacing as wallet, explorer, and bridge-router ambiguity (signature preimages don't collide cross-protocol because Pyde signs FALCON-512, not secp256k1-over-RLP) | Final id picked at the genesis ceremony, registered with chainlist.org so the value is unambiguous across every wallet and bridge | `crates/net/src/discovery.rs::MAINNET_CHAIN_ID` |

The list is the testnet-specific complement to §19. Items in this table are tracked as launch-gating; items in §19 are explicitly post-mainnet. An auditor reviewing the system should expect every row here to be either closed or downgraded in severity by the mainnet genesis ceremony described in §18.2 step 4.

---

## 19. Post-Mainnet Appendix

This section catalogues capabilities that are tracked on Pyde's roadmap but explicitly do not ship at mainnet. Each entry describes the capability, the reason for deferral, and the cost or work estimate. The list is the honest counterpart to the comparison matrix in §17 — these are the items where Pyde's mainnet does not match an incumbent's published feature set, and the deferral is intentional rather than oversight.

### 19.1 ZK execution proofs and the verifiable computation network

Pyde's longest-horizon roadmap item is the introduction of zero-knowledge execution proofs across the chain and the parachain layer. This is not a footnote; it is the direction that turns Pyde from a fast post-quantum L1 into a verifiable computation network at scale. The story splits into three phases.

**Phase 1 (mainnet, shipping).** Validators execute every block they vote on. Hard finality is a FALCON quorum certificate signed by 86 of 128 committee members. Light-client verification of any chain event costs 86 FALCON verifications (~ 86 ms on commodity hardware) plus a Merkle-path verification. This is the model described throughout this paper. The original Pyde architecture proposal included STARK proofs from genesis; mainnet ships committee-only finality instead, because the engineering investment for production-grade circuits, audited prover-network economics, and coordinated launch is large enough to dominate the mainnet timeline on its own. The ZK work is sequenced after mainnet stability.

**Phase 2 (post-mainnet, ~ + 18-30 months): STARK execution proofs as a parallel finality path.** A separate prover network — operators who are not committee members but who stake PYDE under a parachain-style spec — produces STARK proofs of block execution. A block accompanied by a valid STARK proof reaches an additional finality flag in addition to the FALCON QC. Light clients and cross-chain bridges can then verify the proof for ~ 1-5 ms per block instead of ~ 86 ms — a roughly 50-100 × reduction in cross-chain verification cost.

The Phase 2 design is deliberately additive. The existing FALCON-based finality remains valid; STARKs are a parallel option, not a replacement. A wallet, a contract on another chain, or a parachain-side bridge verifier can choose which finality path to consume based on its constraints — a chain with cheap pairing operations might prefer FALCON-on-chain verification; a gas-constrained chain might prefer STARK-on-chain verification. Pyde provides both surfaces; the consumer picks.

The work in Phase 2 splits into three engagements: circuit design and implementation for Pyde's PVM and consensus path (the largest piece, requiring a cryptographic specialist firm), prover-network economic and governance design (parallel to circuit work, requires its own audit), and the on-chain verifier for the produced proofs (a smaller engagement that lives in Pyde's execution layer). Combined audit budget is comparable in scale to the mainnet five-track audit programme.

**Phase 3 (post-mainnet, ~ + 24-36 months): ZK proofs as a parachain attestation mode.** This is the interesting integration, and the place where Pyde's ZK direction diverges from the typical "L1 with execution proofs" story. Parachains in Pyde's architecture (§10) currently attest results via internal consensus among operators — M-of-N FALCON signatures or a small BFT QC, depending on the category. ZK proofs become an alternative attestation mode: a parachain category can register a ZK circuit that proves correct execution of its operations, and Pyde's parachain layer accepts ZK-proof attestations alongside consensus-signed attestations. The implications are substantial.

*Lighter parachain operators.* A parachain operator who can verify a ZK proof can validate operations without re-executing them. For off-chain-compute parachains (the canonical example: ZK-proof generation as a service for Pyde contracts), this becomes a recursive structure where the parachain produces proofs of its own work and other operators verify those proofs at a tiny fraction of the cost of re-execution. Parachain validators stop being executors and start being verifiers; the parachain layer scales horizontally on proof-verification cost rather than on re-execution cost.

*Smaller operator sets become acceptable.* The current parachain trust model relies on M-of-N operator honesty plus on-chain slashing for misbehavior. Once a ZK proof verifies, the trust model collapses to "the proof is mathematically valid" — operator-set size becomes a liveness concern, not a safety concern. A category that ships a ZK circuit can run with a single well-funded operator producing valid proofs, with the proof itself supplying the trust anchor that an M-of-N committee previously supplied.

*Trustless bridges to gas-constrained chains.* A bridge parachain that produces ZK proofs of Pyde state can be verified on chains whose execution budget cannot afford 86 FALCON verifications — most EVM chains today, Bitcoin's restricted scripting, other PoS L1s with limited per-tx gas. This is the long-term path to truly trustless interop with the entire crypto ecosystem, as opposed to interop gated on the counterparty chain having a generous-enough VM for native FALCON.

*Composable verifiable compute.* A Pyde contract that needs verifiable off-chain computation — private financial logic, ML model inference, complex simulations, custom proof-of-honesty assertions — can request it from an off-chain-compute parachain via `cross_call!`. The parachain runs the computation, produces a ZK proof of correct execution, and posts the result + proof back via the standard callback path. The contract verifies the proof on-chain and acts on the result. Pyde becomes a composability surface for verifiable computation, not just for state.

**The unified vision.** Across the three phases, the architecture converges on a single principle: every operation on or adjacent to Pyde — every block, every cross-chain message, every oracle attestation, every off-chain compute result — can be cryptographically proved when the cost-benefit ratio justifies it. Mainnet ships the FALCON-anchored substrate that makes this evolution possible without protocol-breaking changes. Phase 2 adds STARK execution proofs as a parallel verification mode for the chain itself. Phase 3 extends the same proof-based verification mode to the parachain layer, unifying the trust model across the entire Pyde + parachain ecosystem under one cryptographic primitive: the proof.

The end state is a chain whose verification cost scales with the computational complexity of producing proofs, not with the number of operators replicating execution. That is a different shape of system from any L1 in production today, and it is the shape Pyde is building toward.

### 19.2 Parachain specification and reference implementations

Detailed in §10. The Pyde core team publishes a parachain specification on a ~ + 6-month post-mainnet horizon, defining the interface, attestation format, callback protocol, gas-metering rules, and PYDE staking rules that any parachain implementation must follow. Reference implementations in Rust, Go, and C++ ship alongside the spec, starting with an Ethereum-bridge parachain as the first reference (which audits the FALCON-in-EVM verifier as part of the same engagement). Anyone can implement the spec in any language; the reference implementations are starting points, not requirements. Subsequent reference parachains target oracle networks, indexers, off-chain compute, and additional bridge directions (Solana, Bitcoin, other PoS L1s) on a ~ + 12-to- + 18-month horizon, gated on independent audits of the relevant cryptographic-verifier code. The architecture and the contract-side `cross_call!` macro are settled at mainnet; the spec and the implementations follow.

### 19.3 Native bridges

Per-chain bridges to Ethereum, Bitcoin, and other PoS L1s. The Ethereum bridge (FALCON-in-EVM verifier + permissionless relay) is the most concrete near-term target on a + 6-month post-mainnet horizon. The Bitcoin bridge (SPV-style proofs) is harder because Bitcoin's PoW finality is probabilistic; a Pyde-side Bitcoin light client requires choices about how many confirmations equal "final."

### 19.4 Signed mempool commitments and cryptographic censorship slashing

Mainnet ships censorship defense via local-view enforcement (a committee member rejects a block whose ordering omits a tx the member has seen). Post-mainnet adds signed mempool commitments — each validator periodically signs a hash-set of encrypted_txs they have seen, gossiped to the committee — plus committee-aggregated views and slashing evidence for proposers who exclude txs present in ≥ f + 1 signed commitments.

The deferral is scope: mainnet ships safe under HotStuff (false positives cost liveness, not safety). The cryptographic upgrade is a 2 – 3 slice project that does not need to block launch on a 128-validator network.

### 19.5 Pedersen / KZG commitments on PSS resharing

Adds verifiable secret sharing to the committee resharing protocol (§3.6 / §4.6). Defends against a corrupt committee member contributing a polynomial whose constant term ≠ their actual share (currently mitigated by detection — a corrupt resharing causes ciphertexts to stop decrypting at the new epoch, observable within one slot). The cryptographic upgrade is long-horizon hardening, sequenced into the same wave as ZK execution proofs (§19.1 Phase 2).

### 19.6 Programmable accounts

Extends `AuthKeys` with a `Programmable` mode that marks an account as carrying an attached policy contract — the policy bytecode lives at the account's `code_hash` field, the policy state at `storage_root`, reusing the same fields a regular contract uses (the unification is detailed in §11.2 and §11.6). The policy runs on every transaction the account would authorize and returns Allow or Deny. Patterns expressible via policy: per-window spend limits, time locks, allow-listed recipient sets, tiered authorization (small txs need fewer signatures than large ones), inactivity-triggered recovery flows, tagged session caps. Account abstraction as a protocol-native mode rather than a contract layer every project re-implements. Section 11.6 specifies the design. Simple `Single`-keyed EOAs are unaffected; programmable accounts pay one extra PVM call per transaction.

### 19.7 Session keys

Native protocol support for delegated authorization. Lets dApps execute transactions on a user's behalf within a registered scope (specific contracts, specific methods, capped per-tx spend, capped cumulative spend, slot-bounded duration) without prompting the master wallet for each transaction. The use case is dApps where wallet-popup-per-action is the adoption block: gaming with high-frequency interactions, AI agents executing strategies on a schedule, consumer apps. Section 11.7 specifies the design. Master account can revoke any session instantly via a `RevokeSession` transaction; every session-key transaction emits an observable event keyed to the master.

### 19.8 Expanded TypeScript SDK coverage

The TypeScript SDK (`pyde-ts-sdk`) ships at mainnet at ethers-equivalent maturity: provider with batch calls / fee data / gas estimation, wallet with FALCON-512 keypair handling and Poseidon2 address derivation and AES-256-GCM keystore (Argon2id-shared with the Rust SDK and dev tools), contract with ABI-aware calldata encoding / auto-decoding / event queries, WASM-compiled crypto via `pyde-crypto-wasm`, ergonomic utilities (address validation, unit formatting, hex handling). Post-mainnet expands coverage: full parity with the Rust SDK's `EncryptedTx` builder, advanced WebSocket subscription patterns, dedicated bindings for `cross_call!`-style parachain interactions once the parachain spec and reference implementations ship, and first-class TypeScript bindings for the programmable-account and session-key APIs once those ship.

### 19.9 On-chain stake-weighted voting

Explicitly evaluated and rejected for mainnet. The reasoning is in §14.2 — on-chain stake-weighted voting on consensus changes makes protocol evolution a function of token concentration. Pyde's chosen model is off-chain PIPs plus voluntary validator upgrade. Future PIPs may reopen this design space; the current mainnet shipment makes the choice without removing the option to revisit.

### 19.10 Mempool-level pause filter

A cleaner emergency-pause path that propagates the pause signal back to mempool admission rather than gating only at execution time. Currently every non-Resume tx during a pause pays decode + gate-check CPU at the validator; the cleaner path drops them at mempool ingress. Not a DoS (gate-check is cheap) and not a correctness issue (gate rejects before state writes), but post-mainnet polish.

### 19.11 Extended proptest CI and 72-hour fuzz runs

Default proptest is 256 cases; periodic CI runs at `PROPTEST_CASES = 10,000` find more bugs. `cargo-fuzz` targets need 72 + hour soak runs with corpus accumulation pre-mainnet. Both are post-launch hardening that strengthens confidence over time without changing the protocol.

### 19.12 Off-chain Merkle builder CLI for airdrops

The on-chain `build_tree()` for airdrop Merkle proofs is public; an operator-facing CLI tool that takes a CSV of `(address, amount)` pairs and emits the root + per-address proofs is post-mainnet tooling (~ 150 LOC, no consensus impact).

### 19.13 Two-dimensional gas model

The original tokenomics chapter sketched a `(exec_cost, prove_cost)` two-dimensional gas model intended to price ZK proving separately from execution. Without the prover network, this collapses to single-dimensional gas at mainnet. If ZK proofs ship post-mainnet, the second dimension can be reintroduced to price prover-network resource consumption.

---

## 20. Constants Reference

A consolidated reference for every protocol constant referenced in this paper. The authoritative source is the corresponding crate in the Pyde codebase; values in this table are current as of this paper's version stamp.

### 20.1 Consensus

| Constant | Value | Notes |
| --- | --- | --- |
| `BLOCK_TIME_MS` | 400 | Slot duration |
| `COMMITTEE_SIZE` | 128 | Active validators per epoch |
| `QUORUM_THRESHOLD` | 86 | 2f + 1 with f = 42 |
| `RANDOMNESS_THRESHOLD` | 85 | Min sigs to seed next epoch's randomness |
| `EPOCH_LENGTH` | 1 000 slots | ≈ 6.6 minutes per epoch |
| `PROPOSAL_TIMEOUT_MS` | 200 | Primary-proposer timeout before fallback fires |
| `PROGRESS_TIMEOUT_MS` | 2 000 | Max delay before view change |
| `RESHARE_AGGREGATION_DELAY_SLOTS` | 5 | PSS deterministic-aggregation window |
| `UNBONDING_PERIOD` | 3 024 000 slots | ≈ 14 days |
| Weak-subjectivity checkpoint interval | 64 epochs | ≈ 7 hours |

### 20.2 Slashing

| Constant | Value | Notes |
| --- | --- | --- |
| `VALIDATOR_STAKE` | 10 000 PYDE | Bond per validator |
| `FINDER_FEE_PERCENT` | 10 % | On slashed stake to evidence submitter |
| `EVIDENCE_VERSION` | 1 | Wire format version |
| Double-sign slash | 100 % | Of stake; immediate ejection |
| Invalid-proposal slash | 50 % | Of stake |
| Liveness-major slash | 5 % | Absent > 50 % of an epoch |
| Liveness-minor slash | 1 % | Absent > 10 % of an epoch |
| Decryption-withhold slash | 2 % | Per offense |

### 20.3 Gas and fee

| Constant | Value | Notes |
| --- | --- | --- |
| `GAS_TARGET` | 400 M | Equilibrium block gas |
| `GAS_CEILING` | 1.6 B | Elastic ceiling (4 × target) |
| `GENESIS_BASE_FEE` | 50 × 10⁹ quanta/gas | 50 gwei equivalent |
| `ADJUSTMENT_DIVISOR` | 8 | Max ± 12.5 % base-fee change per block |
| `FEE_BURN_PCT` | 70 | Fee distribution |
| `FEE_VALIDATOR_PCT` | 20 | Fee distribution |
| `FEE_TREASURY_PCT` | 10 | Fee distribution |

### 20.4 Tokenomics

| Constant | Value | Notes |
| --- | --- | --- |
| `GENESIS_SUPPLY` | 1 B PYDE (10¹⁸ quanta) | Initial supply |
| `DECIMALS` | 9 | 1 PYDE = 10⁹ quanta |
| Inflation Y1 | 5.00 % | Per-epoch issuance rate |
| Inflation Y2 | 3.00 % | |
| Inflation Y3 | 2.00 % | |
| Inflation Y4+ | 1.00 % | Terminal rate |

### 20.5 PVM

| Constant | Value | Notes |
| --- | --- | --- |
| `MAX_CODE_SIZE` | 60 KB | Per-contract bytecode |
| `MAX_CALLDATA` | 64 KB | Per-call calldata |
| `MAX_TX_SIZE` | 128 KB | Full encoded transaction |
| `MAX_EXT_CALL_DEPTH` | 64 | Cross-contract recursion |
| `MAX_WITNESS_SIZE` | 1 MB | Per-block state witness |
| `PAGE_ALLOC_GAS` | 200 | One-time per touched 4 KB page |
| GP register count | 16 | Each 64-bit, r0 hardwired zero |
| Wide register count | 8 | Each 256-bit |
| Total address space | 4 MB | Null-page guarded, code/heap/stack regions |
| Opcode count | 62 | Of 64 possible (6-bit field) |

### 20.6 Mempool

| Constant | Value | Notes |
| --- | --- | --- |
| `MEMPOOL_SENDER_CAP` | 128 | Per-sender max pending |
| `MEMPOOL_GLOBAL_CAP` | 100 000 | Global max pending |
| `MEMPOOL_TX_TTL` | 240 s (~ 600 slots) | Eviction threshold |
| Per-sender rate limit | 10 tx/s | Submit-rate cap |
| Per-sender concurrent | 100 | In-flight cap |

### 20.7 Cryptography

| Constant | Value | Notes |
| --- | --- | --- |
| FALCON-512 public key | 897 B | NIST FIPS 206 |
| FALCON-512 signature | 600 – 900 B (1 280 B max) | Variable length |
| FALCON-512 verify time | ~ 1 ms | Commodity hardware |
| Kyber-768 public key | 1 184 B | NIST FIPS 203 (ML-KEM) |
| Kyber-768 ciphertext | 1 088 B | Per encapsulation |
| Kyber-768 shared secret | 32 B | Output of `encapsulate` |
| Poseidon2 state width | 8 | Goldilocks field |
| Poseidon2 internal rounds | 22 | Per Pyde parameter set |
| Goldilocks field prime | 2⁶⁴ - 2³² + 1 | |
| Argon2id memory | 64 MiB | Keystore KDF |
| Argon2id iterations | 3 | t parameter |
| Argon2id lanes | 1 | p parameter |
| Argon2id derivation cost | ~ 250 ms | Per guess on single core |

### 20.8 Hardware spec

| Constant | Value | Notes |
| --- | --- | --- |
| Validator CPU | 8 + cores | x86_64 or ARM64 |
| Validator RAM | 16 GB | |
| Validator disk | 500 GB NVMe SSD | |
| Validator network | 100 Mbps symmetric | Low jitter |
| Full node | Same minus per-vote fsync | |

---

## 21. Glossary

**AOT (Ahead-of-Time compiler).** Pyde's Cranelift-based JIT that compiles PVM bytecode to native machine code at contract deploy time. Ensures interpreter / native parity via property-based parity tests.

**BFT (Byzantine Fault Tolerance).** A consensus protocol property where the chain remains safe and live as long as fewer than f = ⌊(n - 1) / 3⌋ validators are Byzantine. Pyde's BFT bound is f ≤ 42 across 128 validators; the safety quorum is 86.

**Committee.** The 128 active validators in a given epoch, eligible to propose blocks, sign votes, and participate in threshold decryption. Rotates at every epoch boundary.

**Commodity hardware.** Pyde's validator hardware spec (8 cores, 16 GB RAM, 500 GB NVMe SSD, 100 Mbps network) — a developer workstation, not a data-center server. Deliberately accessible to non-professional operators.

**Cross-chain.** Pyde's term for interactions between Pyde and other chains (the parachain layer, native bridges, light-client deployments). Mainnet ships the `HardFinalityCert` primitive; parachain specification, reference implementations, and native bridges ship post-mainnet.

**`cross_call!` (macro).** The Otigen macro that initiates an asynchronous interaction with the parachain layer — cross-chain calls (Pyde → Solana / Ethereum / Bitcoin / etc.), oracle queries, off-chain compute requests. Combined gas (Pyde-side + parachain-side) is computed at call time and billed in one transaction; the result arrives via a callback function on the originating contract. At mainnet the macro lowers to "not yet supported" pending the parachain layer (§10).

**Encrypted mempool.** Pyde's MEV protection mechanism: transactions enter the mempool encrypted under a 86-of-128 threshold Kyber-768 public key. The proposer cannot read pending transactions before committing to an ordering.

**Epoch.** A 1 000-slot (~ 6.6-minute) period during which the committee is fixed. Committee rotation, randomness seeding, and PSS resharing all happen at epoch boundaries.

**FALCON-512.** Lattice-based signature scheme standardized as NIST FIPS 206. Pyde's signature primitive for consensus votes, transaction authorization, and validator key registration.

**Finality, hard.** A block is hard-finalized when 86 of 128 committee members have signed a FALCON commit vote, aggregated into a `HardFinalityCert`. Irreversible under the BFT assumption.

**Finality, soft.** A block is soft-finalized when included in a chain backed by at least one quorum certificate. Lands within the same slot as proposal under normal conditions.

**Gossipsub.** The libp2p topic-based publish-subscribe protocol Pyde uses for block, consensus, and transaction propagation across five distinct channels.

**`HardFinalityCert`.** The cross-chain-portable proof of finality on Pyde — a signed certificate carrying slot, block hash, state root, voter bitmap, and 86 + FALCON signatures from the active committee. The mainnet primitive that future bridges, parachains, and external verifiers consume to prove "block N was hard-finalized on Pyde at state root R" (§3.3, §10.2).

**HotStuff.** The pipelined BFT consensus protocol family Pyde modifies. Provides O(n) message complexity per slot and clean view-change.

**JMT (Jellyfish Merkle Tree).** A sparse Merkle variant optimized for incremental updates. Pyde's authenticated state structure, hashed with Poseidon2.

**Kyber-768 / ML-KEM.** Lattice-based key encapsulation mechanism standardized as NIST FIPS 203. Pyde's threshold-encryption primitive.

**MEV (Miner / Maximal Extractable Value).** The profit a block proposer can extract by reordering, censoring, or front-running unconfirmed transactions. Removed at the protocol level by Pyde's encrypted mempool.

**Otigen.** Pyde's purpose-built smart-contract language. Compiles to PVM bytecode plus an ABI JSON via the otic compiler.

**Parachain.** An open-source implementation of the Pyde-published parachain specification, run by a permissionless operator set that stakes PYDE. Categories include cross-chain message routers (Pyde ↔ other chains), oracle networks, indexers, and off-chain compute. Pyde contracts compose with parachains via the `cross_call!` macro; combined gas (Pyde-side + parachain-side) is billed in one transaction. Each category chooses its own internal consensus mechanism. No slot auctions, no parachain-team gatekeeping. Ships post-mainnet on a + 6-to-+ 12-month horizon. Detailed in §10.

**Programmable account (post-mainnet).** An account whose `AuthKeys` is `Programmable`, marking it as carrying an attached PVM bytecode policy at the same `code_hash` field a regular contract uses. The policy runs on every transaction the account would authorize and returns Allow or Deny — expressing patterns like spend limits, time locks, allow-listed recipients, tiered authorization, and recovery flows. Account abstraction as a protocol-native mode rather than a contract layer every project re-implements. Opt-in: simple EOAs are unaffected (§11.6, §19.6).

**PIP (Pyde Improvement Proposal).** The off-chain governance process for protocol changes. Categories are Standards Track, Meta, and Informational. Activation is voluntary validator upgrade after a 6.5 M slot (~ 30 day) window.

**Poseidon2.** Algebraic hash function over the Goldilocks field. Pyde's hash primitive for blocks, transactions, addresses, JMT nodes, VRF input, and threshold-MAC binding.

**PSS (Proactive Secret Sharing).** The protocol that rotates the threshold-encryption secret across committee changes at epoch boundaries. Uses deterministic aggregation to prevent async-arrival convergence failure.

**PVM (Pyde Virtual Machine).** Pyde's register-based VM. 32-bit fixed-width ISA, 16 general-purpose 64-bit registers, 8 wide 256-bit registers, 4 MB address space, 62 opcodes.

**PYDE.** The native token of the Pyde chain. 1 B genesis supply, 9 decimals, used for staking, fee payment, and treasury operations.

**Quorum.** A subset of the committee whose collective signature satisfies a protocol threshold. Pyde's safety quorum is 86 of 128.

**Session key (post-mainnet).** A delegated authorization that lets an application sign a bounded set of transactions on behalf of an account without prompting the master wallet for each one. The master issues an `AuthorizedSession` once specifying scope (allowed contracts, allowed methods, per-tx and cumulative spend caps, slot deadline); subsequent transactions can be signed by the session key. Use cases: gaming, AI agents, consumer apps where wallet-popup-per-action is the adoption block. Master can revoke any session instantly (§11.7, §19.7).

**Slashing.** The on-chain penalty applied to validators who violate consensus rules. Penalties range from 1 % (liveness-minor) to 100 % (double-sign) of the validator's stake; a 10 % finder's fee goes to the evidence submitter.

**Slot.** A 400 ms time interval during which the protocol expects exactly one new block. Slot index is monotonically increasing.

**Threshold encryption.** A cryptographic scheme where a secret key is distributed across N parties such that any K can decrypt cooperatively but fewer than K cannot. Pyde's mempool uses 86-of-128 over Kyber-768.

**Verifiable computation network (post-mainnet).** Pyde's long-horizon ZK direction: across three phases, the chain plus its parachain layer evolves into a system where every operation — every block, every cross-chain message, every oracle attestation, every off-chain compute result — can be cryptographically proved when the cost-benefit ratio justifies it. Phase 2 adds STARK execution proofs as a parallel finality path; Phase 3 adds ZK proofs as a parachain attestation mode (§19.1).

**VRF (Verifiable Random Function).** A function that produces a pseudorandom output and a proof that the output is correctly computed under a given key. Pyde's VRF derives the output via Poseidon2 from a secret-key fingerprint and binds it to a FALCON-512 signature proof, used for proposer selection and epoch randomness seeding.

**Weak subjectivity.** A property of long-lived proof-of-stake chains that requires a new node to start syncing from a recent trusted checkpoint rather than from genesis. Pyde publishes weak-subjectivity checkpoints every 64 epochs.
