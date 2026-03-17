//! Sponsored transactions via gas tanks and paymasters.
//!
//! Gas tanks are a native protocol feature: contracts pre-fund gas for users.
//! The gas_tank field on Account is a separate balance from the main balance.
//! Paymasters are contracts that implement custom sponsorship logic.

use pyde_account::address::Address;
use pyde_account::types::Account;

/// Per-transaction gas sponsorship limit (optional cap).
pub const DEFAULT_PER_TX_LIMIT: u128 = u128::MAX; // unlimited by default

/// Gas tank configuration for a contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GasTankConfig {
    /// Contract address that owns this gas tank.
    pub owner: Address,
    /// Whitelist of sender addresses allowed to use this tank.
    /// Empty = anyone can use it.
    pub whitelist: Vec<Address>,
    /// Maximum gas cost per transaction (in quanta).
    pub per_tx_limit: u128,
    /// Whether the tank is active.
    pub active: bool,
}

impl GasTankConfig {
    /// Create a new open gas tank (anyone can use, no per-tx limit).
    pub fn open(owner: Address) -> Self {
        Self {
            owner,
            whitelist: Vec::new(),
            per_tx_limit: DEFAULT_PER_TX_LIMIT,
            active: true,
        }
    }

    /// Create a whitelisted gas tank.
    pub fn whitelisted(owner: Address, whitelist: Vec<Address>, per_tx_limit: u128) -> Self {
        Self {
            owner,
            whitelist,
            per_tx_limit,
            active: true,
        }
    }

    /// Check if a sender is allowed to use this tank.
    pub fn is_allowed(&self, sender: &Address) -> bool {
        if !self.active {
            return false;
        }
        if self.whitelist.is_empty() {
            return true; // open to all
        }
        self.whitelist.contains(sender)
    }
}

/// Deposit into a contract's gas tank. Anyone can fund any tank.
pub fn deposit(account: &mut Account, amount: u128) {
    account.gas_tank += amount;
}

/// Withdraw from a contract's gas tank. Returns error if insufficient or unauthorized.
pub fn withdraw(
    account: &mut Account,
    amount: u128,
    caller: &Address,
) -> Result<(), String> {
    // Only the account itself can withdraw (owner = self_address)
    if *caller != account.address {
        return Err("only the contract owner can withdraw from gas tank".into());
    }
    if account.gas_tank < amount {
        return Err(format!(
            "insufficient gas tank: need {amount}, have {}",
            account.gas_tank
        ));
    }
    account.gas_tank -= amount;
    Ok(())
}

/// Check if a gas tank can sponsor a transaction.
/// Returns the amount to deduct, or error.
pub fn check_sponsorship(
    account: &Account,
    config: &GasTankConfig,
    sender: &Address,
    gas_cost: u128,
) -> Result<u128, String> {
    if !config.active {
        return Err("gas tank is inactive".into());
    }

    if !config.is_allowed(sender) {
        return Err("sender not whitelisted for this gas tank".into());
    }

    if gas_cost > config.per_tx_limit {
        return Err(format!(
            "gas cost {gas_cost} exceeds per-tx limit {}",
            config.per_tx_limit
        ));
    }

    if account.gas_tank < gas_cost {
        return Err(format!(
            "insufficient gas tank: need {gas_cost}, have {}",
            account.gas_tank
        ));
    }

    Ok(gas_cost)
}

/// Deduct gas cost from a contract's gas tank.
pub fn deduct_gas(account: &mut Account, amount: u128) -> Result<(), String> {
    if account.gas_tank < amount {
        return Err(format!(
            "insufficient gas tank: need {amount}, have {}",
            account.gas_tank
        ));
    }
    account.gas_tank -= amount;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyde_account::address::derive_eoa_address;

    fn make_contract_with_tank(tank_balance: u128) -> Account {
        let addr = derive_eoa_address(b"contract");
        let mut account = Account::new_contract(addr, b"code");
        account.gas_tank = tank_balance;
        account
    }

    fn sender_addr() -> Address {
        derive_eoa_address(b"sender")
    }

    // ========== Task 0441: Gas tank creation and funding ==========

    #[test]
    fn deposit_increases_tank() {
        let mut account = make_contract_with_tank(0);
        deposit(&mut account, 1_000_000);
        assert_eq!(account.gas_tank, 1_000_000);

        deposit(&mut account, 500_000);
        assert_eq!(account.gas_tank, 1_500_000);
    }

    // ========== Task 0442: Gas tank withdrawal ==========

    #[test]
    fn withdraw_by_owner() {
        let mut account = make_contract_with_tank(1_000_000);
        let owner = account.address;
        withdraw(&mut account, 500_000, &owner).unwrap();
        assert_eq!(account.gas_tank, 500_000);
    }

    #[test]
    fn withdraw_by_non_owner_rejected() {
        let mut account = make_contract_with_tank(1_000_000);
        let non_owner = sender_addr();
        assert!(withdraw(&mut account, 100, &non_owner).is_err());
    }

    #[test]
    fn withdraw_insufficient_rejected() {
        let mut account = make_contract_with_tank(100);
        let owner = account.address;
        assert!(withdraw(&mut account, 200, &owner).is_err());
    }

    // ========== Task 0445: Sponsored tx deducts from tank ==========

    #[test]
    fn sponsorship_deducts_from_tank() {
        let mut account = make_contract_with_tank(1_000_000);
        let config = GasTankConfig::open(account.address);
        let sender = sender_addr();

        let cost = check_sponsorship(&account, &config, &sender, 100_000).unwrap();
        assert_eq!(cost, 100_000);

        deduct_gas(&mut account, cost).unwrap();
        assert_eq!(account.gas_tank, 900_000);
    }

    // ========== Task 0446: Insufficient tank rejects ==========

    #[test]
    fn insufficient_tank_rejects() {
        let account = make_contract_with_tank(100);
        let config = GasTankConfig::open(account.address);
        let sender = sender_addr();

        assert!(check_sponsorship(&account, &config, &sender, 1_000).is_err());
    }

    // ========== Task 0447: Per-transaction limit ==========

    #[test]
    fn per_tx_limit_enforced() {
        let account = make_contract_with_tank(1_000_000);
        let config = GasTankConfig::whitelisted(
            account.address,
            vec![sender_addr()],
            50_000, // max 50K per tx
        );

        // Within limit
        assert!(check_sponsorship(&account, &config, &sender_addr(), 50_000).is_ok());

        // Over limit
        assert!(check_sponsorship(&account, &config, &sender_addr(), 50_001).is_err());
    }

    // ========== Whitelist ==========

    #[test]
    fn whitelist_allows_listed_sender() {
        let account = make_contract_with_tank(1_000_000);
        let allowed = sender_addr();
        let config = GasTankConfig::whitelisted(account.address, vec![allowed], u128::MAX);

        assert!(check_sponsorship(&account, &config, &allowed, 1_000).is_ok());
    }

    #[test]
    fn whitelist_rejects_unlisted_sender() {
        let account = make_contract_with_tank(1_000_000);
        let allowed = sender_addr();
        let other = derive_eoa_address(b"other");
        let config = GasTankConfig::whitelisted(account.address, vec![allowed], u128::MAX);

        assert!(check_sponsorship(&account, &config, &other, 1_000).is_err());
    }

    #[test]
    fn open_tank_allows_anyone() {
        let account = make_contract_with_tank(1_000_000);
        let config = GasTankConfig::open(account.address);

        let random1 = derive_eoa_address(b"random1");
        let random2 = derive_eoa_address(b"random2");
        assert!(check_sponsorship(&account, &config, &random1, 1_000).is_ok());
        assert!(check_sponsorship(&account, &config, &random2, 1_000).is_ok());
    }

    // ========== Inactive tank ==========

    #[test]
    fn inactive_tank_rejects() {
        let account = make_contract_with_tank(1_000_000);
        let mut config = GasTankConfig::open(account.address);
        config.active = false;

        assert!(check_sponsorship(&account, &config, &sender_addr(), 1_000).is_err());
    }

    // ========== Task 0448: Paymaster pattern ==========

    #[test]
    fn paymaster_is_just_a_contract_with_gas_tank() {
        // A paymaster is a contract that:
        // 1. Has a gas tank
        // 2. Has custom validation logic (code_hash != zero)
        // 3. Uses GasTankConfig with whitelist/limits
        // The paymaster pattern doesn't need special types —
        // it's a composition of existing Account + GasTankConfig.
        let addr = derive_eoa_address(b"paymaster_contract");
        let mut paymaster = Account::new_contract(addr, b"paymaster_validation_code");
        paymaster.gas_tank = 10_000_000;

        let config = GasTankConfig::whitelisted(
            paymaster.address,
            vec![sender_addr()],
            200_000, // cap per tx
        );

        // Paymaster sponsors a tx
        let cost = check_sponsorship(&paymaster, &config, &sender_addr(), 150_000).unwrap();
        deduct_gas(&mut paymaster, cost).unwrap();
        assert_eq!(paymaster.gas_tank, 10_000_000 - 150_000);
    }
}
