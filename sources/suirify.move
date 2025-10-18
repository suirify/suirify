// suirify.move

/// The main module for the SUIrify protocol.
/// This package is responsible for creating, managing, and verifying attestations.
module suirify::protocol {
    use sui::event;

    // Custom Errors
    const EUNAUTHORIZED: u64 = 0;
    const EPROTOCOL_PAUSED: u64 = 3;
    const EONLY_OWNER_CAN_BURN: u64 = 4;

    // Constants
    const STATUS_ACTIVE: u8 = 1;
    const STATUS_REVOKED: u8 = 3;

    // Structs
    /// A capability object that grants the holder the exclusive authority
    /// to mint, revoke, and manage the protocol's configuration.
    public struct VerifierAdminCap has key, store {
        id: UID,
    }

    /// The primary credential object. It is a Soulbound (non-transferable), user-
    /// owned object representing a successful identity verification.
    public struct SUIrify_Attestation has key, store {
        id: UID,
        owner: address,
        jurisdiction_code: u16,
        verification_level: u8,
        verifier_source: u8,
        verifier_version: u8,
        issue_time_ms: u64,
        expiry_time_ms: u64,
        status: u8,
        revoked: bool,
        revoke_time_ms: u64,
        revoke_reason_code: u8,
        name_hash: vector<u8>,
        is_human_verified: bool,
        is_over_18: bool,
        version: u16,
    }

    /// A singleton object for on-chain governance, holding operational
    /// parameters, limits, and allowlists.
    public struct ProtocolConfig has key, store {
        id: UID,
        paused: bool,
        allowlists: vector<address>,
        default_expiry_duration_ms: u64,
        renewal_period_ms: u64,
        mint_fee: u64,
        upgrade_fee: u64,
        treasury_address: address,
        global_mint_limit_per_day: u64,
        mints_today: u64,
        last_mint_reset_timestamp: u64,
        min_verifier_version: u8,
        contract_version: u16,
    }

    // Events
    public struct AttestationMinted has copy, drop {
        objectId: ID,
        recipient: address,
    }

    public struct AttestationRevoked has copy, drop {
        objectId: ID,
        reason_code: u8,
    }

    // Functions
    /// Initializes the entire protocol.
    fun init(ctx: &mut TxContext) {
        let verifier_admin_cap = VerifierAdminCap {
            id: object::new(ctx),
        };

        let protocol_config = ProtocolConfig {
            id: object::new(ctx),
            paused: false,
            allowlists: vector[],
            default_expiry_duration_ms: 31536000000, // 1 year
            renewal_period_ms: 2592000000, // 30 days
            mint_fee: 100000000, // 0.1 SUI
            upgrade_fee: 50000000, // 0.05 SUI
            treasury_address: tx_context::sender(ctx),
            global_mint_limit_per_day: 1000,
            mints_today: 0,
            last_mint_reset_timestamp: 0,
            min_verifier_version: 1,
            contract_version: 1,
        };

        transfer::transfer(verifier_admin_cap, tx_context::sender(ctx));
        transfer::transfer(protocol_config, tx_context::sender(ctx));
    }

    /// Creates a new SUIrify_Attestation with extended metadata and transfers it
    /// to the recipient.
    public fun mint_attestation(
        _cap: &VerifierAdminCap,
        config: &ProtocolConfig,
        recipient: address,
        jurisdiction_code: u16,
        verifier_source: u8,
        verification_level: u8,
        name_hash: vector<u8>,
        is_human_verified: bool,
        is_over_18: bool,
        verifier_version: u8,
        ctx: &mut TxContext,
    ) {
        assert!(!config.paused, EPROTOCOL_PAUSED);
        assert!(verifier_version >= config.min_verifier_version, EUNAUTHORIZED);

        let attestation = SUIrify_Attestation {
            id: object::new(ctx),
            owner: recipient,
            jurisdiction_code,
            verification_level,
            verifier_source,
            verifier_version,
            issue_time_ms: tx_context::epoch_timestamp_ms(ctx),
            expiry_time_ms: tx_context::epoch_timestamp_ms(ctx) + config.default_expiry_duration_ms,
            status: STATUS_ACTIVE,
            revoked: false,
            revoke_time_ms: 0,
            revoke_reason_code: 0,
            name_hash,
            is_human_verified,
            is_over_18,
            version: 1,
        };

        event::emit(AttestationMinted {
            objectId: object::id(&attestation),
            recipient,
        });

        transfer::transfer(attestation, recipient);
    }

    /// Allows the admin to permanently revoke an existing attestation.
    public fun revoke_attestation(
        _cap: &VerifierAdminCap,
        config: &ProtocolConfig,
        attestation: &mut SUIrify_Attestation,
        reason_code: u8,
        ctx: &mut TxContext,
    ) {
        assert!(!config.paused, EPROTOCOL_PAUSED);

        attestation.status = STATUS_REVOKED;
        attestation.revoked = true;
        attestation.revoke_reason_code = reason_code;
        attestation.revoke_time_ms = tx_context::epoch_timestamp_ms(ctx);

        event::emit(AttestationRevoked {
            objectId: object::id(attestation),
            reason_code,
        });
    }

    /// Allows the owner of an attestation to permanently and irrevocably delete it
    /// from the blockchain ("right to be forgotten").
    public fun burn_self(attestation: SUIrify_Attestation, ctx: &mut TxContext) {
        assert!(attestation.owner == tx_context::sender(ctx), EONLY_OWNER_CAN_BURN);
        let SUIrify_Attestation { id, owner: _, .. } = attestation;
        object::delete(id);
    }

    // Getter functions for cross-module access
    public fun get_status(attestation: &SUIrify_Attestation): u8 {
        attestation.status
    }

    public fun is_revoked(attestation: &SUIrify_Attestation): bool {
        attestation.revoked
    }

    public fun get_expiry_time(attestation: &SUIrify_Attestation): u64 {
        attestation.expiry_time_ms
    }

    public fun get_name_hash(attestation: &SUIrify_Attestation): vector<u8> {
        attestation.name_hash
    }

    public fun get_owner(attestation: &SUIrify_Attestation): address {
        attestation.owner
    }
    // Admin functions to update protocol configuration
    // Updates the upgrade fee
    public fun update_mint_fee(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        new_fee: u64,
    ) {
        config.mint_fee = new_fee;
    }

    // Updates the upgrade fee
    public fun update_upgrade_fee(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        new_upgrade_fee: u64,
    ) {
        config.upgrade_fee = new_upgrade_fee;
    }

    // Updates the treasury address
    public fun update_treasury_address(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        new_treasury_address: address,
    ) {
        config.treasury_address = new_treasury_address;
    }

    // Pauses or unpauses the protocol
    public fun set_protocol_paused(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        paused: bool,
    ) {
        config.paused = paused;
    }

    // Updates the default expiry duration
    public fun update_default_expiry_duration(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        new_duration_ms: u64,
    ) {
        config.default_expiry_duration_ms = new_duration_ms;
    }

    // Updates the renewal period
    public fun update_renewal_period(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        new_period_ms: u64,
    ) {
        config.renewal_period_ms = new_period_ms;
    }

    // the global mint limit per day(
    public fun update_global_mint_limit_per_day(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        new_global_mint_limit_per_day: u64,
    ) {
        config.global_mint_limit_per_day = new_global_mint_limit_per_day;
    }

    // Updates the minimum verifier version(
    public fun update_min_verifier_version(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        new_min_verifier_version: u8,
    ) {
        config.min_verifier_version = new_min_verifier_version;
    }

    // Adds an address to the allowlists
    public fun add_to_allowlist(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        address_to_add: address,
    ) {
        vector::push_back(&mut config.allowlists, address_to_add);
    }

    // Removes an address from the allowlist
    public fun remove_from_allowlist(
        _cap: &VerifierAdminCap,
        config: &mut ProtocolConfig,
        address_to_remove: address,
    ) {
        let (found, index) = vector::index_of(&config.allowlists, &address_to_remove);
        if (found) {
            vector::remove(&mut config.allowlists, index);
        };
    }

    // Checks if an address is in the allowlist
    public fun is_in_allowlist(
        _cap: &VerifierAdminCap,
        config: &ProtocolConfig,
        address_to_check: address,
    ): bool {
        vector::contains(&config.allowlists, &address_to_check)
    }

    // Test-only function to initialize the protocol for testing purposes
    #[test_only]
    public fun test_init(ctx: &mut TxContext) {
        init(ctx);
    }
}

/// Provides a clean, stable, and secure read-only API for dApps and SDKs.
module suirify::attestation_utils {
    use sui::clock::Clock;
    use suirify::protocol::{Self, SUIrify_Attestation};

    /// Returns true if the attestation is currently active,
    /// not revoked, and not expired.
    public fun is_valid(attestation: &SUIrify_Attestation, clock: &Clock): bool {
        protocol::get_status(attestation) == 1 && // STATUS_ACTIVE
        !protocol::is_revoked(attestation) &&
        clock.timestamp_ms() < protocol::get_expiry_time(attestation)
    }

    /// Returns the stored name_hash from the attestation.
    public fun get_name_hash(attestation: &SUIrify_Attestation): vector<u8> {
        protocol::get_name_hash(attestation)
    }
}

/// Defines actions that can only be initiated by the owner of a SUIrify_Attestation.
module suirify::user_actions {
    use suirify::protocol::{Self, SUIrify_Attestation};

    /// Allows the owner of an attestation to permanently and irrevocably delete it
    /// from the blockchain ("right to be forgotten").
    public fun burn_self(attestation: SUIrify_Attestation, ctx: &mut TxContext) {
        protocol::burn_self(attestation, ctx);
    }
}

/// Defines and manages jurisdiction-specific verification policies.
module suirify::jurisdictions {
    use suirify::protocol::VerifierAdminCap;

    /// Defines jurisdiction-specific verification policies.
    public struct JurisdictionPolicy has key, store {
        id: UID,
        iso_num: u16,
        allowed_sources: vector<u8>,
    }

    /// Registry to manage all jurisdiction policies
    public struct JurisdictionRegistry has key {
        id: UID,
        policies: vector<ID>, // Track all policy IDs
    }

    /// Initialize the registry (call this once)
    public fun init_registry(
        _cap: &VerifierAdminCap,
        ctx: &mut TxContext,
    ) {
        let registry = JurisdictionRegistry {
            id: object::new(ctx),
            policies: vector[],
        };
        transfer::share_object(registry); // Shared object for global access
    }

    /// Creates a new jurisdiction policy as a shared object
    public fun add_jurisdiction_policy(
        _cap: &VerifierAdminCap,
        registry: &mut JurisdictionRegistry,
        iso_num: u16,
        allowed_sources: vector<u8>,
        ctx: &mut TxContext,
    ) {
        let policy = JurisdictionPolicy {
            id: object::new(ctx),
            iso_num,
            allowed_sources,
        };
        
        let policy_id = object::id(&policy);
        vector::push_back(&mut registry.policies, policy_id);
        
        transfer::share_object(policy); // Make policy globally accessible
    }
}