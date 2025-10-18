#[test_only]
module suirify::suirify_tests {
    use sui::test_scenario::{Self, next_tx};
    use sui::clock;
    use suirify::protocol::{Self, VerifierAdminCap, ProtocolConfig, SUIrify_Attestation};
    use suirify::attestation_utils;
    use suirify::user_actions;

    // Test constants
    const ADMIN: address = @0xABCD;
    const USER1: address = @0x1234;
    const USER2: address = @0x5678;

    #[test]
    fun test_init_protocol() {
        let mut scenario = test_scenario::begin(ADMIN);
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            // Verify admin cap was created and transferred to admin
            assert!(test_scenario::has_most_recent_for_sender<VerifierAdminCap>(&scenario), 0);
            
            // Verify protocol config was created and transferred to admin
            assert!(test_scenario::has_most_recent_for_sender<ProtocolConfig>(&scenario), 1);
        };
        
        test_scenario::end(scenario);
    }

    #[test]
    fun test_mint_attestation() {
        let mut scenario = test_scenario::begin(ADMIN);
        
        // Initialize protocol
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            // Mint attestation for USER1
            protocol::mint_attestation(
                &admin_cap,
                &config,
                USER1,
                840, // US jurisdiction code
                1,   // verifier source
                1,   // verification level
                b"name_hash_test",
                true, // is_human_verified
                true, // is_over_18
                1,    // verifier_version
                test_scenario::ctx(&mut scenario)
            );
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        next_tx(&mut scenario, USER1);
        {
            // Verify attestation was minted and transferred to USER1
            assert!(test_scenario::has_most_recent_for_sender<SUIrify_Attestation>(&scenario), 2);
            
            let attestation = test_scenario::take_from_sender<SUIrify_Attestation>(&scenario);
            
            // Verify attestation properties
            assert!(protocol::get_owner(&attestation) == USER1, 3);
            assert!(protocol::get_status(&attestation) == 1, 4); // STATUS_ACTIVE
            assert!(!protocol::is_revoked(&attestation), 5);
            assert!(protocol::get_name_hash(&attestation) == b"name_hash_test", 6);
            
            test_scenario::return_to_sender(&scenario, attestation);
        };
        
        test_scenario::end(scenario);
    }

    #[test]
    fun test_revoke_attestation() {
        let mut scenario = test_scenario::begin(ADMIN);
        
        // Initialize and mint attestation
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            protocol::mint_attestation(
                &admin_cap,
                &config,
                USER1,
                840, // US jurisdiction code
                1, 1, b"name_hash_test", true, true, 1,
                test_scenario::ctx(&mut scenario)
            );
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            let mut attestation = test_scenario::take_from_address<SUIrify_Attestation>(&scenario, USER1);
            
            // Revoke the attestation
            protocol::revoke_attestation(
                &admin_cap,
                &config,
                &mut attestation,
                1, // reason code
                test_scenario::ctx(&mut scenario)
            );
            
            // Verify attestation is revoked
            assert!(protocol::get_status(&attestation) == 3, 7); // STATUS_REVOKED
            assert!(protocol::is_revoked(&attestation), 8);
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
            test_scenario::return_to_address(USER1, attestation);
        };
        
        test_scenario::end(scenario);
    }

    #[test]
    fun test_attestation_validity_with_clock() {
        let mut scenario = test_scenario::begin(ADMIN);
        let mut clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        
        // Initialize and mint attestation
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            protocol::mint_attestation(
                &admin_cap,
                &config,
                USER1,
                840, 1, 1, b"name_hash_test", true, true, 1,
                test_scenario::ctx(&mut scenario)
            );
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        next_tx(&mut scenario, USER1);
        {
            let attestation = test_scenario::take_from_sender<SUIrify_Attestation>(&scenario);
            
            // Test valid attestation
            assert!(attestation_utils::is_valid(&attestation, &clock), 9);
            
            // Fast forward time beyond expiry (1 year + 1 day)
            clock::increment_for_testing(&mut clock, 31536000000 + 86400000);
            
            // Test expired attestation
            assert!(!attestation_utils::is_valid(&attestation, &clock), 10);
            
            test_scenario::return_to_sender(&scenario, attestation);
        };
        
        clock::destroy_for_testing(clock);
        test_scenario::end(scenario);
    }

    #[test]
    fun test_burn_self() {
        let mut scenario = test_scenario::begin(ADMIN);
        
        // Initialize and mint attestation
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            protocol::mint_attestation(
                &admin_cap,
                &config,
                USER1,
                840, 1, 1, b"name_hash_test", true, true, 1,
                test_scenario::ctx(&mut scenario)
            );
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        next_tx(&mut scenario, USER1);
        {
            let attestation = test_scenario::take_from_sender<SUIrify_Attestation>(&scenario);
            
            // Burn the attestation
            user_actions::burn_self(attestation, test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, USER1);
        {
            // Verify attestation no longer exists
            assert!(!test_scenario::has_most_recent_for_sender<SUIrify_Attestation>(&scenario), 11);
        };
        
        test_scenario::end(scenario);
    }

    #[test]
    fun test_protocol_config_updates() {
        let mut scenario = test_scenario::begin(ADMIN);
        
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let mut config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            // Test updating mint fee
            protocol::update_mint_fee(&admin_cap, &mut config, 200000000);
            
            // Test updating treasury address
            protocol::update_treasury_address(&admin_cap, &mut config, USER2);
            
            // Test pausing protocol
            protocol::set_protocol_paused(&admin_cap, &mut config, true);
            
            // Test allowlist management
            protocol::add_to_allowlist(&admin_cap, &mut config, USER1);
            assert!(protocol::is_in_allowlist(&admin_cap, &config, USER1), 12);
            
            protocol::remove_from_allowlist(&admin_cap, &mut config, USER1);
            assert!(!protocol::is_in_allowlist(&admin_cap, &config, USER1), 13);
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = suirify::protocol::EPROTOCOL_PAUSED)]
    fun test_mint_when_paused_fails() {
        let mut scenario = test_scenario::begin(ADMIN);
        
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let mut config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            // Pause the protocol
            protocol::set_protocol_paused(&admin_cap, &mut config, true);
            
            // This should fail
            protocol::mint_attestation(
                &admin_cap,
                &config,
                USER1,
                840, 1, 1, b"name_hash_test", true, true, 1,
                test_scenario::ctx(&mut scenario)
            );
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        test_scenario::end(scenario);
    }

    #[test]
    #[expected_failure(abort_code = suirify::protocol::EONLY_OWNER_CAN_BURN)]
    fun test_burn_by_non_owner_fails() {
        let mut scenario = test_scenario::begin(ADMIN);
        
        // Initialize and mint attestation for USER1
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            protocol::mint_attestation(
                &admin_cap,
                &config,
                USER1,
                840, 1, 1, b"name_hash_test", true, true, 1,
                test_scenario::ctx(&mut scenario)
            );
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        next_tx(&mut scenario, USER2); // USER2 tries to burn USER1's attestation
        {
            let attestation = test_scenario::take_from_address<SUIrify_Attestation>(&scenario, USER1);
            
            // This should fail because USER2 is not the owner
            user_actions::burn_self(attestation, test_scenario::ctx(&mut scenario));
        };
        
        test_scenario::end(scenario);
    }

    #[test]
    fun test_attestation_utils() {
        let mut scenario = test_scenario::begin(ADMIN);
        let clock = clock::create_for_testing(test_scenario::ctx(&mut scenario));
        
        // Initialize and mint attestation
        {
            protocol::test_init(test_scenario::ctx(&mut scenario));
        };
        
        next_tx(&mut scenario, ADMIN);
        {
            let admin_cap = test_scenario::take_from_sender<VerifierAdminCap>(&scenario);
            let config = test_scenario::take_from_sender<ProtocolConfig>(&scenario);
            
            protocol::mint_attestation(
                &admin_cap,
                &config,
                USER1,
                840, 1, 1, b"test_name_hash", true, true, 1,
                test_scenario::ctx(&mut scenario)
            );
            
            test_scenario::return_to_sender(&scenario, admin_cap);
            test_scenario::return_to_sender(&scenario, config);
        };
        
        next_tx(&mut scenario, USER1);
        {
            let attestation = test_scenario::take_from_sender<SUIrify_Attestation>(&scenario);
            
            // Test attestation utils functions
            assert!(attestation_utils::is_valid(&attestation, &clock), 14);
            assert!(attestation_utils::get_name_hash(&attestation) == b"test_name_hash", 15);
            
            test_scenario::return_to_sender(&scenario, attestation);
        };
        
        clock::destroy_for_testing(clock);
        test_scenario::end(scenario);
    }
}