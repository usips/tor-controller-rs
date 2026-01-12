//! Integration tests for tor-controller against a real Tor instance.
//!
//! These tests require a running Tor instance with control port enabled.
//!
//! # Running the tests
//!
//! 1. Start Tor with Docker:
//!    ```sh
//!    docker compose up -d
//!    ```
//!
//! 2. Wait for Tor to bootstrap (check logs):
//!    ```sh
//!    docker compose logs -f tor
//!    ```
//!
//! 3. Run the integration tests:
//!    ```sh
//!    cargo test --test integration
//!    ```
//!
//! # Test Configuration
//!
//! By default, tests connect to 127.0.0.1:9051.
//! Set the `TOR_CONTROL_PORT` environment variable to override.

use std::time::Duration;
use tokio::time::timeout;
use tor_controller::{
    AuthCredential, CircuitId, Event, EventType, Result, Signal, TorClient, TorControlError,
};

/// Default timeout for operations
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Get the control port address from environment or use default
fn control_addr() -> String {
    std::env::var("TOR_CONTROL_PORT").unwrap_or_else(|_| "127.0.0.1:9051".to_string())
}

/// Helper to create an authenticated client
async fn authenticated_client() -> Result<TorClient> {
    let mut client = TorClient::connect(&control_addr()).await?;
    // Use password "test" for Docker container, or auto-auth for local Tor
    let password = std::env::var("TOR_PASSWORD").unwrap_or_else(|_| "test".to_string());
    if password.is_empty() {
        client.auto_authenticate().await?;
    } else {
        client
            .authenticate(&AuthCredential::Password(password))
            .await?;
    }
    Ok(client)
}

// ============================================================================
// Connection Tests
// ============================================================================

mod connection {
    use super::*;

    #[tokio::test]
    async fn test_connect() {
        let result = timeout(TEST_TIMEOUT, TorClient::connect(&control_addr())).await;
        assert!(result.is_ok(), "Connection should succeed");
        assert!(result.unwrap().is_ok(), "Should connect to Tor");
    }

    #[tokio::test]
    async fn test_connect_invalid_address() {
        let result = TorClient::connect("127.0.0.1:1").await;
        assert!(result.is_err(), "Should fail to connect to invalid address");
    }

    #[tokio::test]
    async fn test_quit() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.quit().await;
        assert!(result.is_ok(), "QUIT should succeed");
    }
}

// ============================================================================
// Authentication Tests
// ============================================================================

mod authentication {
    use super::*;

    #[tokio::test]
    async fn test_protocol_info() {
        let mut client = TorClient::connect(&control_addr()).await.unwrap();
        let info = client.protocol_info().await.unwrap();

        assert!(info.protocol_version > 0, "Should have protocol version");
        assert!(!info.auth_methods.is_empty(), "Should have auth methods");
        println!("Protocol version: {}", info.protocol_version);
        println!("Auth methods: {:?}", info.auth_methods);
        println!("Cookie file: {:?}", info.cookie_file);
        println!("Tor version: {:?}", info.tor_version);
    }

    #[tokio::test]
    async fn test_auto_authenticate() {
        let mut client = TorClient::connect(&control_addr()).await.unwrap();
        let info = client.protocol_info().await.unwrap();

        // Skip if only password auth is available (requires knowing the password)
        if info.supports_password()
            && !info.supports_null()
            && !info.supports_cookie()
            && !info.supports_safe_cookie()
        {
            println!("Skipping: only password auth available");
            return;
        }

        let result = client.auto_authenticate().await;
        assert!(result.is_ok(), "Auto-authentication should succeed");
    }

    #[tokio::test]
    async fn test_authenticate_cookie() {
        let mut client = TorClient::connect(&control_addr()).await.unwrap();
        let info = client.protocol_info().await.unwrap();

        if let Some(cookie_file) = info.cookie_file {
            let result = client
                .authenticate(&AuthCredential::CookieFile(cookie_file))
                .await;
            assert!(result.is_ok(), "Cookie authentication should succeed");
        }
    }

    #[tokio::test]
    async fn test_authenticate_safecookie() {
        let mut client = TorClient::connect(&control_addr()).await.unwrap();
        let info = client.protocol_info().await.unwrap();

        if info.supports_safe_cookie() {
            if let Some(cookie_path) = info.cookie_file {
                let result = client
                    .authenticate(&AuthCredential::SafeCookie { cookie_path })
                    .await;
                assert!(result.is_ok(), "SAFECOOKIE authentication should succeed");
            }
        }
    }

    #[tokio::test]
    async fn test_authenticate_wrong_password() {
        let mut client = TorClient::connect(&control_addr()).await.unwrap();
        let info = client.protocol_info().await.unwrap();

        // Only test if password auth is supported but NOT null auth
        if info.supports_password() && !info.supports_null() {
            let result = client
                .authenticate(&AuthCredential::Password("wrong_password".to_string()))
                .await;
            assert!(result.is_err(), "Wrong password should fail");
        }
    }
}

// ============================================================================
// Information Query Tests
// ============================================================================

mod information {
    use super::*;

    #[tokio::test]
    async fn test_get_version() {
        let mut client = authenticated_client().await.unwrap();
        let version = client.get_version().await.unwrap();

        assert!(
            version.major > 0 || version.minor > 0,
            "Should have version"
        );
        println!("Tor version: {}", version);
        println!(
            "Parsed: {}.{}.{}.{}",
            version.major, version.minor, version.micro, version.patch
        );
    }

    #[tokio::test]
    async fn test_get_info_version() {
        let mut client = authenticated_client().await.unwrap();
        let version = client.get_info("version").await.unwrap();
        assert!(!version.is_empty(), "Version should not be empty");
    }

    #[tokio::test]
    async fn test_get_info_config_file() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.get_info("config-file").await;
        // May or may not be set depending on Tor configuration
        println!("Config file: {:?}", result);
    }

    #[tokio::test]
    async fn test_get_info_traffic() {
        let mut client = authenticated_client().await.unwrap();
        let read = client.get_info("traffic/read").await.unwrap();
        let written = client.get_info("traffic/written").await.unwrap();

        println!("Traffic read: {} bytes", read);
        println!("Traffic written: {} bytes", written);
    }

    #[tokio::test]
    async fn test_get_info_multi() {
        let mut client = authenticated_client().await.unwrap();
        let info = client
            .get_info_multi(&["version", "traffic/read", "traffic/written"])
            .await
            .unwrap();

        assert!(info.contains_key("version"), "Should have version");
        println!("Multi-info result: {:?}", info);
    }

    #[tokio::test]
    async fn test_get_info_invalid_key() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.get_info("nonexistent-key-12345").await;
        assert!(result.is_err(), "Invalid key should return error");
    }

    #[tokio::test]
    async fn test_get_info_address() {
        let mut client = authenticated_client().await.unwrap();
        // This may fail if Tor hasn't determined its external address
        let result = client.get_info("address").await;
        println!("External address: {:?}", result);
    }

    #[tokio::test]
    async fn test_get_info_fingerprint() {
        let mut client = authenticated_client().await.unwrap();
        // Only available if running as a relay
        let result = client.get_info("fingerprint").await;
        println!("Fingerprint: {:?}", result);
    }

    #[tokio::test]
    async fn test_get_info_dormant() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.get_info("dormant").await;
        println!("Dormant status: {:?}", result);
    }

    #[tokio::test]
    async fn test_get_info_uptime() {
        let mut client = authenticated_client().await.unwrap();
        let uptime = client.get_info("uptime").await.unwrap();
        let uptime_secs: u64 = uptime.parse().unwrap_or(0);
        // u64 is always >= 0, so just check it parses
        let _ = uptime_secs;
        println!("Tor uptime: {} seconds", uptime_secs);
    }

    #[tokio::test]
    async fn test_get_info_process_pid() {
        let mut client = authenticated_client().await.unwrap();
        let pid = client.get_info("process/pid").await.unwrap();
        let pid_num: u32 = pid.parse().unwrap();
        assert!(pid_num > 0, "PID should be positive");
        println!("Tor PID: {}", pid_num);
    }

    #[tokio::test]
    async fn test_get_info_status_bootstrap() {
        let mut client = authenticated_client().await.unwrap();
        let status = client.get_info("status/bootstrap-phase").await.unwrap();
        println!("Bootstrap status: {}", status);
        // Should contain PROGRESS
        assert!(
            status.contains("PROGRESS"),
            "Bootstrap status should contain PROGRESS"
        );
    }
}

// ============================================================================
// Configuration Tests
// ============================================================================

mod configuration {
    use super::*;

    #[tokio::test]
    async fn test_get_conf_socks_port() {
        let mut client = authenticated_client().await.unwrap();
        let port = client.get_conf("SocksPort").await.unwrap();
        println!("SocksPort: {:?}", port);
    }

    #[tokio::test]
    async fn test_get_conf_control_port() {
        let mut client = authenticated_client().await.unwrap();
        let port = client.get_conf("ControlPort").await.unwrap();
        println!("ControlPort: {:?}", port);
    }

    #[tokio::test]
    async fn test_get_conf_data_directory() {
        let mut client = authenticated_client().await.unwrap();
        let dir = client.get_conf("DataDirectory").await.unwrap();
        println!("DataDirectory: {:?}", dir);
    }

    #[tokio::test]
    async fn test_get_conf_multi() {
        let mut client = authenticated_client().await.unwrap();
        let conf = client
            .get_conf_multi(&["SocksPort", "ControlPort", "DataDirectory"])
            .await
            .unwrap();

        println!("Configuration: {:?}", conf);
    }

    #[tokio::test]
    async fn test_set_conf_and_reset() {
        let mut client = authenticated_client().await.unwrap();

        // Get original value
        let original = client.get_conf("MaxCircuitDirtiness").await.unwrap();
        println!("Original MaxCircuitDirtiness: {:?}", original);

        // Set new value
        client.set_conf("MaxCircuitDirtiness", "600").await.unwrap();

        // Verify change
        let new_value = client.get_conf("MaxCircuitDirtiness").await.unwrap();
        assert_eq!(new_value, Some("600".to_string()));

        // Reset to default
        client.reset_conf("MaxCircuitDirtiness").await.unwrap();

        // Note: default value may differ from original if original was non-default
        println!("Reset MaxCircuitDirtiness to default");
    }

    #[tokio::test]
    async fn test_set_conf_multi() {
        let mut client = authenticated_client().await.unwrap();

        // Set multiple values
        let result = client
            .set_conf_multi(&[
                ("MaxCircuitDirtiness", "600"),
                ("CircuitBuildTimeout", "120"),
            ])
            .await;

        // This should succeed
        assert!(result.is_ok(), "Setting multiple config values should work");

        // Reset both
        client.reset_conf("MaxCircuitDirtiness").await.unwrap();
        client.reset_conf("CircuitBuildTimeout").await.unwrap();
    }

    #[tokio::test]
    async fn test_set_conf_invalid() {
        let mut client = authenticated_client().await.unwrap();

        let result = client.set_conf("InvalidConfigOption12345", "value").await;
        assert!(result.is_err(), "Invalid config option should fail");
    }

    #[tokio::test]
    async fn test_get_conf_nonexistent() {
        let mut client = authenticated_client().await.unwrap();

        let result = client.get_conf("NonexistentOption12345").await;
        // Should return error for unknown option
        assert!(result.is_err(), "Unknown option should return error");
    }
}

// ============================================================================
// Circuit Tests
// ============================================================================

mod circuits {
    use super::*;

    #[tokio::test]
    async fn test_get_circuit_status() {
        let mut client = authenticated_client().await.unwrap();
        let circuits = client.get_circuit_status().await.unwrap();

        println!("Found {} circuits", circuits.len());
        for circuit in &circuits {
            println!(
                "  Circuit {}: {:?}, path: {:?}",
                circuit.id, circuit.status, circuit.path
            );
        }
    }

    #[tokio::test]
    async fn test_close_circuit_nonexistent() {
        let mut client = authenticated_client().await.unwrap();

        // Try to close a circuit that doesn't exist
        let result = client.close_circuit(CircuitId(999999999), false).await;
        // This should fail
        assert!(result.is_err(), "Closing nonexistent circuit should fail");
    }

    #[tokio::test]
    async fn test_extend_circuit_empty_path() {
        let mut client = authenticated_client().await.unwrap();

        // Creating a circuit with empty path should create a new one
        // but requires guards to be available
        let result = client.extend_circuit(None, &[]).await;
        // May succeed or fail depending on network status
        println!("Extend circuit with empty path: {:?}", result);
    }
}

// ============================================================================
// Stream Tests
// ============================================================================

mod streams {
    use super::*;

    #[tokio::test]
    async fn test_get_stream_status() {
        let mut client = authenticated_client().await.unwrap();
        let streams = client.get_stream_status().await.unwrap();

        println!("Found {} streams", streams.len());
        for stream in &streams {
            println!(
                "  Stream {}: {:?}, circuit {}, target: {}",
                stream.id, stream.status, stream.circuit_id, stream.target
            );
        }
    }
}

// ============================================================================
// Signal Tests
// ============================================================================

mod signals {
    use super::*;

    #[tokio::test]
    async fn test_signal_newnym() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.signal(Signal::NewNym).await;
        assert!(result.is_ok(), "NEWNYM signal should succeed");
    }

    #[tokio::test]
    async fn test_new_identity() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.new_identity().await;
        assert!(result.is_ok(), "New identity should succeed");
    }

    #[tokio::test]
    async fn test_clear_dns_cache() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.clear_dns_cache().await;
        assert!(result.is_ok(), "Clear DNS cache should succeed");
    }

    #[tokio::test]
    async fn test_signal_heartbeat() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.signal(Signal::Heartbeat).await;
        assert!(result.is_ok(), "HEARTBEAT signal should succeed");
    }

    #[tokio::test]
    async fn test_signal_dump() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.signal(Signal::Dump).await;
        assert!(result.is_ok(), "DUMP signal should succeed");
    }

    #[tokio::test]
    async fn test_signal_active() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.signal(Signal::Active).await;
        assert!(result.is_ok(), "ACTIVE signal should succeed");
    }

    // Note: We don't test SHUTDOWN, HALT, or DORMANT as they would stop Tor
}

// ============================================================================
// Event Tests
// ============================================================================

mod events {
    use super::*;

    #[tokio::test]
    async fn test_set_events_bandwidth() {
        let mut client = authenticated_client().await.unwrap();
        let result = client.set_events(&[EventType::Bw]).await;
        assert!(result.is_ok(), "Setting BW events should succeed");

        // Clear events - ignore errors from async events arriving
        let _ = client.set_events(&[]).await;
    }

    #[tokio::test]
    async fn test_set_events_multiple() {
        let mut client = authenticated_client().await.unwrap();
        let result = client
            .set_events(&[
                EventType::Circ,
                EventType::Stream,
                EventType::Bw,
                EventType::Notice,
            ])
            .await;
        assert!(result.is_ok(), "Setting multiple events should succeed");

        // Clear events - ignore errors from async events arriving
        let _ = client.set_events(&[]).await;
    }

    #[tokio::test]
    async fn test_read_bandwidth_event() {
        let mut client = authenticated_client().await.unwrap();

        // Subscribe to bandwidth events
        client.set_events(&[EventType::Bw]).await.unwrap();

        // Wait for a bandwidth event (sent every second)
        let event = timeout(Duration::from_secs(5), client.read_event()).await;

        match event {
            Ok(Ok(Event::Bandwidth(bw))) => {
                println!(
                    "Received bandwidth event: {} read, {} written",
                    bw.bytes_read, bw.bytes_written
                );
            }
            Ok(Ok(other)) => {
                println!("Received other event: {:?}", other);
            }
            Ok(Err(e)) => {
                panic!("Error reading event: {:?}", e);
            }
            Err(_) => {
                panic!("Timeout waiting for bandwidth event");
            }
        }

        // Clear events
        client.set_events(&[]).await.unwrap();
    }

    #[tokio::test]
    async fn test_set_events_invalid() {
        let mut client = authenticated_client().await.unwrap();
        // All our event types are valid, so this should work
        let result = client.set_events(&[EventType::StatusGeneral]).await;
        assert!(result.is_ok());

        // Clear events
        client.set_events(&[]).await.unwrap();
    }
}

// ============================================================================
// Onion Service Tests
// ============================================================================

mod onion_services {
    use super::*;

    #[tokio::test]
    async fn test_add_and_del_onion() {
        let mut client = authenticated_client().await.unwrap();

        // Create an ephemeral onion service
        let service = client
            .add_onion(&[(80, Some("127.0.0.1:8080"))], None, &[])
            .await
            .unwrap();

        println!("Created onion service: {}", service.address.full_address());
        assert!(service.address.is_v3(), "Should create v3 onion address");
        assert!(
            service.private_key.is_some(),
            "Should return private key by default"
        );

        // Delete the service
        let result = client.del_onion(service.address.service_id()).await;
        assert!(result.is_ok(), "Deleting onion service should succeed");
    }

    #[tokio::test]
    async fn test_add_onion_with_discard_pk() {
        let mut client = authenticated_client().await.unwrap();

        // Create service with DiscardPK flag
        let service = client
            .add_onion(&[(80, Some("127.0.0.1:8080"))], None, &["DiscardPK"])
            .await
            .unwrap();

        println!("Created onion service: {}", service.address.full_address());
        assert!(
            service.private_key.is_none(),
            "Should not return private key with DiscardPK"
        );

        // Cleanup
        client
            .del_onion(service.address.service_id())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_add_onion_multiple_ports() {
        let mut client = authenticated_client().await.unwrap();

        // Create service with multiple port mappings
        let service = client
            .add_onion(
                &[
                    (80, Some("127.0.0.1:8080")),
                    (443, Some("127.0.0.1:8443")),
                    (22, Some("127.0.0.1:2222")),
                ],
                None,
                &[],
            )
            .await
            .unwrap();

        println!(
            "Created multi-port onion service: {}",
            service.address.full_address()
        );

        // Cleanup
        client
            .del_onion(service.address.service_id())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_del_onion_nonexistent() {
        let mut client = authenticated_client().await.unwrap();

        // Try to delete a service that doesn't exist
        let result = client.del_onion("nonexistentserviceid12345678").await;
        assert!(result.is_err(), "Deleting nonexistent service should fail");
    }
}

// ============================================================================
// Address Mapping Tests
// ============================================================================

mod address_mapping {
    use super::*;

    #[tokio::test]
    async fn test_map_address() {
        let mut client = authenticated_client().await.unwrap();

        // Map a fake address to an onion address
        let result = client
            .map_address("www.example.test", "www.torproject.org")
            .await;

        // This should work
        println!("Map address result: {:?}", result);
    }

    #[tokio::test]
    async fn test_resolve() {
        let mut client = authenticated_client().await.unwrap();

        // Note: RESOLVE is asynchronous - it returns immediately and
        // the result comes as an ADDRMAP event
        let result = client.resolve("www.torproject.org", false).await;
        println!("Resolve result: {:?}", result);
    }
}

// ============================================================================
// Ownership Tests
// ============================================================================

mod ownership {
    use super::*;

    #[tokio::test]
    async fn test_take_and_drop_ownership() {
        let mut client = authenticated_client().await.unwrap();

        // Take ownership
        let take_result = client.take_ownership().await;
        assert!(take_result.is_ok(), "TAKEOWNERSHIP should succeed");

        // Drop ownership
        let drop_result = client.drop_ownership().await;
        assert!(drop_result.is_ok(), "DROPOWNERSHIP should succeed");
    }
}

// ============================================================================
// Guard Tests
// ============================================================================

mod guards {
    use super::*;

    #[tokio::test]
    async fn test_drop_guards() {
        let mut client = authenticated_client().await.unwrap();

        // This clears the guard list
        let result = client.drop_guards().await;
        assert!(result.is_ok(), "DROPGUARDS should succeed");
    }
}

// ============================================================================
// Raw Command Tests
// ============================================================================

mod raw_commands {
    use super::*;

    #[tokio::test]
    async fn test_send_raw_command() {
        let mut client = authenticated_client().await.unwrap();

        // Send a raw GETINFO command
        let reply = client.send_command("GETINFO version\r\n").await.unwrap();
        assert!(reply.is_success(), "Raw GETINFO should succeed");
        println!("Raw reply: {:?}", reply);
    }

    #[tokio::test]
    async fn test_send_invalid_command() {
        let mut client = authenticated_client().await.unwrap();

        let reply = client.send_command("INVALIDCOMMAND\r\n").await.unwrap();
        assert!(!reply.is_success(), "Invalid command should return error");
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_handling {
    use super::*;

    #[tokio::test]
    async fn test_error_types() {
        // Test that we can create various error types
        let io_err = TorControlError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "test",
        ));
        println!("IO error: {}", io_err);

        let auth_err = TorControlError::AuthenticationFailed("test".to_string());
        println!("Auth error: {}", auth_err);

        let parse_err = TorControlError::ParseError("test".to_string());
        println!("Parse error: {}", parse_err);
    }

    #[tokio::test]
    async fn test_connection_to_wrong_port() {
        // Try connecting to a port that isn't Tor
        let result = TorClient::connect("127.0.0.1:1").await;
        assert!(result.is_err());
    }
}

// ============================================================================
// Stress Tests
// ============================================================================

mod stress {
    use super::*;

    #[tokio::test]
    async fn test_multiple_sequential_commands() {
        let mut client = authenticated_client().await.unwrap();

        // Send many commands in sequence
        for i in 0..20 {
            let version = client.get_version().await.unwrap();
            assert!(version.major > 0 || version.minor > 0);
            if i % 5 == 0 {
                println!("Completed {} commands", i + 1);
            }
        }
    }

    #[tokio::test]
    async fn test_rapid_config_changes() {
        let mut client = authenticated_client().await.unwrap();

        for i in 0..10 {
            let value = (300 + i * 10).to_string();
            client
                .set_conf("MaxCircuitDirtiness", &value)
                .await
                .unwrap();
            let readback = client.get_conf("MaxCircuitDirtiness").await.unwrap();
            assert_eq!(readback, Some(value));
        }

        // Reset to default
        client.reset_conf("MaxCircuitDirtiness").await.unwrap();
    }

    #[tokio::test]
    async fn test_create_multiple_onion_services() {
        let mut client = authenticated_client().await.unwrap();

        let mut services = Vec::new();

        // Create several onion services
        for i in 0..5 {
            let port = 8080 + i;
            let service = client
                .add_onion(
                    &[(80, Some(&format!("127.0.0.1:{}", port)))],
                    None,
                    &["DiscardPK"],
                )
                .await
                .unwrap();
            println!("Created service {}: {}", i, service.address.full_address());
            services.push(service);
        }

        // Delete all services
        for service in services {
            client
                .del_onion(service.address.service_id())
                .await
                .unwrap();
        }
    }
}

// ============================================================================
// Comprehensive Workflow Test
// ============================================================================

#[tokio::test]
async fn test_complete_workflow() {
    // This test exercises a complete workflow
    let mut client = TorClient::connect(&control_addr()).await.unwrap();

    // 1. Get protocol info
    let info = client.protocol_info().await.unwrap();
    println!("Step 1: Protocol info - version {}", info.protocol_version);

    // 2. Authenticate (using password for Docker, auto for local)
    let password = std::env::var("TOR_PASSWORD").unwrap_or_else(|_| "test".to_string());
    if password.is_empty() {
        client.auto_authenticate().await.unwrap();
    } else {
        client
            .authenticate(&AuthCredential::Password(password))
            .await
            .unwrap();
    }
    println!("Step 2: Authenticated");

    // 3. Get version
    let version = client.get_version().await.unwrap();
    println!("Step 3: Tor version {}", version);

    // 4. Check configuration
    let socks_port = client.get_conf("SocksPort").await.unwrap();
    println!("Step 4: SocksPort = {:?}", socks_port);

    // 5. Get bootstrap status
    let bootstrap = client.get_info("status/bootstrap-phase").await.unwrap();
    println!("Step 5: Bootstrap = {}", bootstrap);

    // 6. Get circuit status
    let circuits = client.get_circuit_status().await.unwrap();
    println!("Step 6: {} circuits", circuits.len());

    // 7. Create onion service
    let service = client
        .add_onion(&[(80, Some("127.0.0.1:8080"))], None, &["DiscardPK"])
        .await
        .unwrap();
    println!("Step 7: Created {}", service.address.full_address());

    // 8. Request new identity
    client.new_identity().await.unwrap();
    println!("Step 8: Requested new identity");

    // 9. Subscribe to events briefly
    client.set_events(&[EventType::Bw]).await.unwrap();
    let event = timeout(Duration::from_secs(2), client.read_event()).await;
    if let Ok(Ok(Event::Bandwidth(bw))) = event {
        println!(
            "Step 9: BW event - {} read, {} written",
            bw.bytes_read, bw.bytes_written
        );
    }
    client.set_events(&[]).await.unwrap();

    // 10. Cleanup
    client
        .del_onion(service.address.service_id())
        .await
        .unwrap();
    println!("Step 10: Cleaned up onion service");

    // 11. Quit
    client.quit().await.unwrap();
    println!("Step 11: Disconnected");

    println!("Complete workflow test passed!");
}
