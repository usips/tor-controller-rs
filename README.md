# tor-control

A safe, practical, robust, and configurable Rust crate for interfacing with the Tor control protocol.

## Features

- 🔒 **Safe** - No unsafe code, comprehensive error handling
- 🔧 **Configurable** - Multiple authentication methods, flexible connection options
- 🚀 **Async** - Built on Tokio for efficient async I/O
- 📦 **Complete** - Implements all major Tor control commands
- 🔐 **Secure Authentication** - Supports NULL, password, cookie, and SAFECOOKIE methods

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
tor-control = "0.1.1"
```

## Quick Start

```rust
use tor_control::{TorClient, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Connect to the default control port (127.0.0.1:9051)
    let mut client = TorClient::connect_default().await?;
    
    // Auto-authenticate using the best available method
    client.auto_authenticate().await?;
    
    // Get Tor version
    let version = client.get_version().await?;
    println!("Connected to Tor {}", version);
    
    // Request a new identity (new circuits)
    client.new_identity().await?;
    println!("New identity requested");
    
    Ok(())
}
```

## Authentication Methods

The crate supports all Tor authentication methods:

### NULL Authentication
```rust
client.authenticate(&AuthCredential::None).await?;
```

### Password Authentication
```rust
client.authenticate(&AuthCredential::Password("secret".to_string())).await?;
```

### Cookie Authentication
```rust
client.authenticate(&AuthCredential::CookieFile(
    "/run/tor/control.authcookie".to_string()
)).await?;
```

### SAFECOOKIE Authentication (Recommended)
```rust
client.authenticate(&AuthCredential::SafeCookie {
    cookie_path: "/run/tor/control.authcookie".to_string(),
}).await?;
```

### Auto Authentication
```rust
// Automatically detect and use the best available method
client.auto_authenticate().await?;
```

## Common Operations

### Configuration Management

```rust
// Get a configuration value
if let Some(socks_port) = client.get_conf("SocksPort").await? {
    println!("SOCKS port: {}", socks_port);
}

// Set configuration
client.set_conf("MaxCircuitDirtiness", "300").await?;

// Save configuration to disk
client.save_conf(false).await?;
```

### Circuit Management

```rust
use tor_control::{Signal, CircuitId};

// Request new identity (new circuits)
client.signal(Signal::NewNym).await?;

// Get circuit status
let circuits = client.get_circuit_status().await?;
for circuit in circuits {
    println!("Circuit {}: {:?}", circuit.id.0, circuit.status);
}

// Close a circuit
client.close_circuit(CircuitId(12345), false).await?;
```

### Onion Services

```rust
// Create a new onion service
let service = client.add_onion(
    &[(80, Some("127.0.0.1:8080"))],  // Virtual port 80 -> local 8080
    None,                              // Generate new key
    &[],                               // No flags
).await?;

println!("Service address: {}", service.address);

if let Some(key) = service.private_key {
    println!("Private key: {}", key);
}

// Delete the service when done
client.del_onion(&service.address.service_id()).await?;
```

### Event Monitoring

```rust
use tor_control::EventType;

// Subscribe to events
client.set_events(&[EventType::Circ, EventType::Stream, EventType::Bw]).await?;

// Read events
loop {
    let event = client.read_event().await?;
    match event {
        Event::Circuit(circ) => println!("Circuit {}: {:?}", circ.id.0, circ.status),
        Event::Bandwidth(bw) => println!("Bandwidth: {} down, {} up", bw.read, bw.written),
        _ => println!("Other event: {:?}", event),
    }
}
```

### Information Queries

```rust
// Get Tor version
let version = client.get_version().await?;
println!("Tor version: {}", version);

// Get arbitrary info
let traffic = client.get_info("traffic/read").await?;
println!("Traffic read: {} bytes", traffic);
```

## Signals

```rust
use tor_control::Signal;

// Request new identity
client.signal(Signal::NewNym).await?;

// Reload configuration
client.signal(Signal::Reload).await?;

// Clear DNS cache
client.signal(Signal::ClearDnsCache).await?;

// Initiate graceful shutdown
client.signal(Signal::Shutdown).await?;
```

## Error Handling

All operations return `Result<T, TorControlError>`:

```rust
use tor_control::TorControlError;

match client.authenticate(&credential).await {
    Ok(()) => println!("Authenticated!"),
    Err(TorControlError::AuthenticationFailed(msg)) => {
        eprintln!("Auth failed: {}", msg);
    }
    Err(TorControlError::ConnectionClosed) => {
        eprintln!("Connection was closed");
    }
    Err(e) => eprintln!("Error: {}", e),
}
```

## Tor Configuration

To enable the control port in Tor, add to your `torrc`:

```
# Enable control port on TCP
ControlPort 9051

# Or use a Unix socket
#ControlSocket /run/tor/control

# Authentication options:
# No authentication (not recommended for production)
#CookieAuthentication 0

# Cookie authentication (recommended)
CookieAuthentication 1

# Or password authentication
#HashedControlPassword <hashed-password>
```

Generate a hashed password with:
```bash
tor --hash-password "your-password"
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `tokio-runtime` | ✓ | Enable async support using Tokio |

## Protocol Compatibility

This crate implements Tor Control Protocol version 1 as specified in the [Tor Control Specification](https://spec.torproject.org/control-spec/).

The version number (0.1.1.0) corresponds to the Tor version where the control protocol was last significantly changed, ensuring compatibility with modern Tor daemons.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related Projects

- [Tor Project](https://www.torproject.org/)
- [Tor Control Specification](https://spec.torproject.org/control-spec/)
