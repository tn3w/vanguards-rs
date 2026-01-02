<h1 align="center">vanguards-rs</h1>

<h3 align="center">Enhanced security for Tor hidden services</h3>
<p align="center">
  Protect against guard discovery attacks with persistent vanguard relay selection
</p>

<p align="center">
  <a href="https://crates.io/crates/vanguards-rs">
    <img src="https://img.shields.io/crates/v/vanguards-rs?style=for-the-badge&logo=rust&logoColor=white&color=f74c00" alt="Crates.io">
  </a>
  <a href="https://vanguards.tn3w.dev/docs">
    <img src="https://img.shields.io/docsrs/vanguards-rs?style=for-the-badge&logo=docs.rs&logoColor=white" alt="docs.rs">
  </a>
  <a href="https://github.com/tn3w/vanguards-rs/blob/master/LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue?style=for-the-badge" alt="License">
  </a>
</p>

<p align="center">
  <a href="https://github.com/tn3w/vanguards-rs/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/tn3w/vanguards-rs/tests.yml?style=for-the-badge&logo=github&logoColor=white&label=CI" alt="CI">
  </a>
  <a href="https://github.com/tn3w/vanguards-rs">
    <img src="https://img.shields.io/github/stars/tn3w/vanguards-rs?style=for-the-badge&logo=github&logoColor=white" alt="Stars">
  </a>
</p>

<p align="center">
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-features">✨ Features</a> •
  <a href="#-examples">💡 Examples</a> •
  <a href="#-configuration">⚙️ Configuration</a>
</p>

## Overview

**vanguards-rs** is a Rust implementation of [vanguards](https://github.com/mikeperry-tor/vanguards), the Python addon for protecting Tor hidden services against guard discovery attacks. It provides the same security protections with Rust's safety guarantees and async-first design.

Even with Tor's v3 onion service protocol, hidden services face sophisticated attacks that require additional defenses. vanguards-rs implements these defenses as a controller addon, protecting your onion services ahead of their integration into Tor core.

```rust
use vanguards_rs::{Config, Vanguards};

#[tokio::main]
async fn main() -> vanguards_rs::Result<()> {
    // Load configuration and run protection
    let config = Config::default();
    let mut vanguards = Vanguards::from_config(config).await?;
    vanguards.run().await
}
```

## ✨ Features

<table>
<tr>
<td width="50%">

### 🛡️ Vanguard Selection

Persistent guard relay selection at multiple layers to prevent guard discovery attacks.

- **Layer 2 Guards** — 4-8 relays, 1-45 day lifetime
- **Layer 3 Guards** — 4-8 relays, 1-48 hour lifetime
- Bandwidth-weighted selection
- Automatic rotation and replenishment

</td>
<td width="50%">

### 📊 Bandwidth Monitoring

Detect bandwidth-based side-channel attacks through circuit analysis.

- Circuit size limits (configurable MB threshold)
- Circuit age monitoring (default 24 hours)
- HSDIR descriptor size limits
- Disconnection warnings

</td>
</tr>
<tr>
<td width="50%">

### 🎯 Rendezvous Point Analysis

Statistical detection of rendezvous point overuse attacks.

- Usage tracking per relay
- Bandwidth-weighted expected usage
- Configurable overuse thresholds
- Automatic circuit closure on detection

</td>
<td width="50%">

### 📝 Log Monitoring

Monitor Tor logs for security-relevant events.

- Protocol warning detection
- Configurable log buffering
- Security event alerting
- Integration with Tor's logging

</td>
</tr>
<tr>
<td width="50%">

### ⏱️ Circuit Build Timeout Verification

Verify circuit construction timing to detect manipulation.

- Track circuit build times
- Detect anomalous patterns
- Optional component (disabled by default)

</td>
<td width="50%">

### 🔍 Path Verification

Verify circuit paths conform to vanguard configuration.

- Ensure guards are used correctly
- Detect path manipulation
- Optional component (disabled by default)

</td>
</tr>
</table>

## 🚀 Quick Start

Add vanguards-rs to your `Cargo.toml`:

```toml
[dependencies]
vanguards-rs = "1"
tokio = { version = "1", features = ["full"] }
```

Or install the CLI:

```bash
cargo install vanguards-rs
```

### Enable Tor's Control Port

Add to your `torrc`:

```
ControlPort 9051
CookieAuthentication 1
DataDirectory /var/lib/tor
```

Or for Unix socket:

```
ControlSocket /run/tor/control
CookieAuthentication 1
DataDirectory /var/lib/tor
```

### Run vanguards-rs

```bash
# Connect to default control port (127.0.0.1:9051)
vanguards-rs

# Connect via Unix socket
vanguards-rs --control-socket /run/tor/control

# Generate default configuration file
vanguards-rs --generate_config vanguards.conf

# Use custom configuration
vanguards-rs --config vanguards.conf
```

## 💡 Examples

### Basic CLI Usage

```bash
# Run with default settings
vanguards-rs

# Connect to specific control port
vanguards-rs --control-ip 127.0.0.1 --control-port 9051

# Use Unix socket with custom state file
vanguards-rs --control-socket /run/tor/control --state /var/lib/tor/vanguards.state

# One-shot mode: set vanguards and exit
vanguards-rs --one-shot-vanguards

# Enable debug logging
vanguards-rs --loglevel DEBUG

# Log to file
vanguards-rs --logfile /var/log/vanguards.log
```

### Component Control

```bash
# Disable specific components
vanguards-rs --disable-bandguards --disable-logguard

# Enable optional components
vanguards-rs --enable-cbtverify --enable-pathverify
```

### Library Usage

```rust
use vanguards_rs::{Config, Vanguards, LogLevel};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> vanguards_rs::Result<()> {
    // Create custom configuration
    let mut config = Config::default();
    config.control_port = Some(9051);
    config.loglevel = LogLevel::Debug;
    config.state_file = PathBuf::from("/var/lib/tor/vanguards.state");

    // Enable optional components
    config.enable_cbtverify = true;
    config.enable_pathverify = true;

    // Validate configuration
    config.validate()?;

    // Run vanguards protection
    let mut vanguards = Vanguards::from_config(config).await?;
    vanguards.run().await
}
```

### Loading Configuration from File

```rust
use vanguards_rs::Config;
use std::path::Path;

let config = Config::from_file(Path::new("vanguards.conf"))?;
```

## ⚙️ Configuration

Configuration can be loaded from multiple sources (in order of precedence):

1. **CLI Arguments** — Highest priority
2. **Environment Variables** — `VANGUARDS_STATE`, `VANGUARDS_CONFIG`
3. **Config File** — TOML format
4. **Defaults** — Sensible defaults for all options

### Example Configuration File

```toml
# Connection settings
control_ip = "127.0.0.1"
control_port = 9051
# control_socket = "/run/tor/control"  # Alternative: Unix socket
# control_pass = "my_password"         # If using password auth

# File paths
state_file = "vanguards.state"

# Logging
loglevel = "notice"  # debug, info, notice, warn, error
# logfile = "/var/log/vanguards.log"

# Component toggles
enable_vanguards = true
enable_bandguards = true
enable_rendguard = true
enable_logguard = true
enable_cbtverify = false
enable_pathverify = false

# Operational settings
close_circuits = true
one_shot_vanguards = false

[vanguards]
num_layer1_guards = 2
num_layer2_guards = 4
num_layer3_guards = 8
min_layer2_lifetime_hours = 24
max_layer2_lifetime_hours = 1080  # 45 days
min_layer3_lifetime_hours = 1
max_layer3_lifetime_hours = 48

[bandguards]
circ_max_megabytes = 0           # 0 = disabled
circ_max_age_hours = 24
circ_max_hsdesc_kilobytes = 30
circ_max_disconnected_secs = 30
conn_max_disconnected_secs = 15

[rendguard]
use_global_start_count = 1000
use_scale_at_count = 20000
use_relay_start_count = 100
use_max_use_to_bw_ratio = 5.0
close_circuits_on_overuse = true

[logguard]
protocol_warns = true
dump_limit = 25
dump_level = "notice"
```

## 📦 Module Reference

| Module                                                                               | Description                                        |
| ------------------------------------------------------------------------------------ | -------------------------------------------------- |
| [`api`](https://vanguards.tn3w.dev/docs/api/)                       | High-level `Vanguards` struct for programmatic use |
| [`config`](https://vanguards.tn3w.dev/docs/config/)                 | Configuration management (TOML, CLI, environment)  |
| [`control`](https://vanguards.tn3w.dev/docs/control/)               | Main event loop and Tor connection management      |
| [`vanguards`](https://vanguards.tn3w.dev/docs/vanguards/)           | Vanguard state and guard selection                 |
| [`bandguards`](https://vanguards.tn3w.dev/docs/bandguards/)         | Bandwidth monitoring and attack detection          |
| [`rendguard`](https://vanguards.tn3w.dev/docs/rendguard/)           | Rendezvous point usage tracking                    |
| [`logguard`](https://vanguards.tn3w.dev/docs/logguard/)             | Tor log monitoring and buffering                   |
| [`cbtverify`](https://vanguards.tn3w.dev/docs/cbtverify/)           | Circuit build timeout verification                 |
| [`pathverify`](https://vanguards.tn3w.dev/docs/pathverify/)         | Circuit path verification                          |
| [`node_selection`](https://vanguards.tn3w.dev/docs/node_selection/) | Bandwidth-weighted relay selection                 |

## 🔒 Security

vanguards-rs is designed with security as a priority:

- **Memory Safety** — Passwords cleared after use (zeroize)
- **File Permissions** — State files written with 0600 permissions
- **Input Validation** — All external inputs validated
- **Atomic Writes** — State file corruption prevention
- **Guard Persistence** — Prevents restart-based guard discovery

## ⚡ Performance

- **Async-first** — Built on Tokio for high-performance async I/O
- **Efficient State** — Python pickle format for compatibility
- **Low Overhead** — Minimal CPU usage during normal operation

## 🔄 Python Compatibility

State files are compatible with Python vanguards for seamless migration:

```bash
# Migrate from Python vanguards
cp ~/.vanguards/vanguards.state ./vanguards.state
vanguards-rs --state vanguards.state
```

## 🛠️ Requirements

- **Rust** 1.70+
- **Tokio** runtime
- **Tor** instance with control port enabled

## 🧪 Testing

```bash
# Run unit tests
cargo test
```

## 📊 Comparison with Python vanguards

| Feature              | Python vanguards | vanguards-rs |
| -------------------- | ---------------- | ------------ |
| Vanguard Selection   | ✅               | ✅           |
| Bandwidth Monitoring | ✅               | ✅           |
| Rendezvous Analysis  | ✅               | ✅           |
| Log Monitoring       | ✅               | ✅           |
| CBT Verification     | ✅               | ✅           |
| Path Verification    | ✅               | ✅           |
| State Compatibility  | ✅               | ✅           |
| Type Safety          | ❌               | ✅           |
| Memory Safety        | ❌               | ✅           |
| Async/Await          | ❌               | ✅           |

## 📄 License

Copyright 2026 vanguards-rs contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 🔗 Links

<p align="center">
  <a href="https://vanguards.tn3w.dev/docs">Documentation</a> •
  <a href="https://crates.io/crates/vanguards-rs">crates.io</a> •
  <a href="https://github.com/tn3w/vanguards-rs">GitHub</a> •
  <a href="https://github.com/mikeperry-tor/vanguards">Python vanguards</a>
</p>

<p align="center">
  <sub>Built with 🦀 by the vanguards-rs contributors</sub>
</p>
