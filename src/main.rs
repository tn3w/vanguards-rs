//! vanguards-rs CLI application entry point.
//!
//! This binary provides a command-line interface for running vanguards-rs
//! as a standalone application to protect Tor hidden services.
//!
//! # Overview
//!
//! The vanguards-rs CLI is the primary way to run vanguards protection for
//! Tor hidden services. It handles configuration loading, logging setup,
//! and runs the main protection loop.
//!
//! # Startup Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    vanguards-rs Startup Flow                    │
//! └─────────────────────────────────────────────────────────────────┘
//!
//!   ┌─────────────────┐
//!   │  Parse CLI Args │ ◄── clap parses command-line arguments
//!   └────────┬────────┘
//!            │
//!            ▼
//!   ┌─────────────────┐       ┌─────────────────┐
//!   │ --generate_config│────▶│ Write default   │────▶ Exit
//!   │    specified?   │       │ config & exit   │
//!   └────────┬────────┘       └─────────────────┘
//!            │ No
//!            ▼
//!   ┌─────────────────┐
//!   │  Load Config    │ ◄── Defaults → File → CLI → Env
//!   └────────┬────────┘
//!            │
//!            ▼
//!   ┌─────────────────┐
//!   │ Initialize      │ ◄── Set up tracing subscriber
//!   │   Logging       │
//!   └────────┬────────┘
//!            │
//!            ▼
//!   ┌─────────────────┐
//!   │ Log Startup     │ ◄── Version, config, enabled components
//!   │   Info          │
//!   └────────┬────────┘
//!            │
//!            ▼
//!   ┌─────────────────┐
//!   │ Run Main Loop   │ ◄── control::run_main()
//!   │ (control.rs)    │
//!   └────────┬────────┘
//!            │
//!            ▼
//!   ┌─────────────────┐
//!   │  Exit with      │
//!   │  status code    │
//!   └─────────────────┘
//! ```
//!
//! # Usage Examples
//!
//! ## Basic Usage
//!
//! ```bash
//! # Run with default settings (connects to 127.0.0.1:9051)
//! vanguards-rs
//!
//! # Connect to specific control port
//! vanguards-rs --control-ip 127.0.0.1 --control-port 9051
//!
//! # Connect via Unix socket
//! vanguards-rs --control-socket /run/tor/control
//! ```
//!
//! ## Configuration
//!
//! ```bash
//! # Generate default configuration file
//! vanguards-rs --generate_config vanguards.conf
//!
//! # Use custom configuration file
//! vanguards-rs --config /etc/vanguards/vanguards.conf
//!
//! # Override config with CLI arguments
//! vanguards-rs --config vanguards.conf --loglevel DEBUG
//! ```
//!
//! ## State Management
//!
//! ```bash
//! # Use custom state file
//! vanguards-rs --state /var/lib/tor/vanguards.state
//!
//! # One-shot mode: set vanguards and exit
//! vanguards-rs --one-shot-vanguards
//! ```
//!
//! ## Component Control
//!
//! ```bash
//! # Disable specific components
//! vanguards-rs --disable-bandguards --disable-logguard
//!
//! # Enable optional components
//! vanguards-rs --enable-cbtverify --enable-pathverify
//! ```
//!
//! ## Logging
//!
//! ```bash
//! # Set log level
//! vanguards-rs --loglevel DEBUG
//!
//! # Log to file
//! vanguards-rs --logfile /var/log/vanguards.log
//!
//! # Log to syslog
//! vanguards-rs --logfile :syslog:
//! ```
//!
//! # Exit Codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0 | Success |
//! | 1 | Error (see stderr for details) |
//!
//! # Environment Variables
//!
//! | Variable | Description |
//! |----------|-------------|
//! | `VANGUARDS_STATE` | Path to state file (equivalent to `--state`) |
//! | `VANGUARDS_CONFIG` | Path to config file (equivalent to `--config`) |
//!
//! # See Also
//!
//! - [`CliArgs`](crate::CliArgs) - Command-line argument definitions
//! - [`Config`](crate::Config) - Configuration structure
//! - [`control::run_main`](crate::control::run_main) - Main event loop

use clap::Parser;
use std::process::ExitCode;

use vanguards_rs::{config, control, logger, CliArgs, Config, LogLevel};

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}

async fn run() -> vanguards_rs::Result<()> {
    let args = CliArgs::parse();

    // Handle --generate_config
    if let Some(ref output_path) = args.generate_config {
        let config = Config::default();
        let toml = config.to_toml()?;
        std::fs::write(output_path, toml)?;
        println!("Wrote default config to {}", output_path.display());
        return Ok(());
    }

    // Load configuration
    let config = config::load_config(&args)?;

    // Initialize logging
    logger::init(config.loglevel, config.logfile.as_deref())?;

    logger::plog(
        LogLevel::Notice,
        &format!("vanguards-rs {} starting", control::VERSION),
    );
    logger::plog(
        LogLevel::Debug,
        &format!("Control IP: {}", config.control_ip),
    );
    logger::plog(
        LogLevel::Debug,
        &format!("State file: {}", config.state_file.display()),
    );

    if config.enable_vanguards {
        logger::plog(LogLevel::Info, "Vanguard selection enabled");
    }
    if config.enable_bandguards {
        logger::plog(LogLevel::Info, "Bandwidth monitoring enabled");
    }
    if config.enable_rendguard {
        logger::plog(LogLevel::Info, "Rendezvous point monitoring enabled");
    }
    if config.enable_logguard {
        logger::plog(LogLevel::Info, "Log monitoring enabled");
    }
    if config.enable_cbtverify {
        logger::plog(LogLevel::Info, "Circuit build timeout verification enabled");
    }
    if config.enable_pathverify {
        logger::plog(LogLevel::Info, "Path verification enabled");
    }

    logger::plog(LogLevel::Notice, "Configuration loaded successfully");

    // Run the main control loop
    control::run_main(config).await
}
