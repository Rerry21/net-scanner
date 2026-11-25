# Net Scanner

A network reconnaissance and analysis toolkit written in Rust. It started as a simple TCP port check and is being built up step by step into a full scanner with host discovery, service detection, and reporting.

## Authorized use only

Only scan systems and networks you own or have explicit permission to test. Scanning without authorization may be illegal.

## Status

In active development. Built step by step.

- [x] Project setup (Cargo, build toolchain)
- [x] TCP connect check on a single host and port
- [ ] CLI with argument parsing and target validation
- [ ] Concurrent (async) port scanning
- [ ] CIDR scanning and host discovery
- [ ] Service detection and banner grabbing
- [ ] DNS, HTTP and TLS analysis
- [ ] UDP scanning
- [ ] OS and device fingerprinting
- [ ] JSON/CSV reports and scan history
- [ ] Custom detection rules and plugins
- [ ] Web dashboard
- [ ] Tests and benchmarks

## Tech stack

**Language:** Rust (standard library only for now)

**Planned crates:** clap, tokio, serde, tracing, axum

## Project structure

```
net-scanner/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs
```

## Getting started

**Requirements:** [Rust](https://rustup.rs). On Windows you also need the *Desktop development with C++* workload from [Build Tools for Visual Studio](https://aka.ms/vs/17/release/vs_BuildTools.exe).

```bash
git clone https://github.com/<your-username>/net-scanner.git
cd net-scanner
cargo run -- <host> <port>
```

Example:

```bash
cargo run -- 127.0.0.1 8080
# 127.0.0.1:8080 -> Open (0 ms)
```

## How it works

`src/main.rs` currently does four things:

1. **Reads the arguments.** `main()` calls `run()`, which expects a host and a port. A missing or invalid port (anything outside 0-65535) prints an error and exits with code 1.
2. **Resolves the host.** A hostname or IP is turned into a socket address, using DNS if needed.
3. **Tries to connect.** `check_port()` opens a TCP connection with a 3-second timeout.
4. **Classifies the result** as a `PortState`:

| State | Meaning |
|---|---|
| Open | The TCP handshake completed |
| Closed | The host actively refused the connection |
| Filtered | No response before the timeout (often a firewall) |

## Development

```bash
cargo fmt      # format
cargo clippy   # lint
cargo test     # run tests
```

## License

MIT LICENSE