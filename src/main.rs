use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "net-scanner",
    version,
    about = "Net Scanner: network reconnaissance toolkit (authorized use only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Check whether a TCP port is open on a target host")]
    Scan {
        #[arg(help = "Hostname or IP address to scan")]
        target: String,

        #[arg(short, long, default_value_t = 80, help = "Port to check")]
        port: u16,

        #[arg(
            short,
            long,
            default_value_t = 3000,
            help = "Connection timeout in milliseconds"
        )]
        timeout: u64,
    },
}

#[derive(Debug)]
enum PortState {
    Open,
    Closed,
    Filtered,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Scan {
            target,
            port,
            timeout,
        } => run_scan(&target, port, Duration::from_millis(timeout)),
    };

    if let Err(message) = result {
        eprintln!("error: {message}");
        process::exit(1);
    }
}

fn run_scan(target: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let addr = resolve(target, port)?;

    let started = Instant::now();
    let state = check_port(addr, timeout);
    let elapsed = started.elapsed();

    println!("{addr} -> {state:?} ({} ms)", elapsed.as_millis());
    Ok(())
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, String> {
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve '{host}': {e}"))?
        .next()
        .ok_or_else(|| format!("no address found for '{host}'"))
}

fn check_port(addr: SocketAddr, timeout: Duration) -> PortState {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => PortState::Open,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => PortState::Closed,
        Err(_) => PortState::Filtered,
    }
}
