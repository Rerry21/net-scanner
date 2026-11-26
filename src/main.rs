mod target;

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::process;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};

use target::Target;

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
    #[command(about = "Check whether a TCP port is open on one or more targets")]
    Scan {
        #[arg(help = "IP, hostname, CIDR (192.168.1.0/24) or range (192.168.1.10-50)")]
        target: Target,

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

fn run_scan(target: &Target, port: u16, timeout: Duration) -> Result<(), String> {
    let ips = target.addresses()?;
    println!(
        "Scanning {target} on port {port} ({} address(es))",
        ips.len()
    );

    for ip in ips {
        let addr = SocketAddr::new(ip, port);
        let started = Instant::now();
        let state = check_port(addr, timeout);
        println!("{addr} -> {state:?} ({} ms)", started.elapsed().as_millis());
    }
    Ok(())
}

fn check_port(addr: SocketAddr, timeout: Duration) -> PortState {
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => PortState::Open,
        Err(e) if e.kind() == ErrorKind::ConnectionRefused => PortState::Closed,
        Err(_) => PortState::Filtered,
    }
}
