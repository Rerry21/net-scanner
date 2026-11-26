mod ports;
mod target;

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};

use ports::PortSpec;
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
    #[command(about = "Check which TCP ports are open on one or more targets")]
    Scan {
        #[arg(help = "IP, hostname, CIDR (192.168.1.0/24) or range (192.168.1.10-50)")]
        target: Target,

        #[arg(
            short,
            long,
            alias = "port",
            default_value = "80",
            help = "Ports: 80 | 22,80,443 | 1-1024 | top100 | all"
        )]
        ports: PortSpec,

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

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            ports,
            timeout,
        } => run_scan(&target, &ports, Duration::from_millis(timeout)),
    }
}

fn run_scan(target: &Target, ports: &PortSpec, timeout: Duration) -> Result<()> {
    let ips = target.addresses()?;
    println!(
        "Scanning {target}: {} address(es), {} port(s)",
        ips.len(),
        ports.ports().len()
    );

    for ip in ips {
        let (mut open, mut closed, mut filtered) = (0u32, 0u32, 0u32);

        for &port in ports.ports() {
            let addr = SocketAddr::new(ip, port);
            let started = Instant::now();
            match check_port(addr, timeout) {
                PortState::Open => {
                    open += 1;
                    println!("{addr} -> Open ({} ms)", started.elapsed().as_millis());
                }
                PortState::Closed => closed += 1,
                PortState::Filtered => filtered += 1,
            }
        }

        println!("{ip}: {open} open, {closed} closed, {filtered} filtered");
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