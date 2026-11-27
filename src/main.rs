mod ports;
mod scanner;
mod target;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Parser, Subcommand};

use ports::PortSpec;
use scanner::{PortResult, PortState, ScanConfig};
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

        #[arg(
            short,
            long,
            default_value_t = 1,
            help = "Extra attempts for ports that time out"
        )]
        retries: u32,

        #[arg(
            short = 'j',
            long,
            default_value_t = 1,
            value_parser = clap::value_parser!(u16).range(1..=512),
            help = "Parallel worker threads (1-512)"
        )]
        threads: u16,

        #[arg(short, long, help = "Also list closed and filtered ports")]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            target,
            ports,
            timeout,
            retries,
            threads,
            verbose,
        } => {
            let config = ScanConfig {
                timeout: Duration::from_millis(timeout),
                retries,
                threads: usize::from(threads),
            };
            run_scan(&target, &ports, config, verbose)
        }
    }
}

fn run_scan(target: &Target, ports: &PortSpec, config: ScanConfig, verbose: bool) -> Result<()> {
    let ips = target.addresses()?;
    println!(
        "Scanning {target}: {} address(es), {} port(s), {} thread(s)",
        ips.len(),
        ports.ports().len(),
        config.threads
    );

    let started = Instant::now();

    for ip in ips {
        let results = scanner::scan_host(ip, ports.ports(), config);
        print_report(ip, &results, verbose);
    }

    println!("\nScan finished in {:.2} s", started.elapsed().as_secs_f64());
    Ok(())
}

fn ms(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn print_report(ip: IpAddr, results: &[PortResult], verbose: bool) {
    println!("\nHost {ip}");
    println!(
        "{:<7} {:<9} {:<24} {:>5} {:>10}",
        "PORT", "STATE", "REASON", "TRIES", "TIME"
    );

    for result in results
        .iter()
        .filter(|r| verbose || r.state == PortState::Open)
    {
        println!(
            "{:<7} {:<9} {:<24} {:>5} {:>7.1} ms",
            result.addr.port(),
            result.state,
            result.reason,
            result.attempts,
            ms(result.elapsed)
        );
    }

    let count = |state: PortState| results.iter().filter(|r| r.state == state).count();
    println!(
        "{} open, {} closed, {} filtered",
        count(PortState::Open),
        count(PortState::Closed),
        count(PortState::Filtered)
    );

    if let Some(latency) = scanner::open_latency(results) {
        println!(
            "Open-port latency: min {:.1} ms, avg {:.1} ms, max {:.1} ms",
            ms(latency.min),
            ms(latency.avg),
            ms(latency.max)
        );
    }
}