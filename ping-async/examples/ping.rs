// examples/ping.rs

use std::io;
use std::net::IpAddr;
use std::time::Duration;

use futures::{channel::mpsc, StreamExt};
use ping_async::IcmpEchoRequestor;

use tokio::time;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: ping <destination>");
        std::process::exit(1);
    }

    let destination = args[1].parse().unwrap();
    let _ = ping(destination, 4).await;
}

async fn ping(dest: IpAddr, times: usize) -> io::Result<()> {
    let (tx, mut rx) = mpsc::unbounded();

    let pinger = match IcmpEchoRequestor::new(tx, dest, None, None, None) {
        Ok(req) => req,
        Err(e) => {
            eprintln!("Error in new: {}", e);
            return Err(e);
        }
    };

    for _ in 0..times {
        if let Err(e) = pinger.send().await {
            eprintln!("Error in send: {}", e);
            return Err(e);
        }

        match rx.next().await {
            Some(reply) => {
                println!(
                    "Reply from {}: status = {:?}, time = {:?}",
                    reply.destination(),
                    reply.status(),
                    reply.round_trip_time()
                );
            }
            None => {
                eprintln!("channel is closed.");
            }
        }

        time::sleep(Duration::from_secs(1)).await;
    }

    Ok(())
}
