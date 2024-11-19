// lib.rs

mod platform;
pub use platform::IcmpEchoRequestor;

use std::net::IpAddr;
use std::time::Duration;

pub const PING_DEFAULT_TTL: u8 = 128;
pub const PING_DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
pub const PING_DEFAULT_REQUEST_DATA_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpEchoStatus {
    Success,
    TimedOut,
    Unreachable,
    Unknown,
}

impl IcmpEchoStatus {
    pub fn ok(self) -> Result<(), String> {
        match self {
            Self::Success => Ok(()),
            Self::TimedOut => Err("Timed out".to_string()),
            Self::Unreachable => Err("Destination unreachable".to_string()),
            Self::Unknown => Err("Unknown error".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpEchoReply {
    destination: IpAddr,
    status: IcmpEchoStatus,
    round_trip_time: Duration,
}

impl IcmpEchoReply {
    pub fn new(destination: IpAddr, status: IcmpEchoStatus, round_trip_time: Duration) -> Self {
        Self {
            destination,
            status,
            round_trip_time,
        }
    }

    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    pub fn status(&self) -> IcmpEchoStatus {
        self.status
    }

    pub fn round_trip_time(&self) -> Duration {
        self.round_trip_time
    }
}

#[cfg(test)]
mod tests {
    use futures::{channel::mpsc, StreamExt};
    use std::io;

    use super::*;

    #[tokio::test]
    async fn ping_localhost_v4() -> io::Result<()> {
        let (tx, mut rx) = mpsc::unbounded();

        let pinger = IcmpEchoRequestor::new(tx, "127.0.0.1".parse().unwrap(), None, None, None)?;
        pinger.send().await?;
        rx.next().await;

        Ok(())
    }

    #[tokio::test]
    async fn ping_localhost_v6() -> io::Result<()> {
        let (tx, mut rx) = mpsc::unbounded();

        let pinger = IcmpEchoRequestor::new(tx, "::1".parse().unwrap(), None, None, None)?;
        pinger.send().await?;
        rx.next().await;

        Ok(())
    }
}
