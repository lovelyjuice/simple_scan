// platform/mod.rs

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use self::windows::IcmpEchoRequestor;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod socket;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use self::socket::IcmpEchoRequestor;
