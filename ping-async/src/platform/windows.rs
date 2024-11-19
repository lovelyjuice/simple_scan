// platform/windows.rs
#![cfg(target_os = "windows")]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV6};
use std::process::exit;
use std::ptr::NonNull;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::channel::mpsc::UnboundedSender;
use log::debug;
use static_assertions::const_assert;
use windows::core::s;

use windows::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOLEAN, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::NetworkManagement::IpHelper::{ICMPV6_ECHO_REPLY_LH as ICMPV6_ECHO_REPLY, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE, IP_DEST_PORT_UNREACHABLE, IP_DEST_PROT_UNREACHABLE, IP_DEST_UNREACHABLE, IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TIME_EXCEEDED, IP_TTL_EXPIRED_REASSEM, IP_TTL_EXPIRED_TRANSIT};
use windows::Win32::Networking::WinSock::{IN6_ADDR, SOCKADDR_IN6};
use windows::Win32::System::Threading::{
    CreateEventW, RegisterWaitForSingleObject, UnregisterWaitEx, WT_EXECUTEINWAITTHREAD,
};
use windows::Win32::System::IO::IO_STATUS_BLOCK;

#[cfg(target_pointer_width = "32")]
use windows::Win32::NetworkManagement::IpHelper::ICMP_ECHO_REPLY;
#[cfg(target_pointer_width = "64")]
use windows::Win32::NetworkManagement::IpHelper::ICMP_ECHO_REPLY32 as ICMP_ECHO_REPLY;
#[cfg(target_pointer_width = "32")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION;
#[cfg(target_pointer_width = "64")]
use windows::Win32::NetworkManagement::IpHelper::IP_OPTION_INFORMATION32 as IP_OPTION_INFORMATION;

use crate::{
    IcmpEchoReply, IcmpEchoStatus, PING_DEFAULT_REQUEST_DATA_LENGTH, PING_DEFAULT_TIMEOUT,
    PING_DEFAULT_TTL,
};

type ise2ex = unsafe extern "system" fn(
    icmphandle: HANDLE,
    event: windows::Win32::Foundation::HANDLE,
    apcroutine: windows::Win32::System::IO::PIO_APC_ROUTINE,
    apccontext: ::core::option::Option<*const ::core::ffi::c_void>,
    sourceaddress: u32,
    destinationaddress: u32,
    requestdata: *const ::core::ffi::c_void,
    requestsize: u16,
    requestoptions: ::core::option::Option<*const IP_OPTION_INFORMATION>,
    replybuffer: *mut ::core::ffi::c_void,
    replysize: u32,
    timeout: u32
)-> u32;

type IcmpCloseHandleFn = unsafe extern "system" fn (icmphandle : HANDLE) -> windows::Win32::Foundation:: BOOL;
type IcmpCreateFileFn = unsafe extern "system" fn () -> HANDLE;
type IcmpParseRepliesFn= unsafe extern "system" fn (replybuffer : *mut ::core::ffi::c_void, replysize : u32) -> u32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyBufferState {
    Empty,
    Icmp4
}

const REPLY_BUFFER_SIZE: usize = 100;

// we don't provide request data, so we don't need to allocate space for it
const_assert!(
    size_of::<ICMP_ECHO_REPLY>()
        + PING_DEFAULT_REQUEST_DATA_LENGTH
        + 8
        + size_of::<IO_STATUS_BLOCK>()
        <= REPLY_BUFFER_SIZE
);
const_assert!(
    size_of::<ICMPV6_ECHO_REPLY>()
        + PING_DEFAULT_REQUEST_DATA_LENGTH
        + 8
        + size_of::<IO_STATUS_BLOCK>()
        <= REPLY_BUFFER_SIZE
);

struct ReplyContext {
    state: ReplyBufferState,
    buffer: Box<[u8]>,
    sender: Option<UnboundedSender<IcmpEchoReply>>,
    target: IpAddr,
    timeout: Duration,
}

impl ReplyContext {
    fn new(sender: UnboundedSender<IcmpEchoReply>, target: IpAddr, timeout: Duration) -> Self {
        ReplyContext {
            state: ReplyBufferState::Empty,
            buffer: vec![0u8; REPLY_BUFFER_SIZE].into_boxed_slice(),
            sender: Some(sender),
            target,
            timeout,
        }
    }

    fn buffer_state(&self) -> ReplyBufferState {
        self.state
    }

    fn buffer_ptr(&mut self) -> *mut u8 {
        self.buffer.as_mut_ptr() as *mut u8
    }

    fn buffer_size(&self) -> usize {
        self.buffer.len()
    }

    fn target(&self) -> IpAddr {
        self.target
    }

    fn timeout(&self) -> Duration {
        self.timeout
    }
}

pub struct IcmpEchoRequestor {
    handle: HANDLE,
    event: HANDLE,
    wait_object: HANDLE,
    target_addr: IpAddr,
    source_addr: Option<IpAddr>,
    ttl: u8,
    timeout: Duration,
    reply_context: NonNull<Arc<Mutex<ReplyContext>>>,
}

impl IcmpEchoRequestor {
    pub fn new(
        reply_tx: UnboundedSender<IcmpEchoReply>,
        target_addr: IpAddr,
        source_addr: Option<IpAddr>,
        ttl: Option<u8>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        let handle = match target_addr {
            IpAddr::V4(_) => unsafe { std::mem::transmute::<_,IcmpCreateFileFn>(GetProcAddress(LoadLibraryA(s!("Iphlpapi.dll")).unwrap(), s!("IcmpCreateFile")))() },
            IpAddr::V6(_) => {
                panic!("");
                HANDLE::default()
            },
        };
        assert!(!handle.is_invalid());

        let event = match unsafe { CreateEventW(None, false, false, None) } {
            Ok(event) => event,
            Err(e) => {
                let _ = unsafe { std::mem::transmute::<_,IcmpCloseHandleFn>(GetProcAddress(LoadLibraryA(s!("Iphlpapi.dll")).unwrap(), s!("IcmpCloseHandle")))(handle) };
                return Err(e.into());
            }
        };

        let ttl = ttl.unwrap_or(PING_DEFAULT_TTL);
        let timeout = timeout.unwrap_or(PING_DEFAULT_TIMEOUT);

        let reply_context = match NonNull::new(Box::into_raw(Box::new(Arc::new(Mutex::new(
            ReplyContext::new(reply_tx, target_addr, timeout),
        ))))) {
            Some(ptr) => ptr,
            None => {
                let _ = unsafe { std::mem::transmute::<_,IcmpCloseHandleFn>(GetProcAddress(LoadLibraryA(s!("Iphlpapi.dll")).unwrap(), s!("IcmpCloseHandle")))(handle) };
                return Err(io::ErrorKind::OutOfMemory.into());
            }
        };

        let mut new_handle = HANDLE::default();
        let wait_object = match unsafe {
            RegisterWaitForSingleObject(
                &mut new_handle as *mut _,
                event,
                Some(wait_callback),
                Some(reply_context.as_ptr() as *const _),
                timeout.as_millis() as u32,
                WT_EXECUTEINWAITTHREAD,
            )
        } {
            Ok(()) => new_handle,
            Err(e) => {
                let _ = unsafe { CloseHandle(event) };
                let _ = unsafe { std::mem::transmute::<_,IcmpCloseHandleFn>(GetProcAddress(LoadLibraryA(s!("Iphlpapi.dll")).unwrap(), s!("IcmpCloseHandle")))(handle) };
                return Err(e.into());
            }
        };

        Ok(IcmpEchoRequestor {
            handle,
            event,
            wait_object,
            target_addr,
            source_addr,
            ttl,
            timeout,
            reply_context,
        })
    }

    pub async fn send(&self) -> io::Result<()> {
        let mut ip_option = IP_OPTION_INFORMATION::default();
        ip_option.Ttl = self.ttl;

        let req_data = [0u8; PING_DEFAULT_REQUEST_DATA_LENGTH];

        let error = match self.target_addr {
            IpAddr::V4(taddr) => {
                let saddr = if let Some(saddr) = self.source_addr {
                    if let IpAddr::V4(s) = saddr {
                        s
                    } else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            String::from("source address must be an IPv4 address"),
                        ));
                    }
                } else {
                    Ipv4Addr::UNSPECIFIED
                };

                unsafe {
                    let mut ctx = self.reply_context.as_ref().lock().unwrap();

                    if ctx.state == ReplyBufferState::Empty {
                        ctx.state = ReplyBufferState::Icmp4;
                    }

                    std::mem::transmute::<_,ise2ex>(GetProcAddress(LoadLibraryA(s!("Iphlpapi.dll")).unwrap(), s!("IcmpSendEcho2Ex")))(
                        self.handle,
                        self.event,
                        None,
                        None,
                        u32::from(saddr).to_be(),
                        u32::from(taddr).to_be(),
                        req_data.as_ptr() as *const _,
                        req_data.len() as u16,
                        Some(&ip_option as *const _ as *const _),
                        ctx.buffer_ptr() as *mut _,
                        ctx.buffer_size() as u32,
                        self.timeout.as_millis() as u32,
                    )
                }
            }
            IpAddr::V6(taddr) => {
                panic!("Do not support ipv6!");
                exit(1);
                1
            }
        };

        if error == ERROR_IO_PENDING.0 {
            Ok(())
        } else {
            let code = unsafe { GetLastError() };
            if code == ERROR_IO_PENDING {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl Drop for IcmpEchoRequestor {
    fn drop(&mut self) {
        unsafe {
            if !self.wait_object.is_invalid() {
                if let Err(e) = UnregisterWaitEx(self.wait_object, INVALID_HANDLE_VALUE) {
                    debug!("failed to UnregisterWaitEx: {}", e);
                }
            }
            if !self.event.is_invalid() {
                if let Err(e) = CloseHandle(self.event) {
                    debug!("failed to CloseHandle: {}", e);
                }
            }
            if !self.handle.is_invalid() {
               std::mem::transmute::<_,IcmpCloseHandleFn>(GetProcAddress(LoadLibraryA(s!("Iphlpapi.dll")).unwrap(), s!("IcmpCloseHandle")))(self.handle);
                
            }

            drop(Box::from_raw(self.reply_context.as_ptr()));
        }
    }
}

fn ip_error_to_icmp_status(code: u32) -> IcmpEchoStatus {
    match code {
        IP_SUCCESS => IcmpEchoStatus::Success,
        IP_REQ_TIMED_OUT | IP_TIME_EXCEEDED | IP_TTL_EXPIRED_REASSEM | IP_TTL_EXPIRED_TRANSIT => {
            IcmpEchoStatus::TimedOut
        }
        IP_DEST_HOST_UNREACHABLE
        | IP_DEST_NET_UNREACHABLE
        | IP_DEST_PORT_UNREACHABLE
        | IP_DEST_PROT_UNREACHABLE
        | IP_DEST_UNREACHABLE => IcmpEchoStatus::Unreachable,
        _ => IcmpEchoStatus::Unknown,
    }
}

unsafe extern "system" fn wait_callback(ptr: *mut c_void, timer_fired: BOOLEAN) {
    let mut reply_context = (ptr as *mut Arc<Mutex<ReplyContext>>)
        .as_ref()
        .unwrap()
        .lock()
        .unwrap();

    let resp = if timer_fired.as_bool() {
        log::debug!("wait_callback timed out");
        IcmpEchoReply::new(
            reply_context.target(),
            IcmpEchoStatus::TimedOut,
            reply_context.timeout(),
        )
    } else {
        match reply_context.buffer_state() {
            ReplyBufferState::Empty => {
                log::debug!("event signalled with invalid empty state");
                return;
            }
            ReplyBufferState::Icmp4 => unsafe {
                let a= std::mem::transmute::<_,IcmpParseRepliesFn>(GetProcAddress(LoadLibraryA(s!("Iphlpapi.dll")).unwrap(), s!("IcmpParseReplies")));
                let ret = a(
                    reply_context.buffer_ptr() as *mut _,
                    reply_context.buffer_size() as u32,
                );

                if ret == 0 {
                    log::debug!("IcmpParseReplies failed: {}", io::Error::last_os_error());
                    return;
                } else {
                    debug_assert_eq!(ret, 1);

                    let resp = *(reply_context.buffer_ptr() as *const ICMP_ECHO_REPLY);
                    let addr = IpAddr::V4(u32::from_be(resp.Address).into());

                    IcmpEchoReply::new(
                        addr,
                        ip_error_to_icmp_status(resp.Status),
                        Duration::from_millis(resp.RoundTripTime.into()),
                    )
                }
            },

        }
    };

    match reply_context.sender.as_ref() {
        Some(sender) => {
            if let Err(e) = sender.unbounded_send(resp) {
                log::debug!("failed to send reply to channel: {}", e);
            }
        }
        None => {
            log::debug!("event signalled with no sender");
        }
    }
}
