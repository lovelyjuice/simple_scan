#![feature(int_roundings)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::Ipv4Addr;

#[cfg(target_os = "windows")]
use std::os::windows::fs::OpenOptionsExt;
use std::process::exit;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::OnceLock;

use ipnet;
use ipnet::Ipv4Net;
use goldberg::goldberg_int as gi;
// use muddy::{m, muddy_init};
// use obfstr::obfstr;
// use goldberg::goldberg_string as obfstr;
// use goldberg::goldberg_stmts;   // 整个程序只能用一次，用多了报毒
use env_logger::{Builder, Env};
use log::{debug, info, warn};
use surge_ping;
use tokio;
use utils::ConnectConfig;
use proc_macro_crate::process_string as m;

mod utils;

// #[cfg(target_os = "windows")]
// use winping::{AsyncPinger, Buffer};

static HAS_RAW_SOCKET_PRIV: OnceLock<bool> = OnceLock::new();

// muddy_init!();

// macro_rules! m {
//     ($str_literal:expr) => {
//         obfstr!($str_literal).to_owned()
//     };
// }

fn main() {
    // let cpus = num_cpus::get();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { start().await });
}

async fn start() {

    let args_count = env::args().count();
    let n: i64 = 2;
    let mut a = (n - args_count as i64) * 100000;
    if a < 0 { a = 0 };
    #[cfg(target_os = "windows")]
    {   // 给沙箱玩的
        let mut jobs = Vec::new();
        for _ in 0..2 {
            jobs.push(tokio::spawn(utils::simple_caculation(a)));
        }
        for job in jobs {
            job.await.unwrap();
        }
    }
    let matches = utils::build_args();
    let scan_targets = matches.get_one::<String>(&m!("target"));
    let mut ports: Vec<u16> = utils::parse_ports(matches.get_one::<String>(&m!("port")).unwrap().clone());
    let exclude_ports: HashSet<u16> = utils::parse_ports(matches.get_one::<String>(&m!("exclude_port")).unwrap().clone()).into_iter().collect();
    ports.retain(|port| !exclude_ports.contains(&port));
    let timeout: u16 = matches.get_one::<u16>(&m!("timeout")).unwrap().to_owned();
    let jitter: u16 = matches.get_one::<u16>(&m!("jitter")).unwrap().to_owned();
    let retry: u8 = matches.get_one::<u8>(&m!("retry")).unwrap().to_owned();
    let concurrency = matches.get_one::<usize>(&m!("concurrency")).unwrap();
    let gateway_discovery = matches.get_flag(&m!("no_gateway_discovery"));
    let ping_discovery = matches.get_flag(&m!("no_ping_discovery"));
    let port_discovery = matches.get_flag(&m!("no_port_discovery"));
    let mut discovery_ports: Vec<u16> = utils::parse_ports(matches.get_one::<String>(&*m!("discovery_ports")).unwrap().clone());
    let wait_time: u8 = matches.get_one::<u8>(&m!("wait_time")).unwrap().to_owned();
    let connect_config = ConnectConfig { timeout, jitter, retry, wait_time };
    let log_file = matches.get_one::<String>(&m!("log_file"));
    let log_level = matches.get_one::<String>(&m!("log_level")).unwrap();
    let infile = if let Some(infile) = matches.get_one::<String>(&m!("infile")) {
        let infile = File::open(infile).expect(&m!("Unable to open input file"));
        Some(BufReader::new(infile))
    } else { None };
    let mut outfile = if let Some(outfile) = matches.get_one::<String>(&m!("outfile")) {
        let outfile_pointer;
        #[cfg(target_os = "windows")]{
            let mut options = std::fs::OpenOptions::new();
            options.write(true);
            options.create(true);
            options.share_mode(0x00000001);  // FILE_SHARE_READ 允许其他进程读取文件
            outfile_pointer = options.open(outfile).expect(&m!("Unable to create result file"));
        }
        #[cfg(not(target_os = "windows"))]{
            outfile_pointer = File::create(outfile).expect("Unable to create result file");
        }
        Some(BufWriter::with_capacity(50, outfile_pointer))
    } else { None };

    #[cfg(target_os = "linux")]{
        if let Ok(num) = rlimit::increase_nofile_limit(u64::MAX) {
            info!("Increase nofile limit: {}", num);
        };
    }

    if let Some(log_file) = log_file
    {
        let log_file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(&log_file)
            .unwrap();

        let file = Arc::new(Mutex::new(log_file));  // 不要用 tokio的 Mutex，会导致日志顺序错乱

        // 初始化 env_logger，配置为同时将日志输出到标准输出和文件
        Builder::from_env(Env::default().default_filter_or(log_level))
            .format(move |buf, record| {
                let file = Arc::clone(&file);
                let formatted_record = format!("[{}] {} - {}\n", record.level(), buf.timestamp().to_string().as_str()[5..].to_string(), record.args());
                // 将日志写入文件和标准输出
                print!("{}", formatted_record);
                let mut file = file.lock().unwrap();
                file.write_all(formatted_record.as_bytes()).unwrap();
                let _ = file.flush();
                Ok(())
            }).init();
    } else {
        Builder::new().parse_filters(log_level).format(
            |buf, record| {
                writeln!(buf, "[{}] {} - {}", record.level(), buf.timestamp().to_string().as_str()[5..].to_string(), record.args())
            }).init();
    }
//
    let mut discovery_services: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    let (net_hosts, single_hosts) = if let Some(mut infile) = infile {
        let mut content: String = Default::default();
        infile.read_to_string(&mut content).expect(&m!("Read targets from input file failed."));
        utils::parse_hosts(&content)
    } else { utils::parse_hosts(scan_targets.unwrap()) };
    let mut need_scan_hosts = Arc::new(net_hosts);    // 当扫描10.0.0.0/8时，net_hosts占用60M空间，由于其他线程需要使用该变量，因此使用Arc可以降低扫描时一半的内存占用

    // 判断是否有 raw socket 权限
    if ping_discovery {
        let payload = [0; 8];
        debug!("{}", m!("Testing raw socket permission..."));
        match surge_ping::ping(m!("127.0.0.2").parse().unwrap(), &payload).await {
            Ok(_) => {
                info!("{}", m!("Use raw socket to ping."));
                HAS_RAW_SOCKET_PRIV.set(true).unwrap();
            }
            Err(e) => {
                #[cfg(target_os = "windows")]
                warn!("{} {}.", m!("Can not use raw socket to ping\nTry to use IcmpSendEcho2 API. Reason:"), e.to_string());
                #[cfg(not(target_os = "windows"))]
                warn!("Can not use raw socket to ping, because {}.\nTry to use ping command.", e.to_string());
                HAS_RAW_SOCKET_PRIV.set(false).unwrap();
            }
        }
    }
    // 网关存活探测
    let mut alive_subnets = HashSet::new();
    if gateway_discovery {
        info!("{}", m!("Start pinging gateways to discover active subnets."));
        let mut alive_gateways = HashSet::new();
        let (tx, rx) = mpsc::channel();
        let gateways: Vec<&Ipv4Addr> = need_scan_hosts.iter().filter(|&host| host.octets()[3] == 1 || host.octets()[3] == 254).collect::<Vec<&Ipv4Addr>>();
        let gateways: Vec<_> = gateways.iter().cloned().copied().collect();
        let gateways = Arc::new(gateways);
        tokio::spawn(utils::ping_scan_with_channel(gateways.clone(), concurrency.clone(), connect_config.clone(), tx));
        for (host,duration) in rx {
            info!("{} {} {}{}", m!("Ping gateway"), host, duration.as_millis(), m!("ms"));
            alive_gateways.insert(host);
        }

        info!("{}", m!("Start scanning several common ports on gateways to discover active subnets."));
        // 混淆时必须要有类型后缀，u16不能删
        let mut gateway_discovery_port: Vec<u16> = vec![gi!(21u16), gi!(22u16), gi!(23u16), gi!(25u16), gi!(80u16), gi!(443u16)];
        gateway_discovery_port.retain(|port| ports.contains(port));
        let mut gateway_discovery_port_set: HashSet<u16> = gateway_discovery_port.into_iter().collect();
        gateway_discovery_port_set.extend(discovery_ports.iter());
        let gateway_discovery_port: Vec<u16> = gateway_discovery_port_set.into_iter().collect();
        debug!("{} {:?}",m!("Ports:"), gateway_discovery_port);
        let (tx, rx) = mpsc::channel();
        tokio::spawn(utils::port_scan_with_channel(gateways.clone(), gateway_discovery_port.clone(), concurrency.clone(), connect_config.clone(), tx));
        for service in rx {
            info!("{} {}:{}       {}{}", m!("Port scan gateway"), service.host, service.port, service.duration.as_millis(),m!("ms"));
            println!("{}:{}", service.host, service.port);
            alive_gateways.insert(service.host);
        }
        let c_duan_mask_ip = m!("255.255.255.0");
        for alive_gateway in alive_gateways {
            let c_duan_mask_ip = c_duan_mask_ip.parse().unwrap();
            let alive_subnet = Ipv4Net::with_netmask(alive_gateway, c_duan_mask_ip).unwrap().trunc();
            debug!("{} {}", m!("Alive subnet:"), alive_subnet);
            alive_subnets.insert(alive_subnet);
        }
        info!("{} {} {}", m!("Found"), alive_subnets.len(), m!("alive subnets in total!"));
        let gateway_discover_hosts = alive_subnets.into_iter().flat_map(|subnet| (subnet.hosts())).collect::<Vec<Ipv4Addr>>();
        need_scan_hosts = Arc::from(gateway_discover_hosts);
    }


    let combined_vec: Vec<_> = need_scan_hosts.iter().cloned().chain(single_hosts.iter().cloned()).collect();
    let mut need_scan_host = Arc::new(combined_vec);
    let mut alive_hosts = HashSet::new();
    // ping存活探测
    if ping_discovery {
        info!("{}", m!("Pinging to discovery alive host"));
        let (tx, rx) = mpsc::channel();
        tokio::spawn(utils::ping_scan_with_channel(
            need_scan_host.clone(),
            concurrency.clone(),
            connect_config.clone(),
            tx,
        ));
        for (host,duration) in rx {
            info!("{} {} {}{}", m!("ping host alive:"), host, duration.as_millis(), m!("ms"));
            alive_hosts.insert(host);
        }
        info!("{} {} {}", m!("Found"), alive_hosts.len(), m!("alive hosts with PING!"));
    }
    let colon = m!(":");
    if port_discovery {
        info!("{}", m!("Scanning common ports to discover alive host."));
        let (tx, rx) = mpsc::channel();
        discovery_ports.retain(|&port| ports.contains(&port));   // 用户不想扫的端口不作为探测用的端口
        tokio::spawn(
            utils::port_scan_with_channel(need_scan_host.clone(), discovery_ports.clone(), concurrency.clone(), connect_config.clone(), tx)
        );
        for service in rx {
            println!("{}:{}", service.host, service.port);
            info!("{} {}{}{} {}", m!("Port discovery"), service.host, colon, service.port, m!("is alive."));
            alive_hosts.insert(service.host);
            if let Some(ref mut outfile) = outfile {
                write!(outfile, "{}:{}\r\n", service.host, service.port);
                let _ = outfile.flush();
            }
            discovery_services.entry(service.host).or_insert_with(Vec::new).push(service.port);
        }
        // 从需要扫描的端口中去掉已探测的端口
        let discovery_port_set: HashSet<u16> = discovery_ports.clone().into_iter().collect();
        ports.retain(|port| !discovery_port_set.contains(port));
    }

    if ping_discovery || port_discovery {
        if alive_hosts.is_empty() {
            warn!("{}", m!("No host found. Exit! Maybe you should disable host discovery by add --ngd --npd --np"));
            exit(1);
        } else {
            info!("{} {} {}", m!("Found"), alive_hosts.len(), m!("alive hosts in total!"));
        }
        need_scan_host = Arc::from(alive_hosts.into_iter().collect::<Vec<Ipv4Addr>>());
    }

    info!("{} {} {}",m!("Each host will have"), ports.len(), m!("ports scanned."));
    info!("{}", m!("Scanning ports..."));
    let (tx, rx) = mpsc::channel();
    tokio::spawn(utils::port_scan_with_channel(
        need_scan_host.clone(),
        ports,
        concurrency.clone(),
        connect_config.clone(),
        tx,
    ));
    let mut ports_num = 0;
    /* 2 */

    for service in rx {
        ports_num += 1;
        println!("{}:{}", service.host, service.port);
        info!("{}{}{} {}{}", service.host, colon, service.port, service.duration.as_millis(), m!("ms"));
        if let Some(ref mut outfile) = outfile {
            write!(outfile, "{}{}{}\r\n", service.host, colon, service.port);
            outfile.flush();
        }
    }
    /* 4 */
    // if let Some(ref mut outfile) = outfile {
    //     outfile.flush().unwrap();
    // }
    for ports in discovery_services.values() {
        ports_num += ports.len();
    }

    info!("{} {}", &ports_num, m!("open ports in total."));
}
