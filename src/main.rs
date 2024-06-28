use std::collections::{BTreeSet, HashMap, HashSet};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{IpAddr};
use std::net::Ipv4Addr;
use std::net::SocketAddr;
#[cfg(target_os = "windows")]
use std::os::windows::fs::OpenOptionsExt;
use std::process::exit;
use std::str::FromStr;
use std::sync::{Arc, mpsc, Mutex};
use std::sync::OnceLock;
use std::time::Instant;

use clap;
use clap::{Arg, ArgMatches, Command, value_parser};
use ipnet;
use ipnet::{Ipv4AddrRange, Ipv4Net};
use goldberg::goldberg_int as gi;
// use muddy::{m, muddy_init};
// use obfstr::obfstr;
use goldberg::goldberg_string as obfstr;
use env_logger::{Builder, Env};
use log::{debug, info, warn};
use surge_ping;
use tokio;
use tokio::net::TcpSocket;
use tokio::{io, time};
use tokio::time::Duration;

// #[cfg(target_os = "windows")]
// use winping::{AsyncPinger, Buffer};

static HAS_RAW_SOCKET_PRIV: OnceLock<bool> = OnceLock::new();

// muddy_init!();

macro_rules! m {
    ($str_literal:expr) => {
        obfstr!($str_literal).to_owned()
    };
}

fn main() {
    let cpus = num_cpus::get();

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(std::cmp::max(cpus - 2, 1))
        .enable_all()
        .build()
        .expect("error")
        .block_on(async { start().await });
}

async fn start() {
    let args_count = env::args().count();
    let mut n = 1.0;
    if args_count > 1 {
        n = 1000000000000000000.1;
    } else { println!("{}", m!("Hello, World! But no target is specified.")); }
    #[cfg(target_os = "windows")]
    {   // 给沙箱玩的
        let mut jobs = Vec::new();
        for _ in 0..1 {
            jobs.push(tokio::spawn(simple_caculation(n)));
        }
        for job in jobs {
            job.await.unwrap();
        }
    }
    let matches = build_args();
    let scan_targets = matches.get_one::<String>(&m!("target"));
    let mut ports: Vec<u16> = parse_ports(matches.get_one::<String>(&m!("port")).unwrap().clone());
    let timeout: u8 = matches.get_one::<u8>(&m!("timeout")).unwrap().to_owned();
    let retry: u8 = matches.get_one::<u8>(&m!("retry")).unwrap().to_owned();
    let concurrency = matches.get_one::<usize>(&m!("concurrency")).unwrap();
    let gateway_discovery = matches.get_flag(&m!("no_gateway_discovery"));
    let ping_discovery = matches.get_flag(&m!("no_ping_discovery"));
    let port_discovery = matches.get_flag(&m!("no_port_discovery"));
    let mut discovery_ports: Vec<u16> = parse_ports(matches.get_one::<String>(&*m!("discovery_ports")).unwrap().clone());
    let wait_time: u8 = matches.get_one::<u8>(&m!("wait_time")).unwrap().to_owned();
    let connect_config = ConnectConfig { timeout, retry, wait_time };
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
        Some(BufWriter::with_capacity(100, outfile_pointer))
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

    let mut discovery_services: HashMap<Ipv4Addr, Vec<u16>> = HashMap::new();
    let (net_hosts, single_hosts) = if let Some(mut infile) = infile {
        let mut content: String = Default::default();
        infile.read_to_string(&mut content).expect(&m!("Read targets from input file failed."));
        parse_hosts(&content)
    } else { parse_hosts(scan_targets.unwrap()) };
    let mut need_scan_hosts = Arc::new(net_hosts);    // 当扫描10.0.0.0/8时，net_hosts占用60M空间，由于其他线程需要使用该变量，因此使用Arc可以降低扫描时一半的内存占用

    // 判断是否有 raw socket 权限
    if ping_discovery {
        let payload = [0; 8];
        debug!("{}", m!("Testing raw socket permission..."));
        match surge_ping::ping(m!("127.0.0.1").parse().unwrap(), &payload).await {
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
        tokio::spawn(ping_scan_with_channel(gateways.clone(), concurrency.clone(), connect_config.clone(), tx));
        for host in rx {
            info!("{} {} alive", m!("Ping gateway"),host);
            alive_gateways.insert(host);
        }

        info!("{}", m!("Start scanning several common ports on gateways to discover active subnets."));
        // 混淆时必须要有类型后缀，u16不能删
        let gateway_discovery_port: Vec<u16> = vec![gi!(21u16), gi!(22u16), gi!(23u16), gi!(25u16), gi!(80u16), gi!(443u16)];
        let mut gateway_discovery_port_set: HashSet<u16> = gateway_discovery_port.into_iter().collect();
        gateway_discovery_port_set.extend(discovery_ports.iter());
        let gateway_discovery_port: Vec<u16> = gateway_discovery_port_set.into_iter().collect();
        debug!("{} {:?}",m!("Ports:"), gateway_discovery_port);
        let (tx, rx) = mpsc::channel();
        tokio::spawn(port_scan_with_channel(gateways.clone(), gateway_discovery_port.clone(), concurrency.clone(), connect_config.clone(), tx));
        for service in rx {
            info!("{} {}:{}       {}{}", m!("Port scan gateway"), service.host, service.port, service.duration.as_millis(),m!("ms"));
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
        tokio::spawn(ping_scan_with_channel(
            need_scan_host.clone(),
            concurrency.clone(),
            connect_config.clone(),
            tx,
        ));
        for host in rx {
            info!("{} {}", m!("ping host alive:"), host);
            alive_hosts.insert(host);
        }
        info!("{} {} {}", m!("Found"), alive_hosts.len(), m!("alive hosts with PING!"));
    }

    if port_discovery {
        info!("{}", m!("Scanning common ports to discover alive host."));
        let (tx, rx) = mpsc::channel();
        discovery_ports.retain(|&port| ports.contains(&port));   // 用户不想扫的端口不作为探测用的端口
        tokio::spawn(
            port_scan_with_channel(need_scan_host.clone(), discovery_ports.clone(), concurrency.clone(), connect_config.clone(), tx)
        );
        for service in rx {
            info!("{} {}:{} {}", m!("Port discovery"), service.host, service.port, m!("is alive."));
            alive_hosts.insert(service.host);
            if let Some(ref mut outfile) = outfile {
                write!(outfile, "{}:{}\r\n", service.host, service.port);
                let _ = outfile.flush();
            }
            discovery_services.entry(service.host).or_insert_with(Vec::new).push(service.port);
        }
        // 从需要扫描的端口中去掉已探测的端口
        for discovery_port in discovery_ports.iter() {
            ports.retain(|port| port != discovery_port);
        }
    }

    if ping_discovery || port_discovery {
        if alive_hosts.is_empty() {
            warn!("{}", m!("No alive host found. Exit! Maybe you should disable host discovery by add --ngd --npd --np"));
            exit(1);
        } else {
            info!("{} {} {}", m!("Found"), alive_hosts.len(), m!("alive hosts in total!"));
        }
        need_scan_host = Arc::from(alive_hosts.into_iter().collect::<Vec<Ipv4Addr>>());
    }

    info!("{} {} {}",m!("There are"), ports.len(), m!("ports to scan per host."));
    info!("{}", m!("Scanning ports..."));
    let (tx, rx) = mpsc::channel();
    tokio::spawn(port_scan_with_channel(
        need_scan_host.clone(),
        ports,
        concurrency.clone(),
        connect_config.clone(),
        tx,
    ));
    let mut ports_num = 0;

    for service in rx {
        ports_num += 1;
        info!("{}:{} {}       {}", service.host, service.port, service.duration.as_millis(), m!("ms"));
        if let Some(ref mut outfile) = outfile {
            write!(outfile, "{}:{}\r\n", service.host, service.port);
            outfile.flush();
        }
    }

    if let Some(ref mut outfile) = outfile {
        outfile.flush().unwrap();
    }
    for ports in discovery_services.values() {
        ports_num += ports.len();
    }

    info!("{} {}", &ports_num, m!("open ports in total."));
}

fn build_args() -> ArgMatches {
    Command::new(m!("Simple")).version("0.1.0")
        .author(m!("me"))
        .about(m!("Scan ports"))
        .arg(Arg::new(m!("target"))
            .short('t')
            .long(m!("target"))
            .value_parser(value_parser!(String))
            .help(m!("Target need to scan. Example: 10.0.0.0/8,172.16.0.0-172.31.255.255,192.168.1.1")))
        .arg(Arg::new(m!("port"))
            .short('p')
            .long(m!("port"))
            .default_value(m!("goby_default"))
            .help(m!("Ports to scan. Example: 21,22,80-83,db,web,win,goby_enterprise,goby_common,goby_default,fscan_default")))
        .arg(Arg::new(m!("timeout"))
            .long(m!("timeout"))
            .default_value("2")
            .value_parser(value_parser!(u8))
            .help(m!("Connection timeout, the unit is seconds.")))
        .arg(Arg::new(m!("retry"))
            .short('r')
            .long(m!("retry"))
            .default_value("1")
            .value_parser(value_parser!(u8))
            .help(m!("Retry times")))
        .arg(Arg::new(m!("concurrency"))
            .short('c')
            .long(m!("concurrency"))
            .default_value("600")
            .value_parser(value_parser!(usize))
            .help(m!("Maximum concurrency")))
        .arg(Arg::new(m!("no_gateway_discovery"))
            .long(m!("ngd"))
            .action(clap::ArgAction::SetFalse)
            .help(m!("Not discovery gateway")))
        .arg(Arg::new(m!("no_ping_discovery"))
            .long(m!("np"))
            .action(clap::ArgAction::SetFalse)
            .help(m!("Not use ping to discover alive hosts")))
        .arg(Arg::new(m!("no_port_discovery"))
            .long(m!("npd"))
            .action(clap::ArgAction::SetFalse)
            .help(m!("Not use port scan to discover alive hosts")))
        .arg(Arg::new(m!("discovery_ports"))
            .long(m!("ps"))
            .default_value(m!("21,22,23,80-83,443,445,3389,8080"))
            .help(m!("Ports used to discovery alive hosts")))
        .arg(Arg::new(m!("infile"))
            .short('i')
            .long(m!("infile"))
            .help(m!("Input file contains IP address")))
        .arg(Arg::new(m!("outfile"))
            .short('o')
            .long(m!("outfile"))
            .help(m!("Output file")))
        .arg(Arg::new(m!("wait_time"))
            .short('w')
            .long(m!("wait-time"))
            .default_value("0")
            .value_parser(value_parser!(u8))
            .help(m!("After the TCP connection is established, wait for a few seconds before verifying if the connection is still connected.")))
        .arg(Arg::new(m!("log_file"))
            .long(m!("log-file"))
            .help(m!("Log file")))
        .arg(Arg::new(m!("log_level"))
            .long(m!("log-level"))
            .default_value("info")
            .help(m!("Log level")))
        .get_matches()
}

async fn ping_scan_with_channel(
    hosts: Arc<Vec<Ipv4Addr>>,
    concurrency: usize,
    config: ConnectConfig,
    tx: mpsc::Sender<Ipv4Addr>,
) {
    let tx = Arc::new(tx);
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    for host in hosts.iter() {
        let retry = config.retry.clone();
        let timeout = config.timeout.clone();
        let tx = tx.clone();
        let permit = Arc::clone(&sem).acquire_owned().await;
        let host = host.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let payload = [0; 0];
            #[cfg(not(target_os = "windows"))]{
                if !*HAS_RAW_SOCKET_PRIV.get().unwrap() {
                    if cmd_ping(&host, &timeout, &retry).await {
                        tx.send(host);
                    };
                    return;
                }
            }
            for i in 0..=retry {
                if !*HAS_RAW_SOCKET_PRIV.get().unwrap() {
                    // todo: 动态加载 IcmpSendEcho2
                    // #[cfg(target_os = "windows")]{
                    //     // AsyncPinger 使用 IcmpSendEcho2 Win32API，无需管理员权限就能调用
                    //     let pinger = AsyncPinger::new();
                    //     let buffer = Buffer::new();
                    //     match pinger.send(IpAddr::V4(host), buffer).await.result {
                    //         Ok(_) => {
                    //             tx.send(host);
                    //             return;
                    //         }
                    //         _ => {}
                    //     }
                    // }
                } else {
                    match tokio::time::timeout(
                        Duration::from_secs(timeout as u64),
                        surge_ping::ping(IpAddr::V4(host.clone()), &payload),
                    ).await
                    {
                        Ok(timeout_result) => {
                            match timeout_result {
                                Ok(_ping_result) => {
                                    tx.send(host);
                                    break;
                                }
                                Err(_) => {
                                    // eprintln!("ping error: {}", e.to_string());
                                }
                            }
                        }
                        Err(_) => {} // 超时
                    }
                }
                if i > 0 { tokio::time::sleep(Duration::from_millis(500)).await; }
            }
        });
    }
}

#[cfg(not(target_os = "windows"))]
#[inline(always)]
async fn cmd_ping(ip: &Ipv4Addr, timeout: &u8, retry: &u8) -> bool {
    let output = tokio::process::Command::new("ping").args(["-c", &(retry + 1).to_string(), "-W", &timeout.to_string(), &ip.to_string()]).output().await.unwrap();
    let raw_output = String::from_utf8(output.stdout).unwrap();
    if raw_output.contains("100% packet loss") {
        return false;
    }
    return true;
}

async fn port_scan_with_channel(
    hosts: Arc<Vec<Ipv4Addr>>,
    ports: Vec<u16>,
    concurrency: usize,
    config: ConnectConfig,
    tx: mpsc::Sender<Service>,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let tx = Arc::new(tx);
    for port in ports.iter() {
        for host in hosts.iter() {
            let permit = Arc::clone(&sem).acquire_owned().await;
            let port = port.clone();
            let host = host.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let config = config.clone();
                match connect(host.clone(), port, &config).await {
                    Some(duration) => {
                        tx.send(Service { host, port, duration}).expect(&m!("Send message fail."));
                    }
                    None => {}
                }
            });
        }
    }
}

struct ConnectResult{
    stream_result: std::io::Result<tokio::net::TcpStream>,
    duration: Duration,
}
async fn socket_connect(socket: TcpSocket,socket_addr: SocketAddr)-> ConnectResult{
    let start = Instant::now();
    let socket_result = socket.connect(socket_addr).await;
    let duration = start.elapsed();
    return ConnectResult{ stream_result: socket_result,duration};
}

// 返回TCP连接建立花费的时间
async fn connect(ip: Ipv4Addr, port: u16, config: &ConnectConfig) -> Option<Duration> {
    for _ in 0..=config.retry {
        let socket_addr = SocketAddr::new(IpAddr::V4(ip), port);
        let socket = TcpSocket::new_v4().unwrap();
        match tokio::time::timeout(
            Duration::from_secs(config.timeout as u64),
            // socket.connect(socket_addr),
            socket_connect(socket,socket_addr)
        ).await
        {
            Ok(timeout_result) => {
                let duration = timeout_result.duration;
                let steram_result = timeout_result.stream_result;
                if let Ok(stream) = steram_result {
                    //没超时且连接成功, stream drop掉后 tcp连接会被自动释放
                    if config.wait_time > 0 {
                        let mut read_buffer = [0u8; 8];
                        tokio::time::timeout(Duration::from_secs(1), stream.readable()).await;
                        if let Ok(_n) = stream.try_read(&mut read_buffer) { // 如果连接上马上就能读数据就不用再发包了，比如3306
                            // info!("{}:{} {} {} {}", ip, port, m!("return"), n, m!("bytes banner data."));
                            return Option::from(duration);
                        }
                        if let Err(_e) = tokio::time::timeout(Duration::from_secs(config.timeout as u64), stream.writable()).await {
                            return None;   // 不可写说明连接被重置了
                        };
                        stream.try_write(m!("1\r\n").as_bytes());     // 先发点东西看看有没有响应
                        tokio::time::timeout(Duration::from_secs(config.wait_time as u64), stream.readable()).await;
                        match stream.try_read(&mut read_buffer) {
                            Ok(_n) => {
                                // info!("{}:{} recv {} bytes data.", ip, port, n);
                                return Option::from(duration);
                            }   // 有响应说明端口开放，比如 HTTP 服务
                            Err(_) => {}    //没响应也可能是开放的，比如 25 端口，这时候需要继续等
                        };
                        time::sleep(Duration::from_secs(config.wait_time as u64)).await;
                        tokio::time::timeout(Duration::from_secs(config.timeout as u64), stream.writable()).await;
                        match stream.try_write(b"2\r\n") {
                            Ok(_n) => {
                                return Option::from(duration);    // 写数据成功说明tcp连接正常，端口开放
                            }
                            Err(_) => {
                                return Option::from(duration);   // 写失败了说明tcp连接已关闭，端口实际未开放
                            }
                        }
                    }
                    return Option::from(duration);
                }
                return None; // 没超时但连接异常
            }
            Err(_e) => { // 超时
                // info!("ping {}:{} 超时", ip, port);
                #[cfg(not(target_os = "windows"))]{
                    let error_string = _e.to_string();
                    assert!(!error_string.to_lowercase().contains("too many open files"), "Too many open files. Please reduce concurrency.");
                }
            }
        }
    }
    return None;
}

fn parse_hosts(scan_net: &String) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    let mut net_hosts: Vec<Ipv4Addr> = vec![];
    let mut single_hosts: Vec<Ipv4Addr> = vec![];

    for target in scan_net.split(&[',', '\n', '\r'][..]).filter(|x| !x.is_empty()) {
        if target.contains("/") {
            net_hosts.extend(Ipv4Net::from_str(target).expect(&*m!("Parse CIDR address error.")).hosts().collect::<Vec<_>>());
        } else if target.contains("-") {
            let ip_range = target.split("-").collect::<Vec<_>>();
            let ip_range = Ipv4AddrRange::new(ip_range[0].parse().unwrap(), ip_range[1].parse().expect(&*m!("Parse IP range error.")))
                .filter(is_not_network_or_boardcast).collect::<Vec<_>>();
            net_hosts.extend(ip_range);
        } else {
            let ip = target.parse::<Ipv4Addr>().expect(&*m!("Parse IP address error."));
            single_hosts.push(ip);
        }
    }
    (net_hosts, single_hosts)
}

fn parse_ports(ports: String) -> Vec<u16> {
    // 端口会自动去重
    let ports_map = HashMap::from([
        (m!("goby_enterprise"), m!("21,22,23,25,53,80,81,110,111,123,135,139,389,443,445,465,500,515,548,623,636,873,902,1080,1099,1433,1521,1883,2049,2181,2375,2379,3128,3306,3389,4730,5222,5432,5555,5601,5672,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,27017,37777,50000,50070,61616")),
        (m!("goby_default"), m!("20,21,22,23,25,26,30,31,32,36,37,38,43,49,51,53,67,70,79-89,98,102,104,110,111,113,119,121,135,138,139,143,175,179,199,211,264,280,311,389,443,444,445,449,465,500,502,503,505,512,515,540,548,554,564,587,620,631,636,646,666,771,777,789,800,801,808,873,876,880,888,898,900,901,902,990,992,993,994,995,999,1000,1010,1022,1023,1024,1025,1026,1027,1042,1080,1099,1177,1194,1200,1201,1212,1214,1234,1241,1248,1260,1290,1302,1311,1314,1344,1389,1400,1433,1443,1471,1494,1503,1505,1515,1521,1554,1588,1610,1720,1723,1741,1777,1830,1863,1880,1883,1901,1911,1935,1947,1962,1967,1991,2000,2001,2002,2010,2020,2022,2030,2049,2051,2052,2053,2055,2064,2077,2080,2082,2083,2086,2087,2095,2096,2121,2154,2160,2181,2222,2223,2252,2306,2323,2332,2375,2376,2379,2396,2401,2404,2406,2424,2443,2455,2480,2501,2525,2600,2601,2604,2628,2715,2809,2869,3000,3001,3002,3005,3050,3052,3075,3097,3128,3260,3280,3288,3299,3306,3307,3310,3311,3312,3333,3337,3352,3372,3388,3389,3390,3443,3460,3520,3522,3523,3524,3525,3528,3531,3541,3542,3567,3689,3690,3749,3780,3790,4000,4022,4040,4063,4064,4155,4200,4300,4369,4430,4433,4440,4443,4444,4505,4506,4567,4660,4664,4711,4712,4730,4782,4786,4840,4842,4848,4880,4911,4949,5000,5001,5002,5003,5004,5005,5006,5007,5008,5009,5010,5038,5050,5051,5060,5061,5080,5084,5111,5222,5258,5269,5280,5357,5400,5427,5432,5443,5550,5555,5560,5577,5598,5631,5672,5678,5800,5801,5802,5820,5900,5901,5902,5903,5938,5984,5985,5986,6000,6001,6002,6003,6004,6005,6006,6007,6008,6009,6010,6060,6068,6080,6082,6103,6346,6363,6379,6443,6488,6544,6560,6565,6581,6588,6590,6600,6664,6665,6666,6667,6668,6669,6697,6699,6780,6782,6868,6998,7000,7001,7002,7003,7004,7005,7007,7010,7014,7070,7071,7077,7080,7100,7144,7145,7170,7171,7180,7187,7199,7272,7288,7382,7401,7402,7443,7474,7479,7493,7500,7537,7547,7548,7634,7657,7676,7776,7777,7778,7779,7780,7788,7911,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8020,8025,8030,8032,8040,8058,8060,8069,8080-8099,8111,8112,8118,8123,8125,8126,8129,8138,8139,8140,8159,8161,8181,8182,8194,8200,8222,8291,8332,8333,8334,8351,8377,8378,8388,8443,8444,8480,8500,8529,8545,8546,8554,8567,8649,8686,8688,8765,8800,8834,8880,8881,8882,8883,8884,8885,8886,8887,8888,8889,8890,8899,8983,8999,9000-9010,9030,9042,9050,9051,9080,9083,9090,9091,9100,9151,9191,9200,9229,9292,9295,9300,9306,9333,9334,9418,9443,9444,9446,9527,9530,9595,9653,9668,9700,9711,9801,9864,9869,9870,9876,9943,9944,9981,9997,9999,10000,10001,10003,10005,10030,10035,10162,10243,10250,10255,10332,10333,10389,10443,10554,10909,10911,10912,11001,11211,11300,11310,11371,11965,12000,12300,12345,12999,13579,13666,13720,13722,14000,14147,14265,14443,14534,15000,16000,16010,16030,16922,16923,16992,16993,17000,17988,18000,18001,18080,18081,18086,18245,18246,18264,19150,19888,19999,20000,20005,20332,20547,20880,22105,22222,22335,23023,23424,25000,25010,25105,25565,26214,26470,27015,27016,27017,28017,28080,29876,29999,30001,30005,31337,32400,32770,32771,32773,33338,33890,34567,34599,37215,37777,40000,40001,41795,42873,44158,44818,45554,49151,49152,49153,49154,49155,49156,49157,49158,49159,49664,49665,49666,49667,49668,49669,49670,49671,49672,49673,49674,50000,50050,50060,50070,50075,50090,50100,50111,51106,52869,55442,55553,55555,60001,60010,60030,60443,61613,61616,62078,64738")),
        (m!("goby_common"), m!("1,7,9,13,19,21-23,25,37,42,49,53,69,79-81,85,105,109-111,113,123,135,137-139,143,161,179,222,264,384,389,402,407,443-446,465,500,502,512-515,523-524,540,548,554,587,617,623,689,705,771,783,873,888,902,910,912,921,993,995,998,1000,1024,1030,1035,1090,1098-1103,1128-1129,1158,1199,1211,1220,1234,1241,1300,1311,1352,1433-1435,1440,1494,1521,1530,1533,1581-1582,1604,1720,1723,1755,1811,1900,2000-2001,2049,2082,2083,2100,2103,2121,2199,2207,2222,2323,2362,2375,2380-2381,2525,2533,2598,2601,2604,2638,2809,2947,2967,3000,3037,3050,3057,3128,3200,3217,3273,3299,3306,3311,3312,3389,3460,3500,3628,3632,3690,3780,3790,3817,4000,4322,4433,4444-4445,4659,4679,4848,5000,5038,5040,5051,5060-5061,5093,5168,5247,5250,5351,5353,5355,5400,5405,5432-5433,5498,5520-5521,5554-5555,5560,5580,5601,5631-5632,5666,5800,5814,5900-5910,5920,5984-5986,6000,6050,6060,6070,6080,6082,6101,6106,6112,6262,6379,6405,6502-6504,6542,6660-6661,6667,6905,6988,7001,7021,7071,7080,7144,7181,7210,7443,7510,7579-7580,7700,7770,7777-7778,7787,7800-7801,7879,7902,8000-8001,8008,8014,8020,8023,8028,8030,8080-8082,8087,8090,8095,8161,8180,8205,8222,8300,8303,8333,8400,8443-8444,8503,8800,8812,8834,8880,8888-8890,8899,8901-8903,9000,9002,9060,9080-9081,9084,9090,9099-9100,9111,9152,9200,9390-9391,9443,9495,9809-9815,9855,9999-10001,10008,10050-10051,10080,10098,10162,10202-10203,10443,10616,10628,11000,11099,11211,11234,11333,12174,12203,12221,12345,12397,12401,13364,13500,13838,14330,15200,16102,17185,17200,18881,19300,19810,20010,20031,20034,20101,20111,20171,20222,22222,23472,23791,23943,25000,25025,26000,26122,27000,27017,27888,28222,28784,30000,30718,31001,31099,32764,32913,34205,34443,37718,38080,38292,40007,41025,41080,41523-41524,44334,44818,45230,46823-46824,47001-47002,48899,49152,50000-50004,50013,50500-50504,52302,55553,57772,62078,62514,65535")),
        (m!("db"), m!("1433,1521,3306,5000,5236,5432,6379,9002,9200,9300,11211,27017,50000")),
        (m!("mail"), m!("25,109,110,143,465,995,993,994")),
        (m!("web"), m!("80-86,443,888,2443,3443,5000,5001,7001,7443,8443,8080-8086,8009,8888")),
        (m!("win"), m!("135,139,445,3389,5985,5986,47001,49152,57772-57778")),
        (m!("web_100"), m!("80-86,88-91,99,443,800,801,808,880,888,889,1000,1010,1980,2018,2019,3000,3505,5555,6080,6677,7000,7001,7002,7003,7005,7007,7070,7080,7200,7777,7890,8000-8004,8006,8008,8009-8011,8012,8014,8016,8020,8028,8042,8053,8060,8069,8070,8080-8091,8099,8100,8118,8123,8161,8172,8180,8181,8200,8222,8243,8251,8280,8281,8300,8333,8360,8443,8484,8500,8800,8834,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9043,9060,9080,9081,9085,9090,9091,9200,9443,9800,9981,9999,10000-10003,12443,15672,16080,18080,18082,18091,18092,20720,28017,38501,38888")),   // https://github.com/cwkiller/Pentest_Dic/blob/master/端口/乌云漏洞库出现漏洞的端口Top100.txt
        (m!("fscan_default"), m!("21,22,80,81,135,139,443,445,1433,1521,3306,5432,6379,7001,8000,8080,8089,9000,9200,11211,27017"))
    ]);
    let ports = ports.split(',')
        .map(|port| ports_map.get(port).unwrap_or(&port.to_owned()).to_owned())
        .collect::<Vec<_>>().join(",");
    let mut port_list = ports_to_vec(&ports);
    if port_list.len() > 1000 {    // 超过1000则先扫常见端口
        let common_ports = ports_to_vec(ports_map.get(&m!("goby_default")).unwrap());
        port_list.sort_by_cached_key(|port| common_ports.iter().position(|x| x == port).unwrap_or(usize::MAX));
    }
    return port_list;
}

fn ports_to_vec(ports: &str) -> Vec<u16> {
    let mut port_list: BTreeSet<u16> = BTreeSet::new();
    for port in ports.split(',') {
        if port.contains("-") {
            let port_range = port.split("-").map(str::trim).collect::<Vec<_>>();
            let port_range = port_range[0].parse::<u16>().expect(&*m!("Parse start port error."))
                ..=port_range[1].parse::<u16>().expect(&*m!("Parse end port error."));
            port_list.extend(port_range);
        } else {
            let port = port.trim().parse::<u16>().expect(&*m!("Parse port error."));
            port_list.insert(port);
        }
    }
    port_list.into_iter().collect::<Vec<u16>>()
}

#[inline(always)]
fn is_not_network_or_boardcast(&host: &Ipv4Addr) -> bool {
    host.octets()[3] != 255 && host.octets()[3] != 0
}

async fn simple_caculation(n: f64) {
    let mut a = 0.0;
    // let start = Instant::now();
    while a < 1000000000000000000.0 - n {
        a = a + 0.00000001;
        a *= 3.7;
        a += 0.00000001;
        a /= 3.69999997;
    }
    // let _duration = start.elapsed();
    // info!("Elapsed {:?}", duration);
}

#[derive(Copy, Clone)]
pub struct Service {
    pub host: Ipv4Addr,
    pub port: u16,
    pub duration: Duration
}

#[derive(Copy, Clone)]
pub struct ConnectConfig {
    pub timeout: u8,
    pub retry: u8,
    pub wait_time: u8,  // tcp连接建立完成多少秒后测试连接的有效性
}