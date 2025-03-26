use crate::HAS_RAW_SOCKET_PRIV;
use clap::{value_parser, Arg, ArgMatches, Command};
use ipnet::{Ipv4AddrRange, Ipv4Net};
use log::{debug, info};
// use muddy::{m, muddy_init};
use proc_macro_crate::process_string as m;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Add;
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};
use tokio::net::TcpSocket;
use tokio::time;

// muddy_init!();
pub fn build_args() -> ArgMatches {
    Command::new(m!("Simple"))
        .version("0.1.1")
        .author(m!("me"))
        .about(m!("Scan ports"))
        .arg(Arg::new(m!("unknown_args")).num_args(1..))  // 忽略多余的索引参数，避免在shellcode加载器中报错
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
        .arg(Arg::new(m!("exclude_port"))
            .long(m!("ep"))
            .default_value(m!("9100"))
            .help(m!("Exclude port. Example: 21,22,80-83,db,web,win,goby_enterprise,goby_common,goby_default,fscan_default")))
        .arg(Arg::new(m!("timeout"))
            .long(m!("timeout"))
            .default_value("2000")
            .value_parser(value_parser!(u16))
            .help(m!("Connection timeout, the unit is ms.")))
        .arg(Arg::new(m!("jitter"))
            .long(m!("jitter"))
            .default_value("1000")
            .value_parser(value_parser!(u16))
            .help(m!("Connection timeout jitter, the unit is ms.")))
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
            .help(m!("Output file for scan results")))
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
            .help(m!("Log level. Available options: info,debug,warn,error")))
        .ignore_errors(true)    // 忽略多余的 --xx 参数
        .get_matches()
}

pub async fn ping_scan_with_channel(
    hosts: Arc<Vec<Ipv4Addr>>,
    concurrency: usize,
    config: ConnectConfig,
    tx: mpsc::Sender<(Ipv4Addr, Duration)>,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let tx = Arc::new(tx);
    let mut total: u64 = 0;
    let mut start_rng: StdRng = SeedableRng::from_entropy();
    for host in hosts.iter() {
        if total < concurrency as u64 {   // 启动时引入随机延迟，防止短时间内发包数量过高
            tokio::time::sleep(Duration::from_millis(start_rng.gen_range(0..=config.jitter) as u64)).await;
        };
        total += 1;
        let config = config.clone();
        let tx = tx.clone();
        let permit = Arc::clone(&sem).acquire_owned().await;
        let host = host.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let payload = [0; 0];
            #[cfg(not(target_os = "windows"))]{
                if !*HAS_RAW_SOCKET_PRIV.get().unwrap() {
                    if cmd_ping(&host, &config.timeout, &config.jitter, &config.retry).await {
                        tx.send((host, Duration::from_millis(0)));
                    };
                    return;
                }
            }
            for i in 0..=config.retry {
                if !*HAS_RAW_SOCKET_PRIV.get().unwrap() {
                    // todo: 动态加载 IcmpSendEcho2
                    // #[cfg(target_os = "windows")]{
                    //     // AsyncPinger 使用 IcmpSendEcho2 Win32API，无需管理员权限就能调用
                    //     let pinger = AsyncPinger::new();
                    //     let buffer = Buffer::new();
                    //     match pinger.send(IpAddr::V4(host), buffer).await.result {
                    //         Ok(_) => {
                    //             tx.send((host,Duration::from_millis(0)));
                    //             return;
                    //         }
                    //         _ => {}
                    //     }
                    // }
                } else {
                    let mut rng: StdRng = SeedableRng::from_entropy();
                    match tokio::time::timeout(
                        Duration::from_millis(config.timeout as u64).add(Duration::from_millis(rng.gen_range(0..=config.jitter) as u64)),
                        surge_ping::ping(IpAddr::V4(host.clone()), &payload),
                    ).await
                    {
                        Ok(timeout_result) => {
                            match timeout_result {
                                Ok(ping_result) => {
                                    tx.send((host, ping_result.1));
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
                if i > 0 { tokio::time::sleep(Duration::from_millis(1000)).await; }
            }
        });
    }
}

#[cfg(not(target_os = "windows"))]
#[inline(always)]
async fn cmd_ping(ip: &Ipv4Addr, timeout: &u16, jitter: &u16, retry: &u8) -> bool {
    let mut rng: StdRng = SeedableRng::from_entropy();
    let timeout = (timeout + rng.gen_range(0..=*jitter)).div_floor(1000);
    let output = tokio::process::Command::new("ping").args(["-c", &(retry + 1).to_string(), "-W", &timeout.to_string(), &ip.to_string()]).output().await.unwrap();
    let raw_output = String::from_utf8(output.stdout).unwrap();
    if raw_output.contains("100% packet loss") {
        return false;
    }
    return true;
}

pub async fn port_scan_with_channel(
    hosts: Arc<Vec<Ipv4Addr>>,
    ports: Vec<u16>,
    concurrency: usize,
    config: ConnectConfig,
    tx: mpsc::Sender<Service>,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let tx = Arc::new(tx);
    let mut total = 0u64;
    let mut rng: StdRng = SeedableRng::from_entropy();
    for port in ports.iter() {
        for host in hosts.iter() {
            if total < concurrency as u64 {   // 启动时引入随机延迟，防止短时间内发包数量过高
                let t = rng.gen_range(0..=config.jitter) as u64;
                tokio::time::sleep(Duration::from_millis(t)).await;
            };
            total += 1;
            let permit = Arc::clone(&sem).acquire_owned().await;
            let port = port.clone();
            let host = host.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let config = config.clone();
                match connect(host.clone(), port, &config).await {
                    Some(duration) => {
                        tx.send(Service { host, port, duration }).expect(&m!("Send message fail."));
                    }
                    None => {}
                }
            });
        }
    }
}

struct ConnectResult {
    stream_result: std::io::Result<tokio::net::TcpStream>,
    duration: Duration,
}

async fn socket_connect_wrapper(socket: TcpSocket, socket_addr: SocketAddr) -> ConnectResult {
    let start = Instant::now();
    let socket_result = socket.connect(socket_addr).await;
    let duration = start.elapsed();
    return ConnectResult { stream_result: socket_result, duration };
}

// 返回TCP连接建立花费的时间
async fn connect(ip: Ipv4Addr, port: u16, config: &ConnectConfig) -> Option<Duration> {
    for retry_times in 0..=config.retry {
        let socket_addr = SocketAddr::new(IpAddr::V4(ip), port);
        let socket = TcpSocket::new_v4().unwrap();
        let mut rng: StdRng = SeedableRng::from_entropy();
        let jitter = Duration::from_millis(rng.gen_range(0..=config.jitter) as u64);
        match tokio::time::timeout(
            Duration::from_millis(config.timeout as u64).add(jitter),
            socket_connect_wrapper(socket, socket_addr),
        ).await
        {
            Ok(connect_result) => {
                let duration = connect_result.duration;
                let steram_result = connect_result.stream_result;
                if let Ok(stream) = steram_result {
                    //没超时且连接成功, stream drop掉后 tcp连接会被自动释放
                    if config.wait_time > 0 {
                        let mut read_buffer = [0u8; 8];
                        tokio::time::timeout(Duration::from_secs(1), stream.readable()).await;
                        if let Ok(_n) = stream.try_read(&mut read_buffer) { // 如果连接上马上就能读数据就不用再发包了，比如3306
                            // debug!("{}:{} {} {} {}", ip, port, m!("return"), n, m!("bytes banner data."));
                            return Option::from(duration);
                        }
                        if let Err(_e) = tokio::time::timeout(Duration::from_secs(config.timeout as u64), stream.writable()).await {
                            return None;   // 不可写说明连接被重置了
                        };
                        stream.try_write(m!("1\r\n").as_bytes());     // 先发点东西看看有没有响应
                        tokio::time::timeout(Duration::from_secs(config.wait_time as u64), stream.readable()).await;
                        match stream.try_read(&mut read_buffer) {
                            Ok(_n) => {
                                // debug!("{}:{} recv {} bytes data.", ip, port, n);
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
                                return None;   // 写失败了说明tcp连接已关闭，端口实际未开放
                            }
                        }
                    }
                    if retry_times > 0{
                        debug!("{} {} {} {}:{} ", m!("Retry"), retry_times, m!("times before connected to"),  ip, port);
                    }
                    time::sleep(jitter).await;  // 握手成功后等待随机延迟再释放连接
                    return Option::from(duration);
                }
                return None; // 没超时但连接异常
            }
            Err(_e) => { // 超时
                // info!("connect {}:{} 超时", ip, port);
                #[cfg(not(target_os = "windows"))]{
                    let error_string = _e.to_string();
                    assert!(!error_string.to_lowercase().contains("too many open files"), "Too many open files. Please reduce concurrency.");
                }
            }
        }
    }
    None
}

pub fn parse_hosts(scan_net: &String) -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    {
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
}

pub fn parse_ports(ports: String) -> Vec<u16> {
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
    port_list
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

pub async fn simple_caculation(n: i64) {
    let mut a = 0.0;
    // let start = Instant::now();

    fn fibonacci_u64(number: u64) -> u64 {
        let mut last: u64 = 1;
        let mut current: u64 = 0;
        let mut buffer: u64;
        let mut position: u64 = 1;

        return loop {
            if position == number {
                break current;
            }

            buffer = last;
            last = current;
            current = buffer + current;
            position += 1;
        };
    }

    for i in 1..n as u64 {
        for j in i..n as u64 {
            for k in i..n as u64 {
                for l in i..n as u64 {
                    for m in i..n as u64 {
                        for n in i..n as u64 {}
                        fibonacci_u64(l);
                    }
                }
            }
        }
    }
    // let _duration = start.elapsed();
    // info!("Elapsed {:?}", duration);
}

#[derive(Copy, Clone)]
pub struct Service {
    pub host: Ipv4Addr,
    pub port: u16,
    pub duration: Duration,
}

#[derive(Copy, Clone)]
pub struct ConnectConfig {
    pub timeout: u16,
    pub jitter: u16,
    pub retry: u8,
    pub wait_time: u8,  // tcp连接建立完成多少秒后测试连接的有效性
}
