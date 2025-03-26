## 简介
一个单纯的端口扫描器，基于tokio实现，仅具备TCP端口扫描功能。具备以下特性：
- 异步扫描
- 并发控制
- 存活探测
- 端口优先
- 识别非正常开放的端口
- 根据权限自动调整ping方式
- 端口数量超过1000则优先扫描常用端口
- linux中自动调整ulimit

### 存活探测
#### 主机存活探测
默认通过以下两种方式探测存活主机
1. icmp ping：首先尝试使用Raw Socket方式去ping，如果失败则使用ping命令（Linux）或者`IcmpSendEcho` API（Windows）。默认开启，如果需要关闭请使用 `--np` 参数
2. 扫描常用端口：默认是`21,22,23,80-83,443,445,3389,8080`，可以通过 `--pe`参数指定。默认开启，如果需要关闭请使用 `--npd` 参数

#### 子网存活探测
子网存活探测适用于扫描较大的内网时，通过对网关（.1和.254）进行存活探测判断C段子网是否有存活主机，以提高扫描速度。对网关的存活探测过程与主机存活探测相同。
默认开启，如需要关闭请使用 `--ngd` 参数

### 识别非正常开放的端口
某些特殊情况下，扫描目标时可能会遇到所有端口全部开放，但实际上绝大多数端口都是假开放状态。
对于这种情况，可以使用 `-w` 参数指定等待时间（单位：秒），TCP连接成功后，等待一段时间再发送一个字节的数据，如果发送失败，则将该端口标记为假开放状态。
该参数往往需要设置成20秒以上，这意味着扫描时间大幅增加，如果扫描单个主机，可以通过nc测试目标机器的空闲超时，将该参数尽可能设置地小。如果扫描多个目标，则应取所有机器的最大值。


### 从文件导入IP地址
一行一个的IP地址，IP地址可以是CIDR格式，也可以是IP地址范围，例如：
```
192.168.0.0/16
172.16.0.0/12
192.168.0.1-192.168.2.100
10.0.0.1
```

## 用法
```shell
Options:
  -t, --target <target>            Target need to scan. Example: 10.0.0.0/8,172.16.0.0-172.31.255.255,192.168.1.1
  -p, --port <port>                Ports to scan. Example: 21,22,80-83,db,web,win,goby_enterprise,goby_common,goby_default,fscan_default [default: goby_enterprise]
      --timeout <timeout>          Connection timeout, the unit is seconds. [default: 2]
  -r, --retry <retry>              Retry times [default: 1]
  -c, --concurrency <concurrency>  Maximum concurrency [default: 600]
      --ngd                        Not discovery gateway
      --np                         Not use ping to discover alive hosts
      --npd                        Not use port scan to discover alive hosts
      --ps <discovery_ports>       Ports used to discovery alive hosts [default: 21,22,23,80-83,443,445,3389,8080]
  -i, --infile <infile>            Input file contains IP address
  -o, --outfile <outfile>          Output file
  -w, --wait-time <wait_time>      After the TCP connection is established, wait for a few seconds before verifying if the connection is still connected. [default: 0]
      --log-file <log_file>        Log file
      --log-level <log_level>      Log level [default: info]
  -h, --help                       Print help
  -V, --version                    Print version
```
