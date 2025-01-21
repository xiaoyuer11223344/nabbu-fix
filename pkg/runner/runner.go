package runner

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Mzack9999/gcache"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/blackrock"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/uncover/sources/agent/shodanidb"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/remeh/sizedwaitgroup"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/port"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/privileges"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/protocol"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/result"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/scan"
)

// Runner 端口枚举实例, 客户端用于编排整个过程。
type Runner struct {
	options       *Options
	targetsFile   string
	scanner       *scan.Scanner
	limiter       *ratelimit.Limiter
	wgscan        sizedwaitgroup.SizedWaitGroup
	dnsclient     *dnsx.DNSX
	stats         *clistats.Statistics
	streamChannel chan Target

	unique gcache.Cache[string, struct{}]
}

type Target struct {
	Ip   string
	Cidr string
	Fqdn string
	Port string
}

// NewRunner 通过解析创建新的runner结构实例配置选项、配置源、阅读列表等
func NewRunner(options *Options) (*Runner, error) {
	// 日志输出等级
	options.configureOutput()

	// 解析端口
	ports, err := ParsePorts(options)
	if err != nil {
		return nil, fmt.Errorf("could not parse ports: %s", err)
	}

	// 配置主机存活探测
	options.configureHostDiscovery(ports)

	// 如果未指定 ip version，则默认为ipv4
	if len(options.IPVersion) == 0 {
		options.IPVersion = []string{scan.IPv4}
	}

	// 重试次数
	if options.Retries == 0 {
		// 默认重试为3次
		options.Retries = DefaultRetriesSynScan
	}

	// 创建新的扫描进程结构
	if options.ResumeCfg == nil {
		options.ResumeCfg = NewResumeCfg()
	}

	// 初始化runner
	runner := &Runner{
		options: options,
	}

	// DNS 客户端配置
	dnsOptions := dnsx.DefaultOptions
	dnsOptions.MaxRetries = runner.options.Retries
	dnsOptions.Hostsfile = true
	if sliceutil.Contains(options.IPVersion, "6") {
		dnsOptions.QuestionTypes = append(dnsOptions.QuestionTypes, dns.TypeAAAA)
	}
	if len(runner.options.baseResolvers) > 0 {
		dnsOptions.BaseResolvers = runner.options.baseResolvers
	}

	// dns 客户端
	dnsClient, err := dnsx.New(dnsOptions)
	if err != nil {
		return nil, err
	}
	runner.dnsclient = dnsClient

	// 获取要排除的IP地址
	excludedIps, err := runner.parseExcludedIps(options)
	if err != nil {
		return nil, err
	}

	// 要扫描的目标，用于后续如果开启stream模式的情况下使用
	runner.streamChannel = make(chan Target)

	// 缓存
	uniqueCache := gcache.New[string, struct{}](1500).Build()
	runner.unique = uniqueCache

	// 扫描配置选项
	scanOpts := &scan.Options{
		Timeout:       time.Duration(options.Timeout) * time.Millisecond,
		Retries:       options.Retries,
		Rate:          options.Rate,
		PortThreshold: options.PortThreshold,
		ExcludeCdn:    options.ExcludeCDN,
		OutputCdn:     options.OutputCDN,
		ExcludedIps:   excludedIps,
		Proxy:         options.Proxy,
		ProxyAuth:     options.ProxyAuth,
		Stream:        options.Stream,
		OnReceive:     options.OnReceive,
		ScanType:      options.ScanType,
	}

	// 数据包 callback 处理函数
	if scanOpts.OnReceive == nil {
		scanOpts.OnReceive = runner.onReceive
	}

	// scanner 配置初始化, 将scanOpts相关配置保存到scanner中
	scanner, err := scan.NewScanner(scanOpts)
	if err != nil {
		return nil, err
	}

	// 扫描器
	runner.scanner = scanner

	// 待扫描的端口
	runner.scanner.Ports = ports

	// 进度条
	if options.EnableProgressBar {
		defaultOptions := &clistats.DefaultOptions
		defaultOptions.ListenPort = options.MetricsPort
		stats, err := clistats.NewWithOptions(context.Background(), defaultOptions)
		if err != nil {
			gologger.Warning().Msgf("Couldn't create progress engine: %s\n", err)
		} else {
			runner.stats = stats
		}
	}

	return runner, nil
}

func (r *Runner) onReceive(hostResult *result.HostResult) {
	// 判断ipv4还是ipv6
	if !ipMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
		return
	}

	// 获取当前IP对应的所有host域名信息
	dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
	if err != nil {
		return
	}

	// 接收事件只有一个端口
	for _, p := range hostResult.Ports {
		// 拼接 1.1.1.1:8080
		ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))

		// 判断是否已经记录过
		if r.unique.Has(ipPort) {
			return
		}
	}

	// 从ip:port组合中恢复主机名
	for _, p := range hostResult.Ports {
		ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
		if dtOthers, ok := r.scanner.IPRanger.Hosts.Get(ipPort); ok {
			if otherName, _, err := net.SplitHostPort(string(dtOthers)); err == nil {
				// 用主机替换 裸ip:port
				for idx, ipCandidate := range dt {
					if iputil.IsIP(ipCandidate) {
						dt[idx] = otherName
					}
				}
			}
		}
		_ = r.unique.Set(ipPort, struct{}{})
	}

	csvHeaderEnabled := true

	buffer := bytes.Buffer{}
	writer := csv.NewWriter(&buffer)
	for _, host := range dt {
		// 晴空缓冲区字符串
		buffer.Reset()

		// 如果标识符为ip的话
		if host == "ip" {
			host = hostResult.IP
		}

		// CDN检测
		isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostResult.IP)

		// 保存数据到文件 (json或者是csv格式)
		if r.options.JSON || r.options.CSV {
			data := &Result{IP: hostResult.IP, TimeStamp: time.Now().UTC()}
			if r.options.OutputCDN {
				data.IsCDNIP = isCDNIP
				data.CDNName = cdnName
			}
			if host != hostResult.IP {
				data.Host = host
			}
			for _, p := range hostResult.Ports {
				data.Port = p.Port
				data.Protocol = p.Protocol.String()
				data.TLS = p.TLS
				if r.options.JSON {
					// json格式数据保存
					b, err := data.JSON()
					if err != nil {
						continue
					}
					buffer.Write([]byte(fmt.Sprintf("%s\n", b)))
				} else if r.options.CSV {
					// csv格式数据保存
					if csvHeaderEnabled {
						writeCSVHeaders(data, writer)
						csvHeaderEnabled = false
					}
					writeCSVRow(data, writer)
				}
			}
		}

		// 控制台输出内容
		if r.options.JSON {
			gologger.Silent().Msgf("%s", buffer.String())
		} else if r.options.CSV {
			writer.Flush()
			gologger.Silent().Msgf("%s", buffer.String())
		} else {
			// 默认控制台正常输出内容
			for _, p := range hostResult.Ports {
				if r.options.OutputCDN && isCDNIP {
					// 如果指定了cdn输出的话，那么就是 host:port cdn
					gologger.Silent().Msgf("%s:%d [%s]\n", host, p.Port, cdnName)
				} else {
					// host:port的内容
					gologger.Silent().Msgf("%s:%d\n", host, p.Port)
				}
			}
		}
	}
}

// RunEnumeration runs the ports enumeration flow on the targets specified
func (r *Runner) RunEnumeration(pctx context.Context) error {

	// 上下文
	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	// 开启syn scan扫描模式，是否需要自定义的一些选项
	// 1. 伪造发送来源地址和端口
	// 2. 监听数据包接口
	if privileges.IsPrivileged && r.options.ScanType == SynScan {
		if r.options.SourceIP != "" {
			err := r.SetSourceIP(r.options.SourceIP)
			if err != nil {
				return err
			}
		}
		if r.options.Interface != "" {
			err := r.SetInterface(r.options.Interface)
			if err != nil {
				return err
			}
		}
		if r.options.SourcePort != "" {
			err := r.SetSourcePort(r.options.SourcePort)
			if err != nil {
				return err
			}
		}

		// 启动后段处理器，等待扫描目标的输入
		r.BackgroundWorkers(ctx)
	}

	if r.options.Stream {
		// 流式模式
		// no lint
		go r.Load()
	} else {
		// 正常模式
		// 获取要扫描的数据
		err := r.Load()
		if err != nil {
			return err
		}
	}

	// 初始化 workers
	r.wgscan = sizedwaitgroup.New(r.options.Rate)

	// 限制每秒请求速率
	r.limiter = ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)

	// 是否进行主机存活发现
	shouldDiscoverHosts := r.options.shouldDiscoverHosts()

	// 是否开启原生数据包构造用于后续的SynScan扫描模式
	shouldUseRawPackets := r.options.shouldUseRawPackets()

	if shouldDiscoverHosts && shouldUseRawPackets {
		// 开启主机存活发现 并且 使用SynScan扫描模式 的情况下
		showHostDiscoveryInfo()

		// 标记当前scanner处于 主机发现 阶段
		r.scanner.ListenHandler.Phase.Set(scan.HostDiscovery)

		// 整理v4 和 v6 的待扫描地址
		_, targetsV4, targetsv6, _, err := r.GetTargetIps(r.getPreprocessedIps)
		if err != nil {
			return err
		}

		// 获取要排除扫描的IP地址
		excludedIPs, err := r.parseExcludedIps(r.options)
		if err != nil {
			return err
		}

		// 存储要排除扫描的IP地址
		excludedIPsMap := make(map[string]struct{})
		for _, ipString := range excludedIPs {
			excludedIPsMap[ipString] = struct{}{}
		}

		discoverCidr := func(cidr *net.IPNet) {
			// 通道保存所有要扫描的IP地址
			ipStream, _ := mapcidr.IPAddressesAsStream(cidr.String())

			// 遍历当前通道读取要扫描的IP地址
			for ip := range ipStream {
				// 仅在excluded ip映射中不存在时运行主机发现
				if _, exists := excludedIPsMap[ip]; !exists {
					// 开始扫描需要主机存活发现的地址
					// note: 如果存在相关机器是存活的话，那么该地址将会存储到  r.scanner.HostDiscoveryResults 中进行保存
					r.handleHostDiscovery(ip)
				}
			}
		}

		// 获取ipv4类型地址的存活主机
		for _, target4 := range targetsV4 {
			discoverCidr(target4)
		}

		// 获取ipv6类型地址的存活主机
		for _, target6 := range targetsv6 {
			discoverCidr(target6)
		}

		// 预热时间
		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		// 如果开启了 "仅主机发现"，那么主机发现完成之后，输出完结果后就直接停止程序
		if r.options.OnlyHostDiscovery {
			// 结果输出
			r.handleOutput(r.scanner.HostDiscoveryResults)
			return nil
		}
	}

	switch {
	case r.options.Stream && !r.options.Passive: // stream active

		// 展示 网络功能/扫描类型
		showNetworkCapabilities(r.options)

		// 阶段设置为 "scan"
		r.scanner.ListenHandler.Phase.Set(scan.Scan)

		// stream 扫描
		handleStreamIp := func(target string, port *port.Port) bool {

			// 是否需要跳过该目标
			if r.scanner.ScanResults.HasSkipped(target) {
				return false
			}

			// 扫描之前，先检查 当前ip是否存在扫描记录，并且查看该扫描记录扫描出来的端口超过 >= 阈值
			// 这种现象相当于类似cdn ip 或者 存在防火墙的情况，导致出现端口存活误报的情况
			if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(target) >= r.options.PortThreshold {
				hosts, _ := r.scanner.IPRanger.GetHostsByIP(target)
				gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", target, hosts)

				// 添加到过滤名单中，后续如果扫描的还是该目标则进行过滤操作
				r.scanner.ScanResults.AddSkipped(target)
				return false
			}

			if shouldUseRawPackets {
				// 如果开了syn扫描的话，那么则通过syn来进行探测目标端口
				r.RawSocketEnumeration(ctx, target, port)
			} else {
				r.wgscan.Add()
				go r.handleHostPort(ctx, target, port)
			}
			return true
		}

		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", target, err)
			}

			if ipStream, err := mapcidr.IPAddressesAsStream(target.Cidr); err == nil {
				// 解析当前cidr地址，通过遍历ipStream获取所有要扫描的数据
				for ip := range ipStream {
					for _, port := range r.scanner.Ports {
						// 扫描ip和对应的port
						if !handleStreamIp(ip, port) {
							break
						}
					}
				}
			} else if target.Ip != "" && target.Port != "" {
				// 1.1.1.1:8080 这种格式的 host:port
				pp, _ := strconv.Atoi(target.Port)
				handleStreamIp(target.Ip, &port.Port{Port: pp, Protocol: protocol.TCP})
			}
		}
		r.wgscan.Wait()

		// 结果处理
		r.handleOutput(r.scanner.ScanResults)
		return nil
	case r.options.Stream && r.options.Passive:
		// note: 使用shodan internetdb api显示被动开放端口

		showNetworkCapabilities(r.options)
		// create retryablehttp instance
		httpClient := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)

		// 阶段设置为 "scan"
		r.scanner.ListenHandler.Phase.Set(scan.Scan)
		for target := range r.streamChannel {
			if err := r.scanner.IPRanger.Add(target.Cidr); err != nil {
				gologger.Warning().Msgf("Couldn't track %s in scan results: %s\n", target, err)
			}
			ipStream, _ := mapcidr.IPAddressesAsStream(target.Cidr)
			for ip := range ipStream {
				r.wgscan.Add()
				go func(ip string) {
					defer r.wgscan.Done()

					// obtain ports from shodan idb
					shodanURL := fmt.Sprintf(shodanidb.URL, url.QueryEscape(ip))
					request, err := retryablehttp.NewRequest(http.MethodGet, shodanURL, nil)
					if err != nil {
						gologger.Warning().Msgf("Couldn't create http request for %s: %s\n", ip, err)
						return
					}
					r.limiter.Take()
					response, err := httpClient.Do(request)
					if err != nil {
						gologger.Warning().Msgf("Couldn't retrieve http response for %s: %s\n", ip, err)
						return
					}
					if response.StatusCode != http.StatusOK {
						gologger.Warning().Msgf("Couldn't retrieve data for %s, server replied with status code: %d\n", ip, response.StatusCode)
						return
					}

					// unmarshal the response
					data := &shodanidb.ShodanResponse{}
					if err := json.NewDecoder(response.Body).Decode(data); err != nil {
						gologger.Warning().Msgf("Couldn't unmarshal json data for %s: %s\n", ip, err)
						return
					}

					var passivePorts []*port.Port
					for _, p := range data.Ports {
						pp := &port.Port{Port: p, Protocol: protocol.TCP}
						passivePorts = append(passivePorts, pp)
					}

					filteredPorts, err := excludePorts(r.options, passivePorts)
					if err != nil {
						gologger.Warning().Msgf("Couldn't exclude ports for %s: %s\n", ip, err)
						return
					}

					for _, p := range filteredPorts {
						if r.scanner.OnReceive != nil {
							r.scanner.OnReceive(&result.HostResult{IP: ip, Ports: []*port.Port{p}})
						}
						r.scanner.ScanResults.AddPort(ip, p)
					}
				}(ip)
			}
		}
		r.wgscan.Wait()

		// 二次校验
		if r.options.Verify {
			r.ConnectVerification()
		}

		// 结果输出以及回调处理
		r.handleOutput(r.scanner.ScanResults)

		// 处理后续的nmap扫描
		return r.handleNmap()
	default:
		// 默认情况下的处理
		showNetworkCapabilities(r.options)

		// CIDR以及ipsWithPort
		ipsCallback := r.getPreprocessedIps
		if shouldDiscoverHosts && shouldUseRawPackets {
			// note: 只有cidr的数据, 这里会直接从r.scanner.HostDiscoveryResults进行获取主机存活的数据
			ipsCallback = r.getHostDiscoveryIps
		}

		// 获取要扫描的目标(如果开始HostDiscovery的话就是存活目标)
		targets, targetsV4, targetsv6, targetsWithPort, err := r.GetTargetIps(ipsCallback)
		if err != nil {
			return err
		}

		// 统计总共要扫描的IP数量
		var targetsCount, portsCount, targetsWithPortCount uint64
		for _, target := range append(targetsV4, targetsv6...) {
			if target == nil {
				continue
			}
			targetsCount += mapcidr.AddressCountIpnet(target)
		}

		// 每个IP要扫描的端口数量
		portsCount = uint64(len(r.scanner.Ports))

		// 1.1.1.1:8080 这种格式IP:PORT的扫描数量
		targetsWithPortCount = uint64(len(targetsWithPort))

		// 阶段设置为 "scan"
		r.scanner.ListenHandler.Phase.Set(scan.Scan)

		// 获取总发包次数
		Range := targetsCount * portsCount

		// 进度条
		if r.options.EnableProgressBar {
			r.stats.AddStatic("ports", portsCount)
			r.stats.AddStatic("hosts", targetsCount)
			r.stats.AddStatic("retries", r.options.Retries)
			r.stats.AddStatic("startedAt", time.Now())
			r.stats.AddCounter("packets", uint64(0))
			r.stats.AddCounter("errors", uint64(0))
			r.stats.AddCounter("total", Range*uint64(r.options.Retries)+targetsWithPortCount)
			r.stats.AddStatic("hosts_with_port", targetsWithPortCount)
			if err := r.stats.Start(); err != nil {
				gologger.Warning().Msgf("Couldn't start statistics: %s\n", err)
			}
		}

		// 由于网络不可靠，无论之前的扫描结果如何，都会执行重试
		// note: 提及下, 在sync扫描的时候由于是并发扫描, 并且默认Retries的次数为3, 所以在syn扫描的时候会出现tcp reused复用的情况
		for currentRetry := 0; currentRetry < r.options.Retries; currentRetry++ {
			// 是否超过Retries重试次数
			if currentRetry < r.options.ResumeCfg.Retry {
				gologger.Debug().Msgf("Skipping Retry: %d\n", currentRetry)
				continue
			}

			// 使用当前时间作为种子
			currentSeed := time.Now().UnixNano()
			r.options.ResumeCfg.RLock()
			if r.options.ResumeCfg.Seed > 0 {
				currentSeed = r.options.ResumeCfg.Seed
			}
			r.options.ResumeCfg.RUnlock()

			// 跟踪当前重试次数
			r.options.ResumeCfg.Lock()
			r.options.ResumeCfg.Retry = currentRetry
			r.options.ResumeCfg.Seed = currentSeed
			r.options.ResumeCfg.Unlock()

			// blackrock算法 随机化数据 且 保证每个元素只取一次
			b := blackrock.New(int64(Range), currentSeed)
			for index := int64(0); index < int64(Range); index++ {
				// 处理IP地址，非1.1.1.1:8080这种格式
				xxx := b.Shuffle(index)
				ipIndex := xxx / int64(portsCount)
				portIndex := int(xxx % int64(portsCount))
				ip := r.PickIP(targets, ipIndex)
				port := r.PickPort(portIndex)

				// 读取上一次的扫描索引记录位置
				r.options.ResumeCfg.RLock()
				resumeCfgIndex := r.options.ResumeCfg.Index
				r.options.ResumeCfg.RUnlock()

				// 如果小于上一次的扫描索引记录位置的话，那么则说明已扫描过，则进行跳过
				if index < resumeCfgIndex {
					gologger.Debug().Msgf("Skipping \"%s:%d\": Resume - Port scan already completed\n", ip, port.Port)
					continue
				}

				// 恢复cfg逻辑
				r.options.ResumeCfg.Lock()
				r.options.ResumeCfg.Index = index
				r.options.ResumeCfg.Unlock()

				// IP是否需要跳过
				// note: 这里跳过的IP是属于存在拦截或者是防火墙导致出现了大量的端口开放的情况
				if r.scanner.ScanResults.HasSkipped(ip) {
					continue
				}

				// 扫描之前，先检查 当前ip是否存在扫描记录，并且查看该扫描记录扫描出来的端口超过 >= 阈值
				// note: 这种现象相当于类似cdn ip 或者 存在防火墙的情况，导致出现端口存活误报的情况
				if r.options.PortThreshold > 0 && r.scanner.ScanResults.GetPortCount(ip) >= r.options.PortThreshold {
					hosts, _ := r.scanner.IPRanger.GetHostsByIP(ip)
					gologger.Info().Msgf("Skipping %s %v, Threshold reached \n", ip, hosts)
					// 如果存在防火墙的ip的话，那么就添加到skip名单中，下次扫描到的话就直接进行跳过即可
					r.scanner.ScanResults.AddSkipped(ip)
					continue
				}

				if shouldUseRawPackets {
					// 是否使用syn scan 扫描模式
					r.RawSocketEnumeration(ctx, ip, port)
				} else {
					// connect scan
					r.wgscan.Add()
					go r.handleHostPort(ctx, ip, port)
				}

				// 进度条展示
				if r.options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
			}

			for _, targetWithPort := range targetsWithPort {
				// 处理ip:port组合, 1.1.1.1:8080这种格式

				// 切分ip和port, 1.1.1.1:8080 -> 1.1.1.1 和 8080
				ip, p, err := net.SplitHostPort(targetWithPort)
				if err != nil {
					gologger.Debug().Msgf("Skipping %s: %v\n", targetWithPort, err)
					continue
				}

				// 本地端口查找
				pp, err := strconv.Atoi(p)
				if err != nil {
					gologger.Debug().Msgf("Skipping %s, could not cast port %s: %v\n", targetWithPort, p, err)
					continue
				}

				var portWithMetadata = port.Port{
					Port:     pp,
					Protocol: protocol.TCP,
				}

				// connect scan
				if shouldUseRawPackets {
					r.RawSocketEnumeration(ctx, ip, &portWithMetadata)
				} else {
					r.wgscan.Add()
					go r.handleHostPort(ctx, ip, &portWithMetadata)
				}
				if r.options.EnableProgressBar {
					r.stats.IncrementCounter("packets", 1)
				}
			}

			r.wgscan.Wait()

			r.options.ResumeCfg.Lock()
			if r.options.ResumeCfg.Seed > 0 {
				r.options.ResumeCfg.Seed = 0
			}
			if r.options.ResumeCfg.Index > 0 {
				// zero also the current index as we are restarting the scan
				r.options.ResumeCfg.Index = 0
			}
			r.options.ResumeCfg.Unlock()
		}

		if r.options.WarmUpTime > 0 {
			time.Sleep(time.Duration(r.options.WarmUpTime) * time.Second)
		}

		// 设置 扫描状态 为 “Done”, 标志当前的扫描阶段已经结束
		r.scanner.ListenHandler.Phase.Set(scan.Done)

		// 二次校验
		// note: 同样也是空指针进行探测，只探测当前该端口是否正常开放情况
		if r.options.Verify {
			r.ConnectVerification()
		}

		// 最终处理的结果都存储到ScanResults , 主键值形式进行存储  1.1.1.1:[80,443,8080] 形式
		r.handleOutput(r.scanner.ScanResults)

		// 前面的数据是否用于nmap
		return r.handleNmap()
	}
}

func (r *Runner) getHostDiscoveryIps() (ips []*net.IPNet, ipsWithPort []string) {
	for ip := range r.scanner.HostDiscoveryResults.GetIPs() {
		ips = append(ips, iputil.ToCidr(string(ip)))
	}

	r.scanner.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		// ips with port are ignored during host discovery phase
		if cidr := iputil.ToCidr(string(ip)); cidr == nil {
			ipsWithPort = append(ipsWithPort, string(ip))
		}
		return nil
	})

	return
}

func (r *Runner) getPreprocessedIps() (cidrs []*net.IPNet, ipsWithPort []string) {
	r.scanner.IPRanger.Hosts.Scan(func(ip, _ []byte) error {
		if cidr := iputil.ToCidr(string(ip)); cidr != nil {
			// 待扫描的IP或者是CIDR格式
			// ./nabbu -h 1.1.1.1
			// ./naabu -h 1.1.1.1/24
			cidrs = append(cidrs, cidr)
		} else {
			// 待扫描的ip:port格式
			// ./naabu -h 1.1.1.1:80
			ipsWithPort = append(ipsWithPort, string(ip))
		}

		return nil
	})
	return
}

func (r *Runner) GetTargetIps(ipsCallback func() ([]*net.IPNet, []string)) (targets, targetsV4, targetsV6 []*net.IPNet, targetsWithPort []string, err error) {

	// 获取cidr格式以及ip格式的扫描数据
	targets, targetsWithPort = ipsCallback()

	// 生成net.IPNet格式的数据
	targetsV4, targetsV6 = mapcidr.CoalesceCIDRs(targets)
	if len(targetsV4) == 0 && len(targetsV6) == 0 && len(targetsWithPort) == 0 {
		return nil, nil, nil, nil, errors.New("no valid ipv4 or ipv6 targets were found")
	}

	targets = make([]*net.IPNet, 0, len(targets))

	// 查看IPVersion是否选择协议是ipv4
	if r.options.ShouldScanIPv4() {
		targets = append(targets, targetsV4...)
	} else {
		targetsV4 = make([]*net.IPNet, 0)
	}

	// 查看IPVersion是否选择协议是ipv6
	if r.options.ShouldScanIPv6() {
		targets = append(targets, targetsV6...)
	} else {
		targetsV6 = make([]*net.IPNet, 0)
	}

	return targets, targetsV4, targetsV6, targetsWithPort, nil
}

func (r *Runner) ShowScanResultOnExit() {
	// 强制结束的情况下的处理
	r.handleOutput(r.scanner.ScanResults)
	err := r.handleNmap()
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}

// Close runner instance
func (r *Runner) Close() {
	_ = os.RemoveAll(r.targetsFile)
	_ = r.scanner.IPRanger.Hosts.Close()
	if r.options.EnableProgressBar {
		_ = r.stats.Stop()
	}
	if r.scanner != nil {
		r.scanner.Close()
	}
	if r.limiter != nil {
		r.limiter.Stop()
	}
}

// PickIP randomly
func (r *Runner) PickIP(targets []*net.IPNet, index int64) string {
	for _, target := range targets {
		subnetIpsCount := int64(mapcidr.AddressCountIpnet(target))
		if index < subnetIpsCount {
			return r.PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

func (r *Runner) PickSubnetIP(network *net.IPNet, index int64) string {
	ipInt, bits, err := mapcidr.IPToInteger(network.IP)
	if err != nil {
		gologger.Warning().Msgf("%s\n", err)
		return ""
	}
	subnetIpInt := big.NewInt(0).Add(ipInt, big.NewInt(index))
	ip := mapcidr.IntegerToIP(subnetIpInt, bits)
	return ip.String()
}

func (r *Runner) PickPort(index int) *port.Port {
	return r.scanner.Ports[index]
}

func (r *Runner) ConnectVerification() {
	// 标记当前阶段为 "扫描" 阶段
	r.scanner.ListenHandler.Phase.Set(scan.Scan)
	var swg sync.WaitGroup
	limiter := ratelimit.New(context.Background(), uint(r.options.Rate), time.Second)
	defer limiter.Stop()

	verifiedResult := result.NewResult()

	for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
		limiter.Take()
		swg.Add(1)
		go func(hostResult *result.HostResult) {
			defer swg.Done()
			results := r.scanner.ConnectVerify(hostResult.IP, hostResult.Ports)

			// 设置对应的ip的端口开放情况
			verifiedResult.SetPorts(hostResult.IP, results)
		}(hostResult)
	}

	// 保存扫描结果
	r.scanner.ScanResults = verifiedResult

	swg.Wait()
}

func (r *Runner) BackgroundWorkers(ctx context.Context) {
	r.scanner.StartWorkers(ctx)
}

func (r *Runner) RawSocketHostDiscovery(ip string) {
	r.handleHostDiscovery(ip)
}

func (r *Runner) RawSocketEnumeration(ctx context.Context, ip string, p *port.Port) {
	select {
	case <-ctx.Done():
		return
	default:
		// cdn/waf扫描排除检查
		if !r.canIScanIfCDN(ip, p) {
			gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", ip, p.Port)
			return
		}

		// 查看扫描结果中是否已经保存了该ip的端口扫描结果
		if r.scanner.ScanResults.IPHasPort(ip, p) {
			return
		}

		r.limiter.Take()
		switch p.Protocol {
		case protocol.TCP:
			// syn 构造 tcp 请求
			r.scanner.EnqueueTCP(ip, scan.Syn, p)
		case protocol.UDP:
			// 构造 udp 请求
			r.scanner.EnqueueUDP(ip, p)
		}
	}
}

// check if an ip can be scanned in case CDN/WAF exclusions are enabled
// 检查在启用CDN/WAF排除的情况下是否可以扫描ip
func (r *Runner) canIScanIfCDN(host string, port *port.Port) bool {
	// 如果不排除CDN ips，则允许所有扫描
	if !r.options.ExcludeCDN {
		return true
	}

	// if exclusion is enabled, but the ip is not part of the CDN/WAF ips range we can scan
	// 如果启用了排除，但该ip不属于我们可以扫描的CDN/WAF-ips范围
	if ok, _, err := r.scanner.CdnCheck(host); err == nil && !ok {
		return true
	}

	// 虽然是cdn，但是当前扫描的80或者是443端口，那么这种情况是允许的
	return port.Port == 80 || port.Port == 443
}

func (r *Runner) handleHostPort(ctx context.Context, host string, p *port.Port) {
	defer r.wgscan.Done()

	select {
	case <-ctx.Done():
		return
	default:
		// CDN检测
		if !r.canIScanIfCDN(host, p) {
			gologger.Debug().Msgf("Skipping cdn target: %s:%d\n", host, p.Port)
			return
		}

		// 该host是否需要该端口对应的扫描操作, 如果对应的ip已经发送过包了，那么下次就不进行发包
		if r.scanner.ScanResults.IPHasPort(host, p) {
			return
		}

		// 限制速率
		r.limiter.Take()

		// 套接字连接端口
		open, err := r.scanner.ConnectPort(host, p, time.Duration(r.options.Timeout)*time.Millisecond)

		if open && err == nil {
			// 添加已经扫描的端口，防止另外的域名解析的ip相同的时候重复进行扫描，浪费资源
			r.scanner.ScanResults.AddPort(host, p)

			//if r.options.ServiceDiscovery {
			//	// todo: 端口指纹识别
			//	// 根据当前端口的情况获取要探测的指纹
			//	useProbe := r.scanner.UseProbe(p)
			//
			//	// 进行端口指纹识别
			//	result, _, status := r.scanner.ScanProbe(host, p, &useProbe)
			//}

			// 回调OnReceive处理结果
			if r.scanner.OnReceive != nil {
				r.scanner.OnReceive(&result.HostResult{IP: host, Ports: []*port.Port{p}})
			}
		}

		// 存在err的情况的话，那么添加一个空指针的port类型，作用只是为了给"Host"做一个标识
		if err != nil {
			r.scanner.ScanResults.AddIp(host)
		}
	}
}

func (r *Runner) handleHostDiscovery(host string) {
	// 速率限制
	r.limiter.Take()

	// Ping扫描，Icmp Echo Request
	if r.options.IcmpEchoRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpEchoRequest)
	}

	// Icmp扫描，Timestamp Request
	if r.options.IcmpTimestampRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpTimestampRequest)
	}

	// - Icmp Netmask Request
	if r.options.IcmpAddressMaskRequestProbe {
		r.scanner.EnqueueICMP(host, scan.IcmpAddressMaskRequest)
	}

	// ARP scan
	// arp扫描
	if r.options.ArpPing {
		r.scanner.EnqueueEthernet(host, scan.Arp)
	}

	// Syn Probes
	// 自定义 TcpSynPingProbes
	if len(r.options.TcpSynPingProbes) > 0 {
		ports, _ := parsePortsSlice(r.options.TcpSynPingProbes)
		r.scanner.EnqueueTCP(host, scan.Syn, ports...)
	}

	// Ack Probes
	// 自定义 TcpAckPingProbes
	if len(r.options.TcpAckPingProbes) > 0 {
		ports, _ := parsePortsSlice(r.options.TcpAckPingProbes)
		r.scanner.EnqueueTCP(host, scan.Ack, ports...)
	}

	// IPv6-ND (for now we broadcast ICMPv6 to ff02::1)
	if r.options.IPv6NeighborDiscoveryPing {
		r.scanner.EnqueueICMP("ff02::1", scan.Ndp)
	}
}

func (r *Runner) SetSourceIP(sourceIP string) error {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return errors.New("invalid source ip")
	}

	switch {
	case iputil.IsIPv4(sourceIP):
		r.scanner.ListenHandler.SourceIp4 = ip
	case iputil.IsIPv6(sourceIP):
		r.scanner.ListenHandler.SourceIP6 = ip
	default:
		return errors.New("invalid ip type")
	}

	return nil
}

func (r *Runner) SetSourcePort(sourcePort string) error {
	isValidPort := iputil.IsPort(sourcePort)
	if !isValidPort {
		return errors.New("invalid source port")
	}

	port, err := strconv.Atoi(sourcePort)
	if err != nil {
		return err
	}

	r.scanner.ListenHandler.Port = port

	return nil
}

func (r *Runner) SetInterface(interfaceName string) error {
	networkInterface, err := net.InterfaceByName(r.options.Interface)
	if err != nil {
		return err
	}

	r.scanner.NetworkInterface = networkInterface
	r.scanner.ListenHandler.SourceHW = networkInterface.HardwareAddr
	return nil
}

func (r *Runner) handleOutput(scanResults *result.Result) {
	var (
		file   *os.File
		err    error
		output string
	)

	// 如果用户给出了输出文件，请将所有找到的端口写入输出文件。
	if r.options.Output != "" {
		output = r.options.Output

		// 如果文件夹路径不存在则进行新建
		outputFolder := filepath.Dir(output)
		if fileutil.FolderExists(outputFolder) {
			mkdirErr := os.MkdirAll(outputFolder, 0700)
			if mkdirErr != nil {
				gologger.Error().Msgf("Could not create output folder %s: %s\n", outputFolder, mkdirErr)
				return
			}
		}

		// 创建文件
		file, err = os.Create(output)
		if err != nil {
			gologger.Error().Msgf("Could not create file %s: %s\n", output, err)
			return
		}
		defer file.Close()
	}
	csvFileHeaderEnabled := true

	switch {
	case scanResults.HasIPsPorts():
		// 如果存在某个ip存在端口开放的情况
		// len(r.ipPorts) > 0

		// 遍历所有存在(ip存在端口开放的情况)
		for hostResult := range scanResults.GetIPsPorts() {
			// 获取对应的Host信息(一般来说都是域名)
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostResult.IP)
			if err != nil {
				continue
			}

			// 判断当前 hostResult.IP 是否符合  IPVersion(ipv4 ipv6)的格式
			if !ipMatchesIpVersions(hostResult.IP, r.options.IPVersion...) {
				continue
			}

			// 遍历当前结果中开放的所有端口
			for _, p := range hostResult.Ports {
				// 拼接 1.1.1.1:80 形式
				ipPort := net.JoinHostPort(hostResult.IP, fmt.Sprint(p.Port))
				if dtOthers, ok := r.scanner.IPRanger.Hosts.Get(ipPort); ok {
					if otherName, _, err := net.SplitHostPort(string(dtOthers)); err == nil {
						// 主机 替换 裸ip:port
						for idx, ipCandidate := range dt {
							if iputil.IsIP(ipCandidate) {
								dt[idx] = otherName
							}
						}
					}
				}
			}

			buffer := bytes.Buffer{}
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostResult.IP
				}

				// 是否存在Cdn
				isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostResult.IP)
				gologger.Info().Msgf("Found %d ports on host %s (%s)\n", len(hostResult.Ports), host, hostResult.IP)

				// 文件保存
				if file != nil {
					if r.options.JSON {
						err = WriteJSONOutput(host, hostResult.IP, hostResult.Ports, r.options.OutputCDN, isCDNIP, cdnName, file)
					} else if r.options.CSV {
						err = WriteCsvOutput(host, hostResult.IP, hostResult.Ports, r.options.OutputCDN, isCDNIP, cdnName, csvFileHeaderEnabled, file)
					} else {
						// 输出
						err = WriteHostOutput(host, hostResult.Ports, r.options.OutputCDN, cdnName, file)
					}
					if err != nil {
						gologger.Error().Msgf("Could not write results to file %s for %s: %s\n", output, host, err)
					}
				}

				// 当前主机所有扫描端口开放结果的回调处理
				if r.options.OnResult != nil {
					r.options.OnResult(&result.HostResult{Host: host, IP: hostResult.IP, Ports: hostResult.Ports})
				}
			}
			csvFileHeaderEnabled = false
		}
	case scanResults.HasIPS():
		// 指定-host 是ip的情况
		for hostIP := range scanResults.GetIPs() {
			dt, err := r.scanner.IPRanger.GetHostsByIP(hostIP)
			if err != nil {
				continue
			}

			// 匹配 ip version
			if !ipMatchesIpVersions(hostIP, r.options.IPVersion...) {
				continue
			}

			buffer := bytes.Buffer{}
			writer := csv.NewWriter(&buffer)
			for _, host := range dt {
				buffer.Reset()
				if host == "ip" {
					host = hostIP
				}

				// 检测是否存在cdn
				isCDNIP, cdnName, _ := r.scanner.CdnCheck(hostIP)
				gologger.Info().Msgf("Found alive host %s (%s)\n", host, hostIP)

				// 控制台输出
				if r.options.JSON || r.options.CSV {
					data := &Result{IP: hostIP, TimeStamp: time.Now().UTC()}
					if r.options.OutputCDN {
						data.IsCDNIP = isCDNIP
						data.CDNName = cdnName
					}
					if host != hostIP {
						data.Host = host
					}
				}
				if r.options.JSON {
					gologger.Silent().Msgf("%s", buffer.String())
				} else if r.options.CSV {
					writer.Flush()
					gologger.Silent().Msgf("%s", buffer.String())
				} else {
					if r.options.OutputCDN && isCDNIP {
						gologger.Silent().Msgf("%s [%s]\n", host, cdnName)
					} else {
						gologger.Silent().Msgf("%s\n", host)
					}
				}

				// 文件保存
				if file != nil {
					if r.options.JSON {
						err = WriteJSONOutput(host, hostIP, nil, r.options.OutputCDN, isCDNIP, cdnName, file)
					} else if r.options.CSV {
						err = WriteCsvOutput(host, hostIP, nil, r.options.OutputCDN, isCDNIP, cdnName, csvFileHeaderEnabled, file)
					} else {
						err = WriteHostOutput(host, nil, r.options.OutputCDN, cdnName, file)
					}
					if err != nil {
						gologger.Error().Msgf("Could not write results to file %s for %s: %s\n", output, host, err)
					}
				}

				// OnResult 自定义回调函数处理
				if r.options.OnResult != nil {
					r.options.OnResult(&result.HostResult{Host: host, IP: hostIP})
				}
			}
			csvFileHeaderEnabled = false
		}
	}
}

func ipMatchesIpVersions(ip string, ipVersions ...string) bool {
	for _, ipVersion := range ipVersions {
		if ipVersion == scan.IPv4 && iputil.IsIPv4(ip) {
			return true
		}
		if ipVersion == scan.IPv6 && iputil.IsIPv6(ip) {
			return true
		}
	}
	return false
}
