package runner

import (
	"flag"
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	osutil "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/port"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/privileges"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/scan"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
)

var (
	errNoInputList   = errors.New("no input list provided")
	errOutputMode    = errors.New("both verbose and silent mode specified")
	errZeroValue     = errors.New("cannot be zero")
	errTwoOutputMode = errors.New("both json and csv mode specified")
)

// ValidateOptions validates the configuration options passed
func (options *Options) ValidateOptions() error {
	// 检查是否提供了主机、域列表或stdin信息。
	// 如果没有提供，请返回。
	if options.Host == nil && options.HostsFile == "" && !options.Stdin && len(flag.Args()) == 0 {
		return errNoInputList
	}

	// 修复 -sn 无效的情况
	if (options.WithHostDiscovery || options.OnlyHostDiscovery) && options.ScanType != SynScan {
		gologger.Warning().Msgf("host discovery requires syn scan, automatically switching to syn scan")
		options.ScanType = SynScan
	}

	// 使用了详细和无声的标志
	if options.Verbose && options.Silent {
		return errOutputMode
	}

	// 输出文件格式
	if options.JSON && options.CSV {
		return errTwoOutputMode
	}

	// 超时时间
	if options.Timeout == 0 {
		return errors.Wrap(errZeroValue, "timeout")
	} else if !privileges.IsPrivileged && options.Timeout == DefaultPortTimeoutSynScan {
		options.Timeout = DefaultPortTimeoutConnectScan
	}

	// 请求速率
	if options.Rate == 0 {
		return errors.Wrap(errZeroValue, "rate")
	} else if !privileges.IsPrivileged && options.Rate == DefaultRateSynScan {
		options.Rate = DefaultRateConnectScan
	}

	// 用户权限情况
	if !privileges.IsPrivileged && options.Retries == DefaultRetriesSynScan {
		options.Retries = DefaultRetriesConnectScan
	}

	// 网络接口
	if options.Interface != "" {
		if _, err := net.InterfaceByName(options.Interface); err != nil {
			return fmt.Errorf("interface %s not found", options.Interface)
		}
	}

	if fileutil.FileExists(options.Resolvers) {
		chanResolvers, err := fileutil.ReadFile(options.Resolvers)
		if err != nil {
			return err
		}
		for resolver := range chanResolvers {
			options.baseResolvers = append(options.baseResolvers, resolver)
		}
	} else if options.Resolvers != "" {
		for _, resolver := range strings.Split(options.Resolvers, ",") {
			options.baseResolvers = append(options.baseResolvers, strings.TrimSpace(resolver))
		}
	}

	// 被动模式启用自动流
	if options.Passive {
		options.Stream = true
	}

	// 流
	if options.Stream {
		if options.Resume {
			return errors.New("resume not supported in stream active mode")
		}
		if options.EnableProgressBar {
			return errors.New("stats not supported in stream active mode")
		}
		if options.Nmap {
			return errors.New("nmap not supported in stream active mode")
		}
	}

	// 流被动
	if options.Verify && options.Stream && !options.Passive {
		return errors.New("verify not supported in stream active mode")
	}

	// 解析并验证源IP和源端口
	// 检查源IP是否仅为IP
	isOnlyIP := iputil.IsIP(options.SourceIP)
	if options.SourceIP != "" && !isOnlyIP {
		ip, port, err := net.SplitHostPort(options.SourceIP)
		if err != nil {
			return err
		}
		options.SourceIP = ip
		options.SourcePort = port
	}

	if len(options.IPVersion) > 0 && !sliceutil.ContainsItems([]string{scan.IPv4, scan.IPv6}, options.IPVersion) {
		return errors.New("IP Version must be 4 and/or 6")
	}

	// 主机发现 == True && 主机发现被禁用 == False，则返回错误
	if !options.WithHostDiscovery && options.hasProbes() {
		return errors.New("discovery probes were provided but host discovery is disabled")
	}

	// 主机发现模式需要高特权访问
	if options.OnlyHostDiscovery && !privileges.IsPrivileged {
		if osutil.IsWindows() {
			return errors.New("host discovery not (yet) supported on windows")
		}
		return errors.New("sudo access required to perform host discovery")
	}

	// 判断端口范围
	if options.PortThreshold < 0 || options.PortThreshold > 65535 {
		return errors.New("port threshold must be between 0 and 65535")
	}

	// 判断代理情况
	if options.Proxy != "" && options.ScanType == SynScan {
		// Syn Scan不能与socks代理一起使用, 回退以"connect scan"扫描模式
		gologger.Warning().Msgf("Syn Scan can't be used with socks proxy: falling back to connect scan")
		options.ScanType = ConnectScan
	}

	if options.ScanType == SynScan && scan.PkgRouter == nil {
		gologger.Warning().Msgf("Routing could not be determined (are you using a VPN?).falling back to connect scan")
		options.ScanType = ConnectScan
	}

	if options.ServiceDiscovery || options.ServiceVersion {
		// 服务指纹以及版本扫描发现
		// todo: 加载相关的nmap指纹信息用于模拟nmap指纹库进行扫描操作
		//gologger.Info().Msgf("Running service discovery scan\n")
		return errors.New("service discovery feature is not implemented")
	}

	return nil
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	if options.NoColor {
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

// 如果未指定，ConfigureHostDiscovery将启用默认探测
// 但请求了主机发现选项
func (options *Options) configureHostDiscovery(ports []*port.Port) {
	// 如果指定端口扫描的数量少于2个则不进行主机发现
	if len(ports) <= 2 {
		gologger.Info().Msgf("Host discovery disabled: less than two ports were specified")
		options.WithHostDiscovery = false
	}
	if options.shouldDiscoverHosts() && !options.hasProbes() {
		// 如果未定义选项，则默认启用
		// - ICMP Echo Request
		// - ICMP timestamp
		// - TCP SYN on port 80
		// - TCP SYN on port 443
		// - TCP ACK on port 80
		// - TCP ACK on port 443
		options.IcmpEchoRequestProbe = true
		options.IcmpTimestampRequestProbe = true
		options.TcpSynPingProbes = append(options.TcpSynPingProbes, "80")
		options.TcpSynPingProbes = append(options.TcpSynPingProbes, "443")
		options.TcpAckPingProbes = append(options.TcpAckPingProbes, "80")
		options.TcpAckPingProbes = append(options.TcpAckPingProbes, "443")
	}
}
