package runner

import (
	"fmt"
	"github.com/google/uuid"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	osutil "github.com/projectdiscovery/utils/os"
)

func (r *Runner) handleNmap() error {
	// 是否指定 --nmap-cli
	command := r.options.NmapCLI
	hasCLI := r.options.NmapCLI != ""
	if hasCLI {
		var ipsPorts []*result.HostResult

		// 获取已经扫描的结果数据
		for hostResult := range r.scanner.ScanResults.GetIPsPorts() {
			// 将所有扫描的结果都保存到ipsPorts
			ipsPorts = append(ipsPorts, hostResult)
		}

		// 端口数量从小到大进行排序
		// note: 优先扫描端口数量少 -> 端口数量多
		sort.Slice(ipsPorts, func(i, j int) bool {
			return len(ipsPorts[i].Ports) < len(ipsPorts[j].Ports)
		})

		// suggests commands grouping ips in pseudo-exp ranges
		// 0 - 100 ports
		// 100 - 1000 ports
		// 1000 - 10000 ports
		// 10000 - 60000 ports
		ranges := make(map[int][]*result.HostResult) // for better readability
		// collect the indexes corresponding to ranges changes
		for _, ipPorts := range ipsPorts {
			// 查看当前地址对应的开放端口的数量
			length := len(ipPorts.Ports)

			// 根据 开放端口数量 分级 1 2 3 0 级别来归类 IP
			var index int
			switch {
			case length > 100 && length < 1000:
				index = 1
			case length >= 1000 && length < 10000:
				index = 2
			case length >= 10000:
				index = 3
			default:
				//  0 < length <= 100
				index = 0
			}

			ranges[index] = append(ranges[index], ipPorts)
		}

		for _, _range := range ranges {
			args := strings.Split(command, " ")
			var (
				ips   []string
				ports []string
			)

			allPorts := make(map[int]struct{})
			for _, ipPorts := range _range {
				// 聚合每个分类完登录下面的所有的IP
				ips = append(ips, ipPorts.IP)
				for _, pp := range ipPorts.Ports {
					allPorts[pp.Port] = struct{}{}
				}
			}

			// 聚合每个分类等级下面的所有的IP的端口信息
			for p := range allPorts {
				ports = append(ports, fmt.Sprint(p))
			}

			// 如果前面的数据没有开放端口的话，那么就不执行
			if len(ports) == 0 {
				continue
			}

			// ',' 拼接所有端口信息，后续作为nmap的-p参数进行使用
			portsStr := strings.Join(ports, ",")

			// ' ' 拼接所有的IP信息，后续作为nmap的IP地址参数进行使用
			ipsStr := strings.Join(ips, " ")

			// 添加端口参数
			args = append(args, "-p", portsStr)

			// 添加IP参数
			args = append(args, ips...)

			// 判断当前nmap命令是否可用于执行
			commandCanBeExecuted := isCommandExecutable(args)

			// 是否需要支持nmap进行调用
			if (r.options.Nmap || hasCLI) && commandCanBeExecuted {
				gologger.Info().Msgf("Running nmap command: %s -p %s %s", command, portsStr, ipsStr)
				// check when user type '-nmap-cli "nmap -sV"'
				// automatically remove nmap
				posArgs := 0
				// nmapCommand helps to check if user is on a Windows machine
				nmapCommand := "nmap"
				if args[0] == "nmap" || args[0] == "nmap.exe" {
					posArgs = 1
				}

				var uuidString string
				if r.options.NmapOx || r.options.NmapOj {
					// 替换uuid字符串
					args, uuidString = replaceUUIDs(args)
				}

				// if it's windows search for the executable
				if osutil.IsWindows() {
					nmapCommand = "nmap.exe"
				}

				// 命令参数
				cmd := exec.Command(nmapCommand, args[posArgs:]...)

				// 结果输出
				if !r.options.Silent {
					cmd.Stdout = os.Stdout
				}

				// 执行命令
				err := cmd.Run()
				if err != nil {
					errMsg := errors.Wrap(err, "Could not run nmap command")
					gologger.Error().Msg(errMsg.Error())
					return errMsg
				}

				// callback处理
				if r.options.OnNMAPCallback != nil {
					// todo: 后期逻辑需要进一步优化
					var nmapParse *result.NmapResult
					var data []byte
					if r.options.NmapOx || r.options.NmapOj {
						// todo: 指定文件输出的情况
						data, err = os.ReadFile(DefaultNmapFilePath(uuidString))
					} else {
						// todo: 获取stdout内容转换为nmap结果
					}

					if err != nil {
						gologger.Error().Msg(err.Error())
					}

					nmapParse, err = result.NmapResultParse(data)
					if err != nil {
						gologger.Error().Msg(err.Error())
					}

					// todo: 回调处理
					r.options.OnNMAPCallback(ipsPorts, nmapParse)
				} else {
					data, errMsg := os.ReadFile(DefaultNmapFilePath(uuidString))
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					nmapParse, errMsg := result.NmapResultParse(data)
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}
					for _, host := range nmapParse.Hosts {
						for _, addr := range host.Addresses {
							for _, port := range host.Ports {
								// 整理 ip:port 对齐 host:port
								// 获取对应ip的host信息

								// note: 这里的hosts存在ipv4 或者是 ipv6的情况，如果需要过滤的话可以通过ipversion来进行筛选
								hosts, _ := r.scanner.IPRanger.GetHostsByIP(addr.Addr)
								fmt.Println("hosts: ", hosts)
								fmt.Println(addr.Addr, addr.AddrType, port.Protocol, port.PortId, port.State.State, port.Service.Name, port.Service.Product, port.Service.CPEs)
							}
						}
					}
				}
			} else {
				gologger.Info().Msgf("Suggested nmap command: %s -p %s %s", command, portsStr, ipsStr)
			}
		}
	}

	return nil
}

func isCommandExecutable(args []string) bool {
	commandLength := calculateCmdLength(args)
	if osutil.IsWindows() {
		// windows has a hard limit of
		// - 2048 characters in XP
		// - 32768 characters in Win7
		return commandLength < 2048
	}
	// linux and darwin
	return true
}

func calculateCmdLength(args []string) int {
	var commandLength int
	for _, arg := range args {
		commandLength += len(arg)
		commandLength += 1 // space character
	}
	return commandLength
}

// DefaultNmapFilePath returns the default nmap file full path
func DefaultNmapFilePath(uuid string) string {
	return filepath.Join("/tmp/", uuid)
}

// cleanDupData
// @Description: 清理重复数据
func cleanDupData() {

}

// replaceUUIDs
// @Description: 生成uuid字符串用于替换命令行中的${uuid}标识符
// @param args
// @param format
// @return []string
func replaceUUIDs(args []string) ([]string, string) {
	// Generate a new UUID v4
	newUUID := uuid.New().String()

	for i, arg := range args {
		if strings.Contains(arg, "${uuid}") {
			// Replace {uuid} in the argument with the new UUID
			args[i] = strings.ReplaceAll(arg, "${uuid}", newUUID)
		}
	}
	return args, newUUID
}
