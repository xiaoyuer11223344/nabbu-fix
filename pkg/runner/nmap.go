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

				if r.options.OnNMAPCallback != nil && (r.options.NmapOx || r.options.NmapOj) {
					// todo: callback回调处理

					data, errMsg := os.ReadFile(DefaultNmapFilePath(uuidString))
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					nmapParse, errMsg := result.NmapResultParse(data)
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					// todo: 数据格式 {"ip":addr.Addr, "host": [host1,host2,host3], "port": ["80","443","8080"]}
					ipHostMap := make(map[string]map[string][]string)

					for _, nmapHost := range nmapParse.Hosts {
						for _, nmapAddr := range nmapHost.Addresses {
							if _, exists := ipHostMap[nmapAddr.Addr]; !exists {
								ipHostMap[nmapAddr.Addr] = map[string][]string{
									"host": {}, // 初始化为空切片
									"port": {}, // 固定端口列表，可以根据需要修改
								}
							}

							var ip2hosts []string
							ip2hosts, err = r.scanner.IPRanger.GetHostsByIP(nmapAddr.Addr)
							if err != nil || len(ip2hosts) == 0 {
								continue
							}

							for _, hostname := range ip2hosts {
								hostFound := false
								for _, existHost := range ipHostMap[nmapAddr.Addr]["host"] {
									if existHost == hostname {
										hostFound = true
										break
									}
								}
								if !hostFound {
									ipHostMap[nmapAddr.Addr]["host"] = append(ipHostMap[nmapAddr.Addr]["host"], hostname)
								}
							}

							for _, port := range nmapHost.Ports {
								portFound := false

								portIdString := fmt.Sprintf("%d", port.PortId)

								for _, existPort := range ipHostMap[nmapAddr.Addr]["port"] {
									if existPort == portIdString {
										portFound = true
										break
									}
								}
								if !portFound {
									ipHostMap[nmapAddr.Addr]["port"] = append(ipHostMap[nmapAddr.Addr]["Port"], portIdString)
								}
							}
						}

					}

					// callback处理
					r.options.OnNMAPCallback(ipHostMap)

				} else {

					data, errMsg := os.ReadFile(DefaultNmapFilePath(uuidString))
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					nmapParse, errMsg := result.NmapResultParse(data)
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					// todo: 数据格式 {"ip":addr.Addr, "host": [host1,host2,host3], "port": ["80","443","8080"]}
					ipHostMap := make(map[string]map[string][]string)

					for _, nmapHost := range nmapParse.Hosts {
						for _, nmapAddr := range nmapHost.Addresses {
							if _, exists := ipHostMap[nmapAddr.Addr]; !exists {
								ipHostMap[nmapAddr.Addr] = map[string][]string{
									"host": {}, // 初始化为空切片
									"port": {}, // 固定端口列表，可以根据需要修改
								}
							}

							var ip2hosts []string
							ip2hosts, err = r.scanner.IPRanger.GetHostsByIP(nmapAddr.Addr)
							if err != nil || len(ip2hosts) == 0 {
								continue
							}

							for _, hostname := range ip2hosts {
								hostFound := false
								for _, existHost := range ipHostMap[nmapAddr.Addr]["host"] {
									if existHost == hostname {
										hostFound = true
										break
									}
								}
								if !hostFound {
									ipHostMap[nmapAddr.Addr]["host"] = append(ipHostMap[nmapAddr.Addr]["host"], hostname)
								}
							}

							for _, port := range nmapHost.Ports {
								portFound := false

								portIdString := fmt.Sprintf("%d", port.PortId)

								for _, existPort := range ipHostMap[nmapAddr.Addr]["port"] {
									if existPort == portIdString {
										portFound = true
										break
									}
								}
								if !portFound {
									ipHostMap[nmapAddr.Addr]["port"] = append(ipHostMap[nmapAddr.Addr]["Port"], portIdString)
								}
							}

							// 输出相关信息（可选）
							//fmt.Println("hosts: ", ip2hosts)
							//for _, port := range nmapHost.Ports {
							//	fmt.Println(nmapAddr.Addr, nmapAddr.AddrType, port.Protocol, port.PortId, port.State.State, port.Service.Name, port.Service.Product, port.Service.CPEs)
							//}
						}
					}

					fmt.Printf("ipHostMap: %+v", ipHostMap)
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
