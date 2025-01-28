package runner

import (
	"fmt"
	"github.com/google/uuid"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/port"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	osutil "github.com/projectdiscovery/utils/os"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/result"
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

				var nmapResults []*result.NmapResult

				// todo: callback
				if r.options.OnNMAPCallback != nil && (r.options.NmapOx || r.options.NmapOj) {
					data, errMsg := os.ReadFile(DefaultNmapFilePath(uuidString))
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					nmapParse, errMsg := result.NmapResultParse(data)
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					for _, nmapHost := range nmapParse.Hosts {
						for _, nmapAddr := range nmapHost.Addresses {
							var ip2hosts []string
							ip2hosts, err = r.scanner.IPRanger.GetHostsByIP(nmapAddr.Addr)
							if err != nil || len(ip2hosts) == 0 {
								continue
							}

							var found bool
							for i, nR := range nmapResults {
								if nR.IP == nmapAddr.Addr {
									for _, hostname := range ip2hosts {
										if !stringsutil.EqualFoldAny(hostname, nR.Hosts...) {
											nmapResults[i].Hosts = append(nmapResults[i].Hosts, hostname)
										}
									}

									for _, _port := range nmapHost.Ports {

										newPort := &port.Port{
											Port:       _port.PortId,
											Service:    _port.Service.Name,
											Product:    _port.Service.Product,
											Version:    _port.Service.Version,
											ExtraInfo:  _port.Service.ExtraInfo,
											DeviceType: _port.Service.DeviceType,
											ServiceFp:  _port.Service.ServiceFp,
											CPE:        strings.Join(result.ConvertCPEsToStrings(_port.Service.CPEs), ","),
										}

										// todo: null -> unknown
										if _port.Service.Name == "" {
											newPort.Service = "unknown"
										}

										// todo: http+tls -> https
										if _port.Service.Name == "http" {
											if _port.Service.Tunnel == "ssl" {
												newPort.Service = "https"
											}
										}

										exist := false
										for _, existPort := range nmapResults[i].Ports {
											if existPort.Port == newPort.Port && existPort.Service == newPort.Service {
												exist = true
												break
											}
										}

										if !exist {
											nmapResults[i].Ports = append(nmapResults[i].Ports, newPort)
										}
									}

									found = true
									break
								}
							}

							// 如果没有找到则添加新的记录
							if !found {
								_hosts := make([]string, 0)
								_ports := make([]*port.Port, 0)

								for _, _host := range ip2hosts {
									if !stringsutil.EqualFoldAny(_host, _hosts...) {
										_hosts = append(_hosts, _host)
									}
								}

								// 去重并添加端口
								for _, _port := range nmapHost.Ports {
									newPort := &port.Port{
										Port:       _port.PortId,
										Service:    _port.Service.Name,
										Product:    _port.Service.Product,
										Version:    _port.Service.Version,
										ExtraInfo:  _port.Service.ExtraInfo,
										DeviceType: _port.Service.DeviceType,
										ServiceFp:  _port.Service.ServiceFp,
										CPE:        strings.Join(result.ConvertCPEsToStrings(_port.Service.CPEs), ","),
									}

									// todo: null -> unknown
									if _port.Service.Name == "" {
										newPort.Service = "unknown"
									}

									// todo: http+tls -> https
									if _port.Service.Name == "http" {
										if _port.Service.Tunnel == "ssl" {
											newPort.Service = "https"
										}
									}

									exist := false
									for _, existPort := range _ports {
										if existPort.Port == newPort.Port && existPort.Service == newPort.Service {
											exist = true
											break
										}
									}

									if !exist {
										_ports = append(_ports, newPort)
									}
								}

								nmapResults = append(nmapResults, &result.NmapResult{
									IP:    nmapAddr.Addr,
									Hosts: _hosts,
									Ports: _ports,
								})
							}
						}
					}

					r.options.OnNMAPCallback(nmapResults)

				} else {
					// todo: test data
					data, errMsg := os.ReadFile(DefaultNmapFilePath(uuidString))
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					nmapParse, errMsg := result.NmapResultParse(data)
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					for _, nmapHost := range nmapParse.Hosts {
						for _, nmapAddr := range nmapHost.Addresses {
							ip2hosts, err := r.scanner.IPRanger.GetHostsByIP(nmapAddr.Addr)
							if err != nil || len(ip2hosts) == 0 {
								continue
							}

							var found bool
							for i, nR := range nmapResults {
								if nR.IP == nmapAddr.Addr {
									for _, hostname := range ip2hosts {
										if !stringsutil.EqualFoldAny(hostname, nR.Hosts...) {
											nmapResults[i].Hosts = append(nmapResults[i].Hosts, hostname)
										}
									}

									for _, _port := range nmapHost.Ports {
										newPort := &port.Port{
											Port:       _port.PortId,
											Service:    _port.Service.Name,
											Product:    _port.Service.Product,
											Version:    _port.Service.Version,
											ExtraInfo:  _port.Service.ExtraInfo,
											DeviceType: _port.Service.DeviceType,
											ServiceFp:  _port.Service.ServiceFp,
											CPE:        strings.Join(result.ConvertCPEsToStrings(_port.Service.CPEs), ","),
										}

										// todo: null -> unknown
										if _port.Service.Name == "" {
											newPort.Service = "unknown"
										}

										// todo: http+tls -> https
										if _port.Service.Name == "http" {
											if _port.Service.Tunnel == "ssl" {
												newPort.Service = "https"
											}
										}

										exist := false
										for _, existPort := range nmapResults[i].Ports {
											if existPort.Port == newPort.Port && existPort.Service == newPort.Service {
												exist = true
												break
											}
										}

										if !exist {
											nmapResults[i].Ports = append(nmapResults[i].Ports, newPort)
										}
									}

									found = true
									break
								}
							}

							// 如果没有找到则添加新的记录
							if !found {
								_hosts := make([]string, 0)
								_ports := make([]*port.Port, 0)

								for _, _host := range ip2hosts {
									if !stringsutil.EqualFoldAny(_host, _hosts...) {
										_hosts = append(_hosts, _host)
									}
								}

								// 去重并添加端口
								for _, _port := range nmapHost.Ports {
									newPort := &port.Port{
										Port:       _port.PortId,
										Service:    _port.Service.Name,
										Product:    _port.Service.Product,
										Version:    _port.Service.Version,
										ExtraInfo:  _port.Service.ExtraInfo,
										DeviceType: _port.Service.DeviceType,
										ServiceFp:  _port.Service.ServiceFp,
										CPE:        strings.Join(result.ConvertCPEsToStrings(_port.Service.CPEs), ","),
									}

									// todo: null -> unknown
									if _port.Service.Name == "" {
										newPort.Service = "unknown"
									}

									// todo: http+tls -> https
									if _port.Service.Name == "http" {
										if _port.Service.Tunnel == "ssl" {
											newPort.Service = "https"
										}
									}

									exist := false
									for _, existPort := range _ports {
										if existPort.Port == newPort.Port && existPort.Service == newPort.Service {
											exist = true
											break
										}
									}
									if !exist {
										_ports = append(_ports, newPort)
									}
								}

								nmapResults = append(nmapResults, &result.NmapResult{
									IP:    nmapAddr.Addr,
									Hosts: _hosts,
									Ports: _ports,
								})
							}

							// 输出相关信息（可选）
							//fmt.Println("hosts: ", ip2hosts)
							//for _, port := range nmapHost.Ports {
							//	fmt.Println(nmapAddr.Addr, nmapAddr.AddrType, port.Protocol, port.PortId, port.State.State, port.Service.Name, port.Service.Product, port.Service.CPEs)
							//}
						}
					}

					for _, _result := range nmapResults {
						fmt.Printf("%+v\n", _result)
						for _, _port := range _result.Ports {
							fmt.Println(_port.Port, _port.Service, _port.Product, _port.Version, _port.ExtraInfo, _port.CPE, _port.DeviceType, _port.ServiceFp)
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
