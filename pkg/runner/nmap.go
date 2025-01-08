package runner

import (
	"fmt"
	"github.com/google/uuid"
	"os"
	"os/exec"
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
			// 分级 1 2 3 0 级别来归类不同地址的开放端口数量
			ranges[index] = append(ranges[index], ipPorts)
		}

		for _, rang := range ranges {
			args := strings.Split(command, " ")
			var (
				ips   []string
				ports []string
			)

			allPorts := make(map[int]struct{})
			for _, ipPorts := range rang {
				ips = append(ips, ipPorts.IP)
				for _, pp := range ipPorts.Ports {
					allPorts[pp.Port] = struct{}{}
				}
			}

			for p := range allPorts {
				ports = append(ports, fmt.Sprint(p))
			}

			// 如果前面的数据没有开放端口的话，那么就不执行
			if len(ports) == 0 {
				continue
			}

			portsStr := strings.Join(ports, ",")
			ipsStr := strings.Join(ips, " ")

			args = append(args, "-p", portsStr)
			args = append(args, ips...)

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

				if r.options.NmapOx || r.options.NmapOj {
					// 替换uuid字符串
					args = replaceUUIDs(args)
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
				if r.options.OnNMAPCallback != nil && r.options.NmapOx {
					// todo: 后期逻辑需要进一步优化
					// todo: 目前判断比较简单, 回调的条件 指定了xml的输出 && 需要回调的操作
					data, errMsg := os.ReadFile(DefaultResumeFilePath())
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					parse, errMsg := result.NmapResultParse(data)
					if err != nil {
						gologger.Error().Msg(errMsg.Error())
					}

					// todo: 回调处理
					r.options.OnNMAPCallback(parse)
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

// replaceUUIDs
// @Description: 生成uuid字符串用于替换命令行中的${uuid}标识符
// @param args
// @param format
// @return []string
func replaceUUIDs(args []string) []string {
	for i, arg := range args {
		if strings.Contains(arg, "${uuid}") {
			// Generate a new UUID v4
			newUUID := uuid.New().String()
			// Replace {uuid} in the argument with the new UUID
			args[i] = strings.ReplaceAll(arg, "${uuid}", newUUID)
		}
	}
	return args
}
