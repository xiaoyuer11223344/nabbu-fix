package scan

import (
	"errors"
	"fmt"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
)

// ConnectVerify is used to verify if ports are accurate using a connect request
func (s *Scanner) ConnectVerify(host string, ports []*port.Port) []*port.Port {
	var verifiedPorts []*port.Port

	// 验证端口是否开放
	for _, p := range ports {
		conn, err := net.DialTimeout(p.Protocol.String(), fmt.Sprintf("%s:%d", host, p.Port), s.timeout)
		if err != nil {
			continue
		}
		gologger.Debug().Msgf("Validated active port %d on %s\n", p.Port, host)
		conn.Close()
		verifiedPorts = append(verifiedPorts, p)
	}
	return verifiedPorts
}

func (s *Scanner) WrapperTcpWithTimeout(network string, address string, timeout time.Duration) (net.Conn, error) {
	var conn net.Conn
	var err error

	if s.proxyDialer == nil || strings.Contains(network, "udp") {
		d := &net.Dialer{Timeout: timeout}
		conn, err = d.Dial(network, address)
		if err != nil {
			return nil, err
		}
	} else {
		conn, err = s.proxyDialer.Dial(network, address)
		if err != nil {
			return nil, err
		}
	}

	return conn, nil
}

// grabResponse
// @Description: 收发包请求
// @param target
// @param data
// @param sconfig
// @return response
// @return err
// @return status
func (s *Scanner) grabResponse(target *result.Target, data []byte, timeout time.Duration) (response []byte, err error, status bool) {
	// 封装 tcp/udp 连接

	conn, err := s.WrapperTcpWithTimeout(target.Port.Protocol.String(), target.GetAddress(), timeout)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()

	if err != nil {
		status = false
		return
	}

	status = true

	// 如果要发送的probe的数据存在的话，那么则进行发送进行探测
	if len(data) > 0 {
		err = conn.SetWriteDeadline(time.Now().Add(timeout))
		if err != nil {
			return
		}

		_, errWrite := conn.Write(data)
		if errWrite != nil {
			return
		}
	}

	// 设置返回数据包中的大小，默认每次读取1024个字节
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	for true {
		var n int
		buff := make([]byte, 1024)
		n, err = conn.Read(buff)
		if err != nil {
			if len(response) > 0 {
				break
			} else {
				return
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}
	return
}

// ScanProbe
// @Description: 指纹扫描
// @receiver s
// @param host
// @param ports
// @return string
func (s *Scanner) ScanProbe(host string, port *port.Port, probes *[]Probe) (result ProbeResult, err error, status bool) {
	target := &result.Target{
		Host: host,
		Port: port,
	}

	for _, probe := range *probes {
		var response []byte

		probeData, _ := DecodeData(probe.Data)
		gologger.Debug().Msgf("[%s] 发送探针 [%s] 数据包[%s]\n", target.GetAddress(), probe.Name, probe.Data)
		response, err, status = s.grabResponse(target, probeData, s.timeout)

		// 判断端口开放程度，如果没有开放的话那么直接关闭
		if status == false {
			gologger.Debug().Msgf("[%s] 收发包连接失败\n", host)
			return
		}

		// 成功获取 Banner 即开始匹配规则，无规则匹配则直接返回
		if len(response) > 0 {
			gologger.Debug().Msgf("[%s] 通过探针 [%s] 获取响应长度为 [%s]\n", target.GetAddress(), probe.Name, strconv.Itoa(len(response)))

			found := false
			softFound := false
			var softMatch Match

			for _, match := range *probe.Matches {
				matched := match.MatchPattern(response)
				if matched && !match.IsSoft {
					extras := match.ParseVersionInfo(response)

					result.Service.Target = target

					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data
					result.Service.Details.MatchMatched = match.Pattern

					result.Service.Protocol = strings.ToLower(probe.Protocol)
					result.Service.Name = match.Service

					result.Banner = string(response)
					result.BannerBytes = response
					result.Service.Extras = extras

					result.Timestamp = int32(time.Now().Unix())

					found = true

					return
				} else if matched && match.IsSoft && !softFound {
					// soft 匹配，记录结果
					softFound = true
					softMatch = match
				}
			}

			// 当前 Probe 下的 Matches 未匹配成功，使用 Fallback Probe 中的 Matches 进行尝试
			// 回退操作，跳转到probe为Fallback的探针中继续进行探测
			fallback := probe.Fallback
			if _, ok := s.ProbesMapKName[fallback]; ok {
				fbProbe := s.ProbesMapKName[fallback]
				for _, match := range *fbProbe.Matches {
					matched := match.MatchPattern(response)
					if matched && !match.IsSoft {
						extras := match.ParseVersionInfo(response)

						result.Service.Target = target

						result.Service.Details.ProbeName = probe.Name
						result.Service.Details.ProbeData = probe.Data
						result.Service.Details.MatchMatched = match.Pattern

						result.Service.Protocol = strings.ToLower(probe.Protocol)
						result.Service.Name = match.Service

						result.Banner = string(response)
						result.BannerBytes = response
						result.Service.Extras = extras

						result.Timestamp = int32(time.Now().Unix())

						found = true

						return
					} else if matched && match.IsSoft && !softFound {
						// soft 匹配，记录结果
						//fmt.Printf("[%s]匹配服务：%s，匹配正则：%s\n", target.Host, match.Service, match.Pattern)
						softFound = true
						softMatch = match
					}
				}
			}

			if !found {
				if softFound { //Match
					result.Service.Target = target
					result.Service.Protocol = strings.ToLower(probe.Protocol)
					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data
					result.Service.Details.MatchMatched = softMatch.Pattern
					result.Service.Details.IsSoftMatched = true

					result.Banner = string(response)
					result.BannerBytes = response

					result.Timestamp = int32(time.Now().Unix())

					extras := softMatch.ParseVersionInfo(response)
					result.Service.Extras = extras
					result.Service.Name = softMatch.Service

					return
				} else {
					result.Service.Target = target
					result.Service.Protocol = strings.ToLower(probe.Protocol)

					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data

					result.Banner = string(response)
					result.BannerBytes = response
					result.Service.Name = "unknown"

					result.Timestamp = int32(time.Now().Unix())
					continue
				}
			}
		}
	}

	return result, errors.New("no response"), true
}
