package scan

import (
	"fmt"
	"net"
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
