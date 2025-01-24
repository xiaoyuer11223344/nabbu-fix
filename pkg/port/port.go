package port

import (
	"fmt"
	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/protocol"
)

type Port struct {
	Port       int               `json:"port"`
	Protocol   protocol.Protocol `json:"protocol"`
	TLS        bool              `json:"tls"`
	Service    string            `json:"service"`
	Version    string            `json:"version"`
	CPE        string            `json:"CPE"`
	Product    string            `json:"product"`
	Status     string            `json:"status"`
	ExtraInfo  string            `json:"extra_info"`
	DeviceType string            `json:"device_type"`
	ServiceFp  string            `json:"service_fp"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
