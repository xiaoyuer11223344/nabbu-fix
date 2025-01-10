package port

import (
	"fmt"

	"github.com/xiaoyuer11223344/nabbu-fix/v2/pkg/protocol"
)

type Port struct {
	Port     int               `json:"port"`
	Service  string            `json:"service"`
	Protocol protocol.Protocol `json:"protocol"`
	TLS      bool              `json:"tls"`
}

func (p *Port) String() string {
	return fmt.Sprintf("%d-%d-%v", p.Port, p.Protocol, p.TLS)
}
