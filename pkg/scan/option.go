package scan

import (
	_ "embed"
	"fmt"
	"github.com/projectdiscovery/naabu/v2/pkg/port"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/result"
)

//go:embed service.txt
var RuleProbe string

// Options of the scan
type Options struct {
	Timeout       time.Duration
	Retries       int
	Rate          int
	PortThreshold int
	ExcludeCdn    bool
	OutputCdn     bool
	ExcludedIps   []string
	Proxy         string
	ProxyAuth     string
	Stream        bool
	OnReceive     result.ResultFn
	ScanType      string
	Rarity        int
}

type Details struct {
	ProbeName     string `json:"probe_name"`
	ProbeData     string `json:"probe_data"`
	MatchMatched  string `json:"match_matched"`
	IsSoftMatched bool   `json:"soft_matched"`
}

type Target struct {
	Host string `json:"host"`
	Port *port.Port
}

func (t *Target) GetAddress() string {
	return fmt.Sprintf(`%s:%d`, t.Host, t.Port)
}

type Service struct {
	*Target
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Banner      string `json:"banner"`
	BannerBytes []byte `json:"banner_bytes"`
	Extras      `json:"extras"`
	Details     `json:"details"`
}
