package scan

import (
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"regexp"
	"strconv"
	"strings"
)

type ProbesRarity []Probe

type Probe struct {
	Name         string
	Data         string
	Protocol     string
	Ports        string
	SSLPorts     string
	TotalWaitMS  int
	TCPWrappedMS int
	Rarity       int
	Fallback     string
	Matches      *[]Match
}

type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

type ProbeResult struct {
	result.Target
	result.Service `json:"service"`
	Timestamp      int32  `json:"timestamp"`
	Error          string `json:"error"`
}

func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}

	if strings.Count(data, " ") <= 0 {
		panic("错误的指令格式")
	}

	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	return directive
}

func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:3]
	other := probeStr[4:]

	// 探针的协议必须是TCP或UDP其中一中
	if !(proto == "TCP" || proto == "UDP") {
		panic("探针的协议必须是TCP或UDP其中一中")
	}

	if len(other) == 0 {
		panic("没有探针指令")
	}

	directive := p.getDirectiveSyntax(other)

	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))
}

func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}
	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplit := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplit[0], strings.Join(textSplit[1:], "")

	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string(patternUnescaped)
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return match, ok
	}
	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo
	return match, nil
}

func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplit := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplit[0], strings.Join(textSplit[1:], "")
	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string(patternUnescaped)
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
}

func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
}

func (p *Probe) parseTotalWaitMS(data string) {
	p.TotalWaitMS, _ = strconv.Atoi(data[len("totalwaitms")+1:])
}

func (p *Probe) parseTCPWrappedMS(data string) {
	p.TCPWrappedMS, _ = strconv.Atoi(data[len("tcpwrappedms")+1:])
}

func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(data[len("rarity")+1:])
}

func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

func (p *Probe) parseFromString(data string) {
	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")

	probeStr := lines[0]

	p.parseProbeInfo(probeStr)

	var matches []Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matches = append(matches, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matches = append(matches, softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			p.parsePorts(line)
		} else if strings.HasPrefix(line, "sslports ") {
			p.parseSSLPorts(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			p.parseTCPWrappedMS(line)
		} else if strings.HasPrefix(line, "rarity ") {
			p.parseRarity(line)
		} else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		}
	}

	p.Matches = &matches
}

func (ps ProbesRarity) Len() int {
	return len(ps)
}

func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}

func (p *Probe) ContainsPort(testPort int) bool {
	ports := strings.Split(p.Ports, ",")

	// 常规分割判断，Ports 字符串不含端口范围形式 "[start]-[end]"
	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == cmpPort {
			return true
		}
	}

	// 范围判断检查，拆分 Ports 中诸如 "[start]-[end]" 类型的端口范围进行比较
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == cmpPort {
					return true
				}
			}
		}
	}
	return false
}
