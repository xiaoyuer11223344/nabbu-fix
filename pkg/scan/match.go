package scan

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Match struct {
	IsSoft          bool
	Service         string
	Pattern         string
	VersionInfo     string
	PatternCompiled *regexp.Regexp
}

type Extras struct {
	VendorProduct   string `json:"vendor_product,omitempty"`
	Version         string `json:"version,omitempty"`
	Info            string `json:"info,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	DeviceType      string `json:"device_type,omitempty"`
	CPE             string `json:"cpe,omitempty"`
}

// isHexCode
// @Description: 判断16进制字符串
// @param b
// @return bool
func isHexCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)
	return matchRe.Match(b)
}

// isOctalCode
// @Description: 判断8进制字符串
// @param b
// @return bool
func isOctalCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[0-7]{1,3}`)
	return matchRe.Match(b)
}

// isStructCode
// @Description: 判断结构字符串
// @param b
// @return bool
func isStructCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[aftnrv]`)
	return matchRe.Match(b)
}

// isReChar
// @Description: 判断正则字符串
// @param n
// @return bool
func isReChar(n int64) bool {
	reChars := `.*?+{}()^$|\`
	for _, char := range reChars {
		if n == int64(char) {
			return true
		}
	}
	return false
}

// isOtherEscapeCode
// @Description: 其他转义字符串
// @param b
// @return bool
func isOtherEscapeCode(b []byte) bool {
	matchRe := regexp.MustCompile(`\\[^\\]`)
	return matchRe.Match(b)
}

// DecodeData
// @Description: 解码数据
// @param s
// @return []byte
// @return error
func DecodeData(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			replace = []byte{uint8(byteNum)}
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  {0x07}, // \a
				102: {0x0c}, // \f
				116: {0x09}, // \t
				110: {0x0a}, // \n
				114: {0x0d}, // \r
				118: {0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

// DecodePattern 解析指纹库中匹配规则字符串，转换成 golang 中可以进行编译的字符串
func DecodePattern(s string) ([]byte, error) {
	sByteOrigin := []byte(s)
	matchRe := regexp.MustCompile(`\\(x[0-9a-fA-F]{2}|[0-7]{1,3}|[aftnrv])`)
	sByteDec := matchRe.ReplaceAllFunc(sByteOrigin, func(match []byte) (v []byte) {
		var replace []byte
		// 十六进制转义格式
		if isHexCode(match) {
			hexNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(hexNum), 16, 32)
			if isReChar(byteNum) {
				replace = []byte{'\\', uint8(byteNum)}
			} else {
				replace = []byte{uint8(byteNum)}
			}
		}
		// 格式控制符 \r\n\a\b\f\t
		if isStructCode(match) {
			structCodeMap := map[int][]byte{
				97:  {0x07}, // \a
				102: {0x0c}, // \f
				116: {0x09}, // \t
				110: {0x0a}, // \n
				114: {0x0d}, // \r
				118: {0x0b}, // \v
			}
			replace = structCodeMap[int(match[1])]
		}
		// 八进制转义格式
		if isOctalCode(match) {
			octalNum := match[2:]
			byteNum, _ := strconv.ParseInt(string(octalNum), 8, 32)
			replace = []byte{uint8(byteNum)}
		}
		return replace
	})

	matchRe2 := regexp.MustCompile(`\\([^\\])`)
	sByteDec2 := matchRe2.ReplaceAllFunc(sByteDec, func(match []byte) (v []byte) {
		var replace []byte
		if isOtherEscapeCode(match) {
			replace = match
		} else {
			replace = match
		}
		return replace
	})
	return sByteDec2, nil
}

// SortProbesByRarity
// @Description: 结果排序
// @param probes
// @return probesSorted
func SortProbesByRarity(probes []Probe) (probesSorted []Probe) {
	probesToSort := ProbesRarity(probes)
	sort.Stable(probesToSort)
	// 稳定排序 ， 探针发送顺序不同，最后会导致探测服务出现问题
	probesSorted = probesToSort
	return probesSorted
}

// MatchPattern
// @Description: Banner正则匹配
// @receiver m
// @param response
// @return matched
func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string(response)
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	// 匹配结果大于 0 表示规则与 response 匹配成功
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

// ParseVersionInfo
// @Description: 解析版本信息
// @receiver m
// @param response
// @return Extras
func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		if len(vendorProductName) > 1 {
			extras.VendorProduct = vendorProductName[1]
		}
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		if len(vendorProductName) > 1 {
			extras.VendorProduct = vendorProductName[1]
		}
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		if len(version) > 1 {
			extras.Version = version[1]
		}
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		if len(version) > 1 {
			extras.Version = version[1]
		}
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		if len(info) > 1 {
			extras.Info = info[1]
		}
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		if len(info) > 1 {
			extras.Info = info[1]
		}
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		if len(hostname) > 1 {
			extras.Hostname = hostname[1]
		}
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		if len(hostname) > 1 {
			extras.Hostname = hostname[1]
		}
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		if len(operatingSystem) > 1 {
			extras.OperatingSystem = operatingSystem[1]
		}
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		if len(operatingSystem) > 1 {
			extras.OperatingSystem = operatingSystem[1]
		}
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		if len(deviceType) > 1 {
			extras.DeviceType = deviceType[1]
		}
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		if len(deviceType) > 1 {
			extras.DeviceType = deviceType[1]
		}
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}
