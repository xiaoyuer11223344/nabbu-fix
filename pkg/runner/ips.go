package runner

import (
	"strings"

	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
)

func (r *Runner) parseExcludedIps(options *Options) ([]string, error) {
	var excludedIps []string

	// 排除指定为字符串的情况下
	if options.ExcludeIps != "" {
		for _, host := range strings.Split(options.ExcludeIps, ",") {
			// 解析获取所有要排除的IP
			ips, err := r.getExcludeItems(host)
			if err != nil {
				return nil, err
			}
			excludedIps = append(excludedIps, ips...)
		}
	}

	// 排除指定为文件的情况下
	if options.ExcludeIpsFile != "" {
		cdata, err := fileutil.ReadFile(options.ExcludeIpsFile)
		if err != nil {
			return excludedIps, err
		}
		for host := range cdata {
			// 解析获取所有要排除的IP
			ips, err := r.getExcludeItems(host)
			if err != nil {
				return nil, err
			}
			excludedIps = append(excludedIps, ips...)
		}
	}

	return excludedIps, nil
}

func (r *Runner) getExcludeItems(s string) ([]string, error) {
	if isIpOrCidr(s) {
		// 判断当前字符串是否是IP或者是CIDR格式
		return []string{s}, nil
	}

	// 获取ipv4 ipv6 信息
	ips4, ips6, err := r.host2ips(s)
	if err != nil {
		return nil, err
	}
	return append(ips4, ips6...), nil
}

func isIpOrCidr(s string) bool {
	return iputil.IsIP(s) || iputil.IsCIDR(s)
}
