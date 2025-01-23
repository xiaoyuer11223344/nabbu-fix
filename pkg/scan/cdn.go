package scan

import (
	"fmt"
	"net"

	"github.com/pkg/errors"
)

// CdnCheck verifies if the given ip is part of Cdn/WAF ranges
func (s *Scanner) CdnCheck(ip string) (bool, string, error) {
	if s.cdn == nil {
		return false, "", errors.New("cdn client not initialized")
	}

	// the goal is to check if ip is part of cdn/waf to decide if target should be scanned or not
	// since 'cloud' itemtype does not fit logic here , we consider target is not part of cdn/waf
	matched, value, itemType, err := s.cdn.Check(net.ParseIP((ip)))
	if itemType == "cloud" {
		return false, "", err
	}
	return matched, value, err
}

func (s *Scanner) CdnCheckDomain(domain string) (bool, string, error) {
	if s.cdn == nil {
		return false, "", fmt.Errorf("cdn client not configured")
	}

	// the goal is to check if ip is part of cdn/waf to decide if target should be scanned or not
	// since 'cloud' itemtype does not fit logic here , we consider target is not part of cdn/waf
	matched, value, itemType, err := s.cdn.CheckDomainWithFallback(domain)

	if itemType == "cloud" {
		return false, value, err
	}

	return matched, value, err
}
