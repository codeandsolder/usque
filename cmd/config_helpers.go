package cmd

import (
	"fmt"
	"net"
)

func endpointHost(endpoint string) (string, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	if host == "" || net.ParseIP(host) == nil {
		return "", fmt.Errorf("endpoint %q does not contain an IP address", endpoint)
	}
	return host, nil
}
