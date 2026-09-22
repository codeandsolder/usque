package cmd

import "testing"

func TestParseL4SourceAddr(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ip   string
		zone string
	}{
		{name: "empty", in: ""},
		{name: "ipv4", in: "127.0.0.1", ip: "127.0.0.1"},
		{name: "ipv6", in: "2001:db8::1", ip: "2001:db8::1"},
		{name: "ipv6 zone", in: "fe80::1%eth0", ip: "fe80::1", zone: "eth0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseL4SourceAddr(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if tt.in == "" {
				if got != nil {
					t.Fatalf("parseL4SourceAddr(%q) = %#v, want nil", tt.in, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseL4SourceAddr(%q) returned nil", tt.in)
			}
			if got.IP.String() != tt.ip {
				t.Errorf("IP = %q, want %q", got.IP, tt.ip)
			}
			if got.Zone != tt.zone {
				t.Errorf("Zone = %q, want %q", got.Zone, tt.zone)
			}
			if got.Port != 0 {
				t.Errorf("Port = %d, want 0", got.Port)
			}
		})
	}
}

func TestParseL4SourceAddrRejectsInvalidAddress(t *testing.T) {
	if _, err := parseL4SourceAddr("definitely-not-an-ip"); err == nil {
		t.Fatal("expected invalid source IP to fail")
	}
}
