//go:build linux

package lanfirewall

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestUFWActive(t *testing.T) {
	for _, tc := range []struct {
		content string
		want    bool
	}{
		{"# ENABLED=yes\nENABLED=no\n", false},
		{"ENABLED=yes\n", true},
		{"ENABLED=YES # enabled\n", true},
		{"garbage\n", false},
	} {
		if got := ufwEnabled([]byte(tc.content)); got != tc.want {
			t.Fatalf("%q got %v", tc.content, got)
		}
	}
}

func TestLANOnlyScopedRules(t *testing.T) {
	interfaces := []net.Interface{{Name: "wlp3s0", Flags: net.FlagUp}, {Name: "docker0", Flags: net.FlagUp}, {Name: "wg0", Flags: net.FlagUp}, {Name: "lo", Flags: net.FlagLoopback | net.FlagUp}}
	lookup := func(i net.Interface) ([]net.Addr, error) {
		var raw string
		switch i.Name {
		case "wlp3s0":
			raw = "10.3.0.197/24"
		case "docker0":
			raw = "172.17.0.1/16"
		case "wg0":
			raw = "10.8.0.1/24"
		default:
			raw = "127.0.0.1/8"
		}
		_, ip, _ := net.ParseCIDR(raw)
		// net.ParseCIDR masks the address; use ParseCIDR's returned IP separately.
		parsedIP, _, _ := net.ParseCIDR(raw)
		return []net.Addr{&net.IPNet{IP: parsedIP, Mask: ip.Mask}}, nil
	}
	rules := rulesForInterfaces(interfaces, lookup, []string{"10.3.0.197", "172.17.0.1", "10.8.0.1"}, 38831, 53000, 53063)
	want := []rule{
		{Interface: "wlp3s0", Subnet: "10.3.0.0/24", Address: "10.3.0.197", Port: 38831, PortEnd: 38831, Protocol: "tcp"},
		{Interface: "wlp3s0", Subnet: "10.3.0.0/24", Address: "10.3.0.197", Port: 53000, PortEnd: 53063, Protocol: "udp"},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules = %#v, want %#v", rules, want)
	}
	if !validRule(want[0]) {
		t.Fatal("valid LAN rule rejected")
	}
	for _, bad := range []rule{{Interface: "wlp3s0;rm", Subnet: "10.3.0.0/24", Address: "10.3.0.197", Port: 38831, PortEnd: 38831, Protocol: "tcp"}, {Interface: "wlp3s0", Subnet: "0.0.0.0/0", Address: "10.3.0.197", Port: 38831, PortEnd: 38831, Protocol: "tcp"}} {
		if validRule(bad) {
			t.Fatalf("accepted unsafe rule: %#v", bad)
		}
	}
	if !strings.Contains(strings.Join(argsForRule(want[0], false, "badsharing-client-test"), " "), "from 10.3.0.0/24 to 10.3.0.197 port 38831 proto tcp") {
		t.Fatal("TCP not restricted to LAN source and port")
	}
	if !strings.Contains(strings.Join(argsForRule(want[1], false, "badsharing-client-test"), " "), "from 10.3.0.0/24 to 10.3.0.197 port 53000:53063 proto udp") {
		t.Fatal("UDP not restricted to LAN source and port range")
	}
}
