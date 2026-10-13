package settings

import (
	"strings"
	"testing"
)

func TestCredentials(t *testing.T) {
	token, err := RandomHex(32)
	if err != nil || len(token) != 64 {
		t.Fatal("random token invalid")
	}
	key, err := RandomHex(32)
	if err != nil {
		t.Fatal(err)
	}
	c := Config{SignalURL: "http://127.0.0.1:8088", Room: "demo_1", Token: token, KeyHex: key}
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.SignalURL = "http://example.com:8088"
	if _, err := c.Validate(); err == nil {
		t.Fatal("remote HTTP accepted")
	}
	c.SignalURL = "https://example.com"
	c.RelayOnly = true
	if _, err := c.Validate(); err == nil {
		t.Fatal("relay without TURN accepted")
	}
	c.RelayOnly = false
	c.TURN = "turn:relay.example.com:3478"
	c.TURNUser = "demo"
	c.TURNPassword = "secret"
	if _, err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.KeyHex = strings.Repeat("z", 64)
	if _, err := c.Validate(); err == nil {
		t.Fatal("non-hex accepted")
	}
}
func TestParseAddresses(t *testing.T) {
	a := ParseAddresses(" stun:one:3478,\n turn:two:3478; ")
	if len(a) != 2 || a[0] != "stun:one:3478" || a[1] != "turn:two:3478" {
		t.Fatal(a)
	}
}

func TestLANICEPortRange(t *testing.T) {
	token, _ := RandomHex(32)
	key, _ := RandomHex(32)
	cfg := Config{SignalURL: "https://example.com", Room: "demo", Token: token, KeyHex: key, UDPPortMin: 52000, UDPPortMax: 52063}
	if _, err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][2]uint16{{52000, 0}, {53000, 52000}, {52000, 53000}} {
		cfg.UDPPortMin, cfg.UDPPortMax = invalid[0], invalid[1]
		if _, err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid ICE range %d..%d", invalid[0], invalid[1])
		}
	}
}
