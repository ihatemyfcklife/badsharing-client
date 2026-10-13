package settings

import (
	"context"
	"encoding/hex"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInvitationRoundTrip(t *testing.T) {
	i := Invite{Version: 1, Hosts: []string{"192.168.1.18", "127.0.0.1"}, Port: 50000,
		Pin: strings.Repeat("ab", 32), Room: "myroom", Token: strings.Repeat("a", 64), Key: strings.Repeat("b", 64)}
	code, err := i.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeInvite(code)
	if err != nil {
		t.Fatal(err)
	}
	if out.Port != i.Port || out.Pin != i.Pin || out.Key != i.Key || len(out.Hosts) != 2 {
		t.Fatal("invitation round trip failed")
	}
	if _, err := DecodeInvite(code + "Z"); err == nil {
		t.Fatal("accepted corrupted code")
	}
	i.Hosts = []string{"public.example.com"}
	if _, err := i.Encode(); err == nil {
		t.Fatal("accepted a remote host")
	}
	i.Hosts = []string{"169.254.169.254"}
	if _, err := i.Encode(); err == nil {
		t.Fatal("accepted link-local address")
	}
	i.Pin = "not-a-pin"
	if _, err := i.Encode(); err == nil {
		t.Fatal("accepted invalid pin")
	}
}

func TestPinnedClientRejectsInvalidPins(t *testing.T) {
	if _, err := PinnedHTTP("bad", time.Second); err == nil {
		t.Fatal("accepted invalid pin")
	}
	if _, err := PinnedHTTP(hex.EncodeToString(make([]byte, 32)), time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestLocalSignalingInvitation(t *testing.T) {
	if hosts, err := localHosts(); err != nil || len(hosts) == 0 {
		t.Skip("no private LAN interface available in test environment")
	}
	server, err := StartLocalServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	code, err := server.Invite.Encode()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := DecodeInvite(code)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	config, err := invite.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := url.Parse(config.SignalURL)
	if err != nil || resolved.Scheme != "https" || resolved.Port() != strconv.Itoa(invite.Port) || !slices.Contains(invite.Hosts, resolved.Hostname()) || config.CertPin != invite.Pin {
		t.Fatalf("wrong resolved endpoint: %q (candidates: %v)", config.SignalURL, invite.Hosts)
	}
	if _, err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	invite.Pin = strings.Repeat("ff", 32)
	if _, err := invite.Resolve(ctx); err == nil {
		t.Fatal("accepted wrong TLS pin")
	}
}

func TestPhysicalLANInterfacesArePreferred(t *testing.T) {
	for _, name := range []string{"wlp2s0", "enp0s3", "Ethernet", "Wi-Fi", "wlan0"} {
		if interfacePriority(name) != 0 {
			t.Fatalf("physical LAN interface %q not preferred", name)
		}
	}
	for _, name := range []string{"docker0", "vEthernet (Default Switch)", "wg0", "tailscale0", "virbr0"} {
		if interfacePriority(name) <= 0 {
			t.Fatalf("virtual interface %q incorrectly preferred", name)
		}
	}
}

func TestResolveReportsRealReachabilityErrors(t *testing.T) {
	// Closed localhost port should describe the actual failed endpoint rather
	// than claiming without evidence that the peers are not on the same LAN.
	invite := Invite{Version: 1, Hosts: []string{"127.0.0.1"}, Port: 1,
		Pin: strings.Repeat("aa", 32), Room: "myroom", Token: strings.Repeat("a", 64), Key: strings.Repeat("b", 64)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := invite.Resolve(ctx)
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:1") || strings.Contains(err.Error(), "must be on the same LAN") {
		t.Fatalf("unhelpful reachability diagnostics: %v", err)
	}
}
