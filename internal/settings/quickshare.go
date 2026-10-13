package settings

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ihatemyfcklife/badsharing-client/internal/lanfirewall"
	"github.com/ihatemyfcklife/badsharing/signaling"
)

const invitePrefix = "badsharing://join/"

// Invite contains one-time session credentials. Treat its contents exactly like
// a password: anyone who obtains the code can join and disrupt a transfer.
type Invite struct {
	Version int      `json:"v"`
	Hosts   []string `json:"hosts"`
	Port    int      `json:"port"`
	Pin     string   `json:"pin"`
	Room    string   `json:"room"`
	Token   string   `json:"token"`
	Key     string   `json:"key"`
}

func validHost(h string) bool {
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsValid() && !ip.IsUnspecified() && !ip.IsMulticast() &&
		(ip.IsPrivate() || ip.IsLoopback())
}

func (i Invite) Check() error {
	if i.Version != 1 || i.Port < 1 || i.Port > 65535 || len(i.Hosts) == 0 || len(i.Hosts) > 12 {
		return errors.New("unsupported or invalid invitation")
	}
	for _, host := range i.Hosts {
		if !validHost(host) {
			return errors.New("invitation has an invalid LAN address")
		}
	}
	if len(i.Pin) != 64 {
		return errors.New("invitation certificate pin is missing")
	}
	if _, err := hex.DecodeString(i.Pin); err != nil {
		return errors.New("invalid certificate pin")
	}
	// The URL is a placeholder for validation; each candidate uses HTTPS.
	_, err := (Config{SignalURL: "https://127.0.0.1", Room: i.Room, Token: i.Token, KeyHex: i.Key, CertPin: i.Pin}).Validate()
	return err
}

func (i Invite) Encode() (string, error) {
	if err := i.Check(); err != nil {
		return "", err
	}
	payload, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	return invitePrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeInvite(code string) (Invite, error) {
	var i Invite
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, invitePrefix) || len(code) > 3000 {
		return i, errors.New("paste a valid badsharing invitation")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, invitePrefix))
	if err != nil || len(raw) > 2048 {
		return i, errors.New("invalid invitation encoding")
	}
	if err := json.Unmarshal(raw, &i); err != nil {
		return i, errors.New("invalid invitation data")
	}
	return i, i.Check()
}

// PinnedHTTP accepts a self-signed TLS certificate only when its SHA-256
// fingerprint matches the authenticated invitation. This is pinning, not an
// unconditional insecure TLS bypass.
func PinnedHTTP(pinHex string, timeout time.Duration) (*http.Client, error) {
	expected, err := hex.DecodeString(pinHex)
	if err != nil || len(expected) != sha256.Size {
		return nil, errors.New("invalid TLS certificate pin")
	}
	t := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true, // replaced with explicit fingerprint verification below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("TLS certificate missing")
				}
				cert := cs.PeerCertificates[0]
				sum := sha256.Sum256(cert.Raw)
				if subtleConstantCompare(sum[:], expected) == false {
					return errors.New("invitation TLS fingerprint mismatch")
				}
				now := time.Now()
				if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
					return errors.New("invitation TLS certificate expired")
				}
				return nil
			},
		},
		Proxy:                 nil, // LAN pairing bypasses system HTTP proxies
		MaxIdleConns:          4,
		IdleConnTimeout:       10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &http.Client{Transport: t, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func subtleConstantCompare(a, b []byte) bool { return len(a) == len(b) && subtleCompare(a, b) }

// Kept separate so invite validation does not require a third-party package.
func subtleCompare(a, b []byte) bool {
	var v byte
	for k := range a {
		v |= a[k] ^ b[k]
	}
	return v == 0
}

// Resolve tests the sender's advertised addresses in parallel. A device may
// have Wi-Fi, Ethernet, VPN and VM adapters; none of those alone indicates that
// the receiver is on a different network. Every candidate is protected by the
// invitation's TLS certificate fingerprint.
func (i Invite) Resolve(ctx context.Context) (Config, error) {
	if err := i.Check(); err != nil {
		return Config{}, err
	}
	if ctx == nil {
		return Config{}, errors.New("invitation: missing context")
	}
	const probeTimeout = 2500 * time.Millisecond
	httpClient, err := PinnedHTTP(i.Pin, probeTimeout)
	if err != nil {
		return Config{}, err
	}
	defer httpClient.CloseIdleConnections()

	type result struct {
		url string
		err error
	}
	// Concurrent probing avoids waiting on dead VPN or virtual adapter addresses
	// before reaching the actual Wi-Fi/Ethernet interface.
	tryAll := func() (string, []result) {
		results := make(chan result, len(i.Hosts))
		probeCtx, stop := context.WithCancel(ctx)
		defer stop()
		var wg sync.WaitGroup
		for _, host := range i.Hosts {
			host := host
			wg.Add(1)
			go func() {
				defer wg.Done()
				addr := "https://" + net.JoinHostPort(host, strconv.Itoa(i.Port))
				requestCtx, cancel := context.WithTimeout(probeCtx, probeTimeout)
				defer cancel()
				req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, addr+"/healthz", nil)
				if err != nil {
					select {
					case results <- result{url: addr, err: err}:
					case <-probeCtx.Done():
					}
					return
				}
				res, err := httpClient.Do(req)
				if err == nil {
					_ = res.Body.Close()
					if res.StatusCode != http.StatusOK {
						err = fmt.Errorf("HTTP %d", res.StatusCode)
					}
				}
				select {
				case results <- result{url: addr, err: err}:
				case <-probeCtx.Done():
				}
			}()
		}
		go func() { wg.Wait(); close(results) }()
		failures := make([]result, 0, len(i.Hosts))
		for r := range results {
			if r.err == nil {
				stop()
				return r.url, failures
			}
			failures = append(failures, r)
		}
		return "", failures
	}

	var failures []result
	for attempt := 0; attempt < 2; attempt++ {
		if ctx.Err() != nil {
			return Config{}, ctx.Err()
		}
		addr, tried := tryAll()
		if addr != "" {
			return Config{SignalURL: addr, Room: i.Room, Token: i.Token, KeyHex: i.Key, CertPin: i.Pin}, nil
		}
		failures = tried
		if attempt == 0 {
			timer := time.NewTimer(350 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Config{}, ctx.Err()
			case <-timer.C:
			}
		}
	}
	// Do not mistake a blocked HTTPS port, a rejected certificate or a virtual
	// adapter for proof that the two computers belong to different LANs.
	sort.Slice(failures, func(a, b int) bool { return failures[a].url < failures[b].url })
	details := make([]string, 0, len(failures))
	for _, f := range failures {
		if f.err != nil {
			details = append(details, f.url+": "+f.err.Error())
		}
	}
	return Config{}, fmt.Errorf("cannot reach the sender's private HTTPS sharing service. Check that sharing is still running, allow badsharing-client through the sender's private-network firewall, and disable guest Wi-Fi/client isolation. Attempted endpoints: %s", strings.Join(details, " | ")+". "+receiverNetworkHint(i.Hosts))
}

// receiverNetworkHint is diagnostic only. Different routed LAN subnets can
// still reach one another; a same-subnet match does not prove reachability.
func receiverNetworkHint(hosts []string) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "The receiver's local interfaces could not be inspected."
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || !p.Addr().Is4() {
				continue
			}
			for _, host := range hosts {
				ip, err := netip.ParseAddr(host)
				if err == nil && ip.Is4() && p.Contains(ip) {
					return "A sender address is on an active local subnet; check the sender firewall or Wi-Fi client isolation."
				}
			}
		}
	}
	return "No sender address matches an active receiver subnet. Check whether the invite advertises a VPN/virtual address or a different Wi-Fi network; routed subnets may still work."
}

// LocalServer is an ephemeral HTTPS rendezvous owned by the sender. Its token
// and certificate are discarded when the share is stopped.
type LocalServer struct {
	server     *http.Server
	listener   net.Listener
	Invite     Invite
	URL        string
	UDPPortMin uint16
	UDPPortMax uint16
	firewallMu sync.Mutex
	firewall   *lanfirewall.Session
	closed     bool
}

// PrepareNetwork checks Linux Mint's UFW firewall and, only when active,
// requests OS authorization for temporary LAN-scoped TCP and UDP ICE rules. It MUST be
// called off the GUI thread because a Polkit authorization dialog may open.
func (s *LocalServer) PrepareNetwork(ctx context.Context) (string, error) {
	if s == nil {
		return "", errors.New("local share was not started")
	}
	port := s.listener.Addr().(*net.TCPAddr).Port
	session, message, err := lanfirewall.Prepare(ctx, port, s.UDPPortMin, s.UDPPortMax, s.Invite.Hosts)
	if err != nil {
		return "", err
	}
	s.firewallMu.Lock()
	if s.closed || ctx.Err() != nil {
		s.firewallMu.Unlock()
		_ = session.Close()
		return "", errors.New("local share stopped before network setup finished")
	}
	s.firewall = session
	s.firewallMu.Unlock()

	// Confirm that the listening service and its certificate are usable on
	// the advertised local addresses before handing the invitation to anyone.
	// This does not prove a remote machine can cross a router or firewall.
	probe, err := PinnedHTTP(s.Invite.Pin, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer probe.CloseIdleConnections()
	var failures []string
	for _, host := range s.Invite.Hosts {
		addr := "https://" + net.JoinHostPort(host, strconv.Itoa(port)) + "/healthz"
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
		if requestErr != nil {
			return "", requestErr
		}
		resp, requestErr := probe.Do(req)
		if requestErr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return message + "; local HTTPS and certificate verified", nil
			}
			requestErr = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		failures = append(failures, host+": "+requestErr.Error())
	}
	return "", fmt.Errorf("private HTTPS sharing service did not pass its local check (%s)", strings.Join(failures, " | "))
}

func (s *LocalServer) Close() error {
	if s == nil {
		return nil
	}
	s.firewallMu.Lock()
	if s.closed {
		s.firewallMu.Unlock()
		return nil
	}
	s.closed = true
	firewall := s.firewall
	s.firewall = nil
	s.firewallMu.Unlock()
	_ = s.server.Close()
	err := s.listener.Close()
	if firewall != nil {
		if closeErr := firewall.Close(); closeErr != nil {
			return fmt.Errorf("could not clean up temporary Linux firewall rule: %w", closeErr)
		}
	}
	return err
}

const DefaultSTUN = "stun:stun.l.google.com:19302"

// hostCandidate is ordered to prefer actual Wi-Fi/Ethernet interfaces over
// VPNs, Docker bridges and hypervisor networks. All valid candidates are still
// embedded in the invitation (up to the 12-address protocol limit).
type hostCandidate struct {
	address string
	rank    int
}

func interfacePriority(name string) int {
	s := strings.ToLower(name)
	for _, virtual := range []string{"docker", "veth", "vbox", "virtualbox", "vmnet", "vmware", "vethernet", "hyper-v", "tailscale", "zerotier", "wg", "tun", "tap", "virbr", "br-", "podman", "wsl", "loopback"} {
		if strings.HasPrefix(s, virtual) || strings.Contains(s, virtual) {
			return 10
		}
	}
	for _, physical := range []string{"wifi", "wi-fi", "wireless", "wlan", "wlp", "wlx", "ethernet", "eth", "enp", "eno", "ens", "enx"} {
		if strings.HasPrefix(s, physical) || strings.Contains(s, physical) {
			return 0
		}
	}
	return 3
}

func localHosts() ([]string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var candidates []hostCandidate
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if !ip.Is4() || !ip.IsPrivate() {
				continue
			}
			address := ip.String()
			if !seen[address] {
				seen[address] = true
				candidates = append(candidates, hostCandidate{address: address, rank: interfacePriority(iface.Name)})
			}
		}
	}
	sort.Slice(candidates, func(a, b int) bool {
		if candidates[a].rank != candidates[b].rank {
			return candidates[a].rank < candidates[b].rank
		}
		return candidates[a].address < candidates[b].address
	})
	if len(candidates) == 0 {
		return nil, errors.New("no private IPv4 Wi-Fi/Ethernet address found; connect to a LAN")
	}
	var hosts []string
	for _, candidate := range candidates {
		if len(hosts) == 12 {
			break
		}
		hosts = append(hosts, candidate.address)
	}
	return hosts, nil
}

func StartLocalServer() (*LocalServer, error) {
	hosts, err := localHosts()
	if err != nil {
		return nil, err
	}
	room, err := RandomHex(12)
	if err != nil {
		return nil, err
	}
	token, err := RandomHex(32)
	if err != nil {
		return nil, err
	}
	key, err := RandomHex(32)
	if err != nil {
		return nil, err
	}
	broker, err := signaling.NewServer(token)
	if err != nil {
		return nil, err
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	certTemplate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "badsharing ephemeral LAN"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		certTemplate.IPAddresses = append(certTemplate.IPAddresses, net.ParseIP(h))
	}
	rawCert, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("cannot open local network port: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	// Keep ICE UDP sockets in one bounded range so an active Linux firewall
	// needs only one temporary UDP rule for the entire sharing session.
	portOffset, err := rand.Int(rand.Reader, big.NewInt(4096))
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	udpPortMin := uint16(52000 + portOffset.Int64())
	udpPortMax := udpPortMin + 63
	fingerprint := sha256.Sum256(rawCert)
	invite := Invite{Version: 1, Hosts: hosts, Port: port, Pin: hex.EncodeToString(fingerprint[:]), Room: room, Token: token, Key: key}
	mux := http.NewServeMux()
	mux.Handle("/v1/", broker)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{rawCert}, PrivateKey: priv}}, MinVersion: tls.VersionTLS12})
	go func() { _ = server.Serve(tlsListener) }()
	local := &LocalServer{server: server, listener: listener, Invite: invite, UDPPortMin: udpPortMin, UDPPortMax: udpPortMax, URL: "https://" + net.JoinHostPort(hosts[0], strconv.Itoa(port))}
	if _, err := url.Parse(local.URL); err != nil {
		_ = local.Close()
		return nil, err
	}
	return local, nil
}
