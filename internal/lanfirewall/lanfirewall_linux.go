//go:build linux

// Package lanfirewall provides session-scoped Linux UFW permissions.
// A privileged helper holds a pipe from the unprivileged GUI process and
// deletes precisely the rules it created when the pipe closes.
package lanfirewall

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const helperFlag = "--badsharing-ufw-session-helper"

type rule struct {
	Interface string `json:"interface"`
	Subnet    string `json:"subnet"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	PortEnd   int    `json:"port_end"`
	Protocol  string `json:"protocol"`
}

type Session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	waited chan error
	once   sync.Once
}

func (s *Session) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.once.Do(func() {
		_ = s.stdin.Close() // signals the privileged helper to remove its rules
		select {
		case closeErr = <-s.waited:
		case <-time.After(12 * time.Second):
			_ = s.cmd.Process.Kill()
			closeErr = <-s.waited
			if closeErr == nil {
				closeErr = errors.New("firewall helper timed out during cleanup")
			}
		}
	})
	return closeErr
}

// UFW is commonly installed but disabled by default on Linux Mint.
// Reading the standard configuration avoids requiring elevated permissions
// merely to check its status.
func ufwEnabled(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "ENABLED" {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(parts[1]), "\"'"), "yes")
		}
	}
	return false
}

func activeUFW() (bool, error) {
	b, err := os.ReadFile("/etc/ufw/ufw.conf")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot check Linux UFW configuration: %w", err)
	}
	return ufwEnabled(b), nil
}

func allowedInterfaceName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validRule(r rule) bool {
	if !allowedInterfaceName(r.Interface) || r.Port < 1024 || r.Port > 65535 || r.PortEnd < r.Port || r.PortEnd > 65535 || r.PortEnd-r.Port > 127 || (r.Protocol != "tcp" && r.Protocol != "udp") || (r.Protocol == "tcp" && r.PortEnd != r.Port) {
		return false
	}
	ip, ipErr := netip.ParseAddr(r.Address)
	prefix, prefixErr := netip.ParsePrefix(r.Subnet)
	return ipErr == nil && prefixErr == nil && ip.Is4() && ip.IsPrivate() &&
		prefix.Addr().Is4() && prefix.IsValid() && prefix.Bits() >= 8 &&
		prefix.Masked() == prefix && prefix.Contains(ip) && prefix.Addr().IsPrivate()
}

func physicalInterface(name string) bool {
	name = strings.ToLower(name)
	for _, exclude := range []string{"docker", "veth", "br-", "virbr", "tun", "tap", "wg", "tailscale", "zerotier", "vmnet", "vbox", "podman", "zt", "lo"} {
		if strings.HasPrefix(name, exclude) {
			return false
		}
	}
	return true
}

// Rules are restricted to the sender's own IPv4 address and the actual LAN
// subnet configured on the sender's active non-virtual network interfaces.
func rulesForInterfaces(ifaces []net.Interface, addressList func(net.Interface) ([]net.Addr, error), hosts []string, tcpPort int, udpMin, udpMax uint16) []rule {
	allowedHosts := make(map[string]bool, len(hosts))
	for _, host := range hosts {
		allowedHosts[host] = true
	}
	var result []rule
	seen := map[rule]bool{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 || !physicalInterface(iface.Name) || !allowedInterfaceName(iface.Name) {
			continue
		}
		addrs, err := addressList(iface)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if !ip.Is4() || !ip.IsPrivate() || !allowedHosts[ip.String()] {
				continue
			}
			for _, r := range []rule{
				{Interface: iface.Name, Subnet: prefix.Masked().String(), Address: ip.String(), Port: tcpPort, PortEnd: tcpPort, Protocol: "tcp"},
				{Interface: iface.Name, Subnet: prefix.Masked().String(), Address: ip.String(), Port: int(udpMin), PortEnd: int(udpMax), Protocol: "udp"},
			} {
				if validRule(r) && !seen[r] {
					seen[r] = true
					result = append(result, r)
				}
			}
		}
	}
	return result
}

// Prepare permits one sharing session when UFW is active. The desktop will
// trigger an OS Polkit authorization prompt; no blanket firewall disable or
// permanent rule is requested. When UFW is inactive no privilege is used.
func Prepare(ctx context.Context, port int, udpMin, udpMax uint16, hosts []string) (*Session, string, error) {
	if ctx == nil {
		return nil, "", errors.New("firewall setup requires a context")
	}
	active, err := activeUFW()
	if err != nil {
		return nil, "", err
	}
	if !active {
		return nil, "UFW is not active; no firewall changes are needed", nil
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, "", fmt.Errorf("cannot identify LAN interfaces: %w", err)
	}
	rules := rulesForInterfaces(ifaces, func(iface net.Interface) ([]net.Addr, error) { return iface.Addrs() }, hosts, port, udpMin, udpMax)
	if len(rules) == 0 {
		return nil, "", errors.New("UFW is active but no physical LAN interface matched the invitation; connect via Ethernet/Wi-Fi")
	}
	if _, err := os.Stat("/usr/sbin/ufw"); err != nil {
		return nil, "", errors.New("UFW is active but /usr/sbin/ufw is unavailable")
	}
	self, err := os.Executable()
	if err != nil {
		return nil, "", err
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil {
		return nil, "", err
	}
	payload, err := json.Marshal(rules)
	if err != nil {
		return nil, "", err
	}
	args := []string{self, helperFlag, base64.RawURLEncoding.EncodeToString(payload)}
	program := ""
	if os.Geteuid() == 0 {
		program, args = self, args[1:]
	} else {
		program, err = exec.LookPath("pkexec")
		if err != nil {
			return nil, "", errors.New("UFW needs permission, but pkexec is unavailable; install policykit-1 or use a prebuilt desktop package")
		}
	}
	cmd := exec.Command(program, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, "", err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, "", err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return nil, "", fmt.Errorf("cannot request firewall authorization: %w", err)
	}
	s := &Session{cmd: cmd, stdin: stdin, waited: make(chan error, 1)}
	ready := make(chan string, 1)
	go func() {
		line, _ := bufio.NewReader(stdout).ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	go func() { s.waited <- cmd.Wait() }()
	select {
	case line := <-ready:
		if line != "READY" {
			_ = stdin.Close()
			<-s.waited
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = "authorization denied or UFW could not add a session rule"
			}
			return nil, "", fmt.Errorf("could not open the Linux LAN firewall for this share: %s", msg)
		}
		if ctx.Err() != nil {
			_ = s.Close()
			return nil, "", ctx.Err()
		}
		return s, fmt.Sprintf("UFW verified LAN access: HTTPS TCP %d and WebRTC UDP %d-%d (session-scoped)", port, udpMin, udpMax), nil
	case <-ctx.Done():
		_ = stdin.Close()
		_ = s.Close()
		return nil, "", ctx.Err()
	case <-time.After(60 * time.Second):
		_ = stdin.Close()
		_ = s.Close()
		return nil, "", errors.New("firewall authorization timed out; retry the share and approve the Linux security prompt")
	}
}

func ufwCommand(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "/usr/sbin/ufw", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ufw: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return string(output), nil
}

func argsForRule(r rule, remove bool, comment string) []string {
	args := []string{"--force"}
	if remove {
		args = append(args, "delete")
	} else {
		args = append(args, "insert", "1")
	}
	port := strconv.Itoa(r.Port)
	if r.PortEnd > r.Port {
		port += ":" + strconv.Itoa(r.PortEnd)
	}
	args = append(args, "allow", "in", "on", r.Interface, "from", r.Subnet, "to", r.Address, "port", port, "proto", r.Protocol)
	if !remove {
		args = append(args, "comment", comment)
	}
	return args
}

// RunHelper is executed before the GUI is initialized. It is exclusively a
// privileged, session-scoped firewall agent and never touches file content.
func RunHelper(args []string) (handled bool, err error) {
	if len(args) == 0 || args[0] != helperFlag {
		return false, nil
	}
	if os.Geteuid() != 0 {
		return true, errors.New("firewall helper requires OS authorization")
	}
	if len(args) != 2 || len(args[1]) > 8192 {
		return true, errors.New("invalid firewall helper arguments")
	}
	payload, err := base64.RawURLEncoding.DecodeString(args[1])
	if err != nil || len(payload) > 6144 {
		return true, errors.New("invalid firewall helper payload")
	}
	var rules []rule
	if err := json.Unmarshal(payload, &rules); err != nil || len(rules) < 1 || len(rules) > 24 {
		return true, errors.New("invalid firewall helper rules")
	}
	for _, r := range rules {
		if !validRule(r) {
			return true, errors.New("invalid LAN-specific firewall rule")
		}
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return true, fmt.Errorf("could not identify temporary UFW rules: %w", err)
	}
	commentPrefix := "badsharing-client-" + hex.EncodeToString(nonce[:])
	type ownedRule struct {
		rule    rule
		comment string
	}
	var added []ownedRule
	defer func() {
		for i := len(added) - 1; i >= 0; i-- {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			status, statusErr := ufwCommand(cleanupCtx, "status")
			var cleanupErr error
			if statusErr != nil {
				cleanupErr = statusErr
			} else if strings.Contains(status, added[i].comment) {
				_, cleanupErr = ufwCommand(cleanupCtx, argsForRule(added[i].rule, true, "")...)
			}
			cancel()
			if cleanupErr != nil && err == nil {
				err = fmt.Errorf("could not remove temporary UFW rule: %w", cleanupErr)
			}
		}
	}()
	for index, r := range rules {
		marker := fmt.Sprintf("%s-%d", commentPrefix, index)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		_, commandErr := ufwCommand(ctx, argsForRule(r, false, marker)...)
		if commandErr == nil {
			var status string
			status, commandErr = ufwCommand(ctx, "status")
			if commandErr == nil && strings.Contains(status, marker) {
				added = append(added, ownedRule{rule: r, comment: marker})
			} else if commandErr == nil {
				// UFW skipped our insert due to an existing equivalent user rule.
				// Never delete a rule unless our unique comment proves ownership.
			}
		}
		cancel()
		if commandErr != nil {
			return true, commandErr
		}
	}
	fmt.Fprintln(os.Stdout, "READY")
	// EOF occurs on normal Stop, on GUI closure, or if the desktop crashes.
	_, _ = io.Copy(io.Discard, os.Stdin)
	return true, nil
}
