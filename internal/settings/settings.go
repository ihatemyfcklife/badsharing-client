package settings

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Config holds ephemeral, shared connection settings. It must not be persisted
// to disk because it contains credentials for the signaling and relay servers.
type Config struct {
	SignalURL    string
	Room         string
	Token        string
	KeyHex       string
	STUN         string
	TURN         string
	TURNUser     string
	TURNPassword string
	RelayOnly    bool
	CertPin      string // TLS SHA-256 fingerprint for ephemeral invite certificates
	UDPPortMin   uint16 // LAN-only WebRTC ICE port range, zero for default
	UDPPortMax   uint16
}

func RandomHex(n int) (string, error) {
	if n < 1 || n > 256 {
		return "", errors.New("invalid random byte length")
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func ParseAddresses(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	out := make([]string, 0)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '\n' || r == ';' }) {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (c Config) Validate() ([32]byte, error) {
	var key [32]byte
	if (c.UDPPortMin == 0) != (c.UDPPortMax == 0) || (c.UDPPortMin != 0 && (c.UDPPortMin < 1024 || c.UDPPortMin > c.UDPPortMax || c.UDPPortMax-c.UDPPortMin > 127)) {
		return key, errors.New("invalid LAN ICE UDP port range")
	}
	raw, err := hex.DecodeString(strings.TrimSpace(c.KeyHex))
	if err != nil || len(raw) != 32 {
		return key, errors.New("file key must be 64 hexadecimal characters (32 bytes)")
	}
	copy(key[:], raw)
	if len(c.Token) < 32 || len(c.Token) > 512 {
		return key, errors.New("signaling token must be between 32 and 512 characters")
	}
	if len(c.Room) < 1 || len(c.Room) > 96 {
		return key, errors.New("room must contain 1–96 letters, digits, hyphens or underscores")
	}
	for _, r := range c.Room {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return key, errors.New("invalid room characters")
		}
	}
	u, err := url.Parse(c.SignalURL)
	if err != nil || u.Host == "" {
		return key, errors.New("invalid signaling server URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return key, errors.New("signaling URL must not contain credentials, query or fragment")
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
			return key, errors.New("HTTPS is required outside localhost")
		}
	}
	if c.CertPin != "" {
		if u.Scheme != "https" || len(c.CertPin) != 64 {
			return key, errors.New("certificate pin requires HTTPS and 64 hex characters")
		}
		if _, err := hex.DecodeString(c.CertPin); err != nil {
			return key, errors.New("invalid certificate pin")
		}
	}
	for _, candidate := range append(ParseAddresses(c.STUN), ParseAddresses(c.TURN)...) {
		if len(candidate) > 512 {
			return key, errors.New("ICE server URL too long")
		}
		iceURL, err := url.Parse(candidate)
		if err != nil || !(strings.HasPrefix(candidate, "stun:") || strings.HasPrefix(candidate, "stuns:") || strings.HasPrefix(candidate, "turn:") || strings.HasPrefix(candidate, "turns:")) || iceURL.Opaque == "" {
			return key, fmt.Errorf("invalid STUN/TURN URL: %s", candidate)
		}
	}
	if len(ParseAddresses(c.TURN)) > 0 && (c.TURNUser == "" || c.TURNPassword == "") {
		return key, errors.New("TURN username and password are required")
	}
	if c.RelayOnly && len(ParseAddresses(c.TURN)) == 0 {
		return key, errors.New("relay-only requires a TURN server")
	}
	return key, nil
}
