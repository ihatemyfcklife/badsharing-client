// Package rtc provides the WebRTC transport used by badsharing-client.
// It is a desktop counterpart to badsharing's optional Pion transport module.
package rtc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"
)

const maxFrame = 8192
const maxBuffered = 2 << 20

// Config defines ICE servers. TURN credentials should be short-lived.
type Config struct {
	STUN         []string
	TURN         []string
	TURNUser     string
	TURNPassword string
	ForceRelay   bool
	UDPPortMin   uint16 // Optional restricted ICE port range for automatic LAN firewall
	UDPPortMax   uint16
}

func (c Config) webrtcConfig() (webrtc.Configuration, error) {
	var servers []webrtc.ICEServer
	if len(c.STUN) > 0 {
		servers = append(servers, webrtc.ICEServer{URLs: c.STUN})
	}
	if len(c.TURN) > 0 {
		if c.TURNUser == "" || c.TURNPassword == "" {
			return webrtc.Configuration{}, errors.New("TURN credentials required")
		}
		servers = append(servers, webrtc.ICEServer{URLs: c.TURN, Username: c.TURNUser, Credential: c.TURNPassword})
	}
	cfg := webrtc.Configuration{ICEServers: servers}
	if c.ForceRelay {
		if len(c.TURN) == 0 {
			return cfg, errors.New("relay-only requires TURN")
		}
		cfg.ICETransportPolicy = webrtc.ICETransportPolicyRelay
	}
	return cfg, nil
}

// Link implements swarm.Link. Control messages are reliable/ordered; coded
// shard messages use a separate unordered channel without retransmissions.
type Link struct {
	pc          *webrtc.PeerConnection
	mu          sync.Mutex
	control     *webrtc.DataChannel
	data        *webrtc.DataChannel
	controlOpen bool
	dataOpen    bool
	incoming    chan []byte
	ready       chan struct{}
	closed      chan struct{}
	readyOnce   sync.Once
	closeOnce   sync.Once
}

func New(c Config, initiator bool) (*Link, error) {
	cfg, err := c.webrtcConfig()
	if err != nil {
		return nil, err
	}
	var pc *webrtc.PeerConnection
	if c.UDPPortMin != 0 || c.UDPPortMax != 0 {
		if c.UDPPortMin < 1024 || c.UDPPortMax < c.UDPPortMin {
			return nil, errors.New("invalid LAN WebRTC UDP port range")
		}
		settings := webrtc.SettingEngine{}
		if err := settings.SetEphemeralUDPPortRange(c.UDPPortMin, c.UDPPortMax); err != nil {
			return nil, err
		}
		pc, err = webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(cfg)
	} else {
		pc, err = webrtc.NewPeerConnection(cfg)
	}
	if err != nil {
		return nil, err
	}
	l := &Link{pc: pc, incoming: make(chan []byte, 512), ready: make(chan struct{}), closed: make(chan struct{})}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			_ = l.Close()
		}
	})
	pc.OnDataChannel(l.attach)
	if initiator {
		ctl, e := pc.CreateDataChannel("badsharing-control", nil)
		if e != nil {
			_ = l.Close()
			return nil, e
		}
		l.attach(ctl)
		ordered := false
		retries := uint16(0)
		ch, e := pc.CreateDataChannel("badsharing-rlnc", &webrtc.DataChannelInit{Ordered: &ordered, MaxRetransmits: &retries})
		if e != nil {
			_ = l.Close()
			return nil, e
		}
		l.attach(ch)
	}
	return l, nil
}

func (l *Link) attach(dc *webrtc.DataChannel) {
	isControl := dc.Label() == "badsharing-control"
	if !isControl && dc.Label() != "badsharing-rlnc" {
		_ = dc.Close()
		return
	}
	l.mu.Lock()
	if isControl {
		if l.control != nil && l.control != dc {
			l.mu.Unlock()
			_ = dc.Close()
			return
		}
		l.control = dc
	} else {
		if l.data != nil && l.data != dc {
			l.mu.Unlock()
			_ = dc.Close()
			return
		}
		l.data = dc
	}
	l.mu.Unlock()
	dc.OnOpen(func() {
		l.mu.Lock()
		if isControl {
			l.controlOpen = true
		} else {
			l.dataOpen = true
		}
		done := l.controlOpen && l.dataOpen
		l.mu.Unlock()
		if done {
			l.readyOnce.Do(func() { close(l.ready) })
		}
	})
	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if m.IsString || len(m.Data) == 0 || len(m.Data) > maxFrame {
			return
		}
		// A stalled receiver cannot consume unbounded memory.
		copyFrame := append([]byte(nil), m.Data...)
		select {
		case l.incoming <- copyFrame:
		case <-l.closed:
		default:
			_ = l.Close()
		}
	})
	dc.OnClose(func() { _ = l.Close() })
}

func (l *Link) Offer(ctx context.Context) (string, error) {
	desc, err := l.pc.CreateOffer(nil)
	if err != nil {
		return "", err
	}
	complete := webrtc.GatheringCompletePromise(l.pc)
	if err := l.pc.SetLocalDescription(desc); err != nil {
		return "", err
	}
	select {
	case <-complete:
	case <-ctx.Done():
		return "", ctx.Err()
	case <-l.closed:
		return "", errors.New("link closed")
	}
	local := l.pc.LocalDescription()
	if local == nil {
		return "", errors.New("missing local SDP")
	}
	return local.SDP, nil
}
func (l *Link) Answer(ctx context.Context, sdp string) (string, error) {
	if err := l.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: sdp}); err != nil {
		return "", err
	}
	ans, err := l.pc.CreateAnswer(nil)
	if err != nil {
		return "", err
	}
	complete := webrtc.GatheringCompletePromise(l.pc)
	if err := l.pc.SetLocalDescription(ans); err != nil {
		return "", err
	}
	select {
	case <-complete:
	case <-ctx.Done():
		return "", ctx.Err()
	case <-l.closed:
		return "", errors.New("link closed")
	}
	local := l.pc.LocalDescription()
	if local == nil {
		return "", errors.New("missing local SDP")
	}
	return local.SDP, nil
}
func (l *Link) AcceptAnswer(sdp string) error {
	return l.pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: sdp})
}
func (l *Link) WaitReady(ctx context.Context) error {
	select {
	case <-l.ready:
		return nil
	case <-l.closed:
		return errors.New("WebRTC connection closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (l *Link) Closed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}

func (l *Link) Send(ctx context.Context, payload []byte) error {
	if len(payload) < 1 || len(payload) > maxFrame {
		return errors.New("invalid WebRTC message size")
	}
	if err := l.WaitReady(ctx); err != nil {
		return err
	}
	// BSW1/2 is the coded RLNC frame; all other messages are control.
	isShard := len(payload) >= 5 && string(payload[:4]) == "BSW1" && payload[4] == 2
	for {
		l.mu.Lock()
		ch := l.control
		if isShard {
			ch = l.data
		}
		if ch == nil {
			l.mu.Unlock()
			return errors.New("WebRTC channel unavailable")
		}
		if ch.BufferedAmount() < maxBuffered {
			err := ch.Send(payload)
			l.mu.Unlock()
			return err
		}
		l.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.closed:
			return errors.New("WebRTC connection closed")
		case <-time.After(15 * time.Millisecond):
		}
	}
}
func (l *Link) Recv(ctx context.Context) ([]byte, error) {
	if err := l.WaitReady(ctx); err != nil {
		return nil, err
	}
	select {
	case frame := <-l.incoming:
		return frame, nil
	case <-l.closed:
		return nil, errors.New("WebRTC connection closed")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (l *Link) Close() error {
	var err error
	l.closeOnce.Do(func() { close(l.closed); err = l.pc.Close() })
	return err
}
