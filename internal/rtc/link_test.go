package rtc

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestLocalWebRTCDataChannels(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	a, err := New(Config{}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(Config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	sdp, err := a.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := b.Answer(ctx, sdp)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.AcceptAnswer(reply); err != nil {
		t.Fatal(err)
	}
	if err := a.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	for _, frame := range [][]byte{[]byte("control"), append([]byte("BSW1\x02"), bytes.Repeat([]byte{4}, 1388)...)} {
		if err := a.Send(ctx, frame); err != nil {
			t.Fatal(err)
		}
		got, err := b.Recv(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(frame, got) {
			t.Fatalf("received incorrect %d-byte message", len(got))
		}
	}
}
func TestRelayOnlyNeedsTURN(t *testing.T) {
	l, err := New(Config{ForceRelay: true}, true)
	if l != nil {
		_ = l.Close()
	}
	if err == nil {
		t.Fatal("relay-only without TURN accepted")
	}
}

// Verify ICE candidate gathering stays functional when a sender uses a
// restricted UDP range compatible with a temporary LAN firewall allowance.
func TestRestrictedUDPPortRange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a, err := New(Config{UDPPortMin: 59100, UDPPortMax: 59163}, true)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := New(Config{}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	offer, err := a.Offer(ctx)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := b.Answer(ctx, offer)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.AcceptAnswer(answer); err != nil {
		t.Fatal(err)
	}
	if err = a.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err = b.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	if err = a.Send(ctx, []byte("private LAN transfer")); err != nil {
		t.Fatal(err)
	}
	payload, err := b.Recv(ctx)
	if err != nil || string(payload) != "private LAN transfer" {
		t.Fatalf("bad WebRTC transfer: %q (%v)", payload, err)
	}
}
