package rtc

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/ihatemyfcklife/badsharing/signaling"
)

// Coordinator uses authenticated signaling for SDP rendezvous. Lower peer IDs
// create offers; higher IDs answer. Full ICE gathering avoids trickle signaling.
type Coordinator struct {
	Signal   *signaling.Client
	ICE      Config
	MaxPeers int
	OnStatus func(string)
}

func (c *Coordinator) Run(ctx context.Context, onConnected func(string, *Link)) error {
	if ctx == nil || c == nil || c.Signal == nil || onConnected == nil {
		return errors.New("invalid WebRTC coordinator")
	}
	limit := c.MaxPeers
	if limit <= 0 || limit > 16 {
		limit = 16
	}
	links := map[string]*Link{}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	status := func(msg string) {
		if c.OnStatus != nil {
			c.OnStatus(msg)
		}
	}
	// Joining a room requires a peer list request.
	if _, err := c.Signal.Peers(ctx); err != nil {
		return err
	}
	status("Registered with signaling server")
	ticker := time.NewTicker(1800 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		for id, l := range links {
			if l.Closed() {
				delete(links, id)
			}
		}
		peers, err := c.Signal.Peers(ctx)
		if err != nil {
			return err
		}
		sort.Strings(peers)
		for _, id := range peers {
			if len(links) >= limit {
				break
			}
			if id <= c.Signal.PeerID || links[id] != nil {
				continue
			}
			l, err := New(c.ICE, true)
			if err != nil {
				return err
			}
			links[id] = l
			offerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			sdp, err := l.Offer(offerCtx)
			cancel()
			if err != nil {
				_ = l.Close()
				delete(links, id)
				continue
			}
			if err := c.Signal.Send(ctx, id, "offer", sdp); err != nil {
				_ = l.Close()
				delete(links, id)
				continue
			}
			c.onConnection(ctx, id, l, onConnected)
		}
		messages, err := c.Signal.Receive(ctx)
		if err != nil {
			return err
		}
		for _, message := range messages {
			if message.To != c.Signal.PeerID || message.From == c.Signal.PeerID {
				continue
			}
			id := message.From
			switch message.Type {
			case "offer":
				if id >= c.Signal.PeerID || links[id] != nil || len(links) >= limit {
					continue
				}
				l, err := New(c.ICE, false)
				if err != nil {
					return err
				}
				links[id] = l
				answerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				sdp, err := l.Answer(answerCtx, message.Data)
				cancel()
				if err != nil {
					_ = l.Close()
					delete(links, id)
					continue
				}
				if err := c.Signal.Send(ctx, id, "answer", sdp); err != nil {
					_ = l.Close()
					delete(links, id)
					continue
				}
				c.onConnection(ctx, id, l, onConnected)
			case "answer":
				if l := links[id]; l != nil {
					if err := l.AcceptAnswer(message.Data); err != nil {
						_ = l.Close()
						delete(links, id)
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (c *Coordinator) onConnection(ctx context.Context, id string, l *Link, onConnected func(string, *Link)) {
	go func() {
		readyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err := l.WaitReady(readyCtx); err != nil {
			_ = l.Close()
			return
		}
		if c.OnStatus != nil {
			c.OnStatus("Peer connected: " + id)
		}
		onConnected(id, l)
	}()
}
