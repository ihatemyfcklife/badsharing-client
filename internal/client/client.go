// Package client connects the badsharing swarm engine to a desktop app.
// No GUI dependency is imported here, so transfers are independently testable.
package client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ihatemyfcklife/badsharing"
	"github.com/ihatemyfcklife/badsharing-client/internal/rtc"
	"github.com/ihatemyfcklife/badsharing-client/internal/settings"
	"github.com/ihatemyfcklife/badsharing/signaling"
	"github.com/ihatemyfcklife/badsharing/swarm"
)

type Mode string

const (
	Send    Mode = "send"
	Receive Mode = "receive"
)

type Request struct {
	Mode            Mode
	Config          settings.Config
	File            string
	OutputDirectory string
	OutputName      string
	Sources         int
	Gather          time.Duration
}

type Event struct {
	State     string
	Message   string
	Sent      int64
	Received  int64
	Total     int64
	Connected int
}

type Notify func(Event)

type Transfer struct {
	sendBytes atomic.Int64
	recvBytes atomic.Int64
	peers     atomic.Int32
	callback  Notify
	mu        sync.Mutex
	state     string
	message   string
	total     int64
}

func (t *Transfer) publish(state, msg string) {
	t.mu.Lock()
	if state != "" {
		t.state = state
	}
	if msg != "" {
		t.message = msg
	}
	snapshot := Event{State: t.state, Message: t.message, Total: t.total, Sent: t.sendBytes.Load(), Received: t.recvBytes.Load(), Connected: int(t.peers.Load())}
	t.mu.Unlock()
	if t.callback != nil {
		t.callback(snapshot)
	}
}
func (t *Transfer) pulse(ctx context.Context) {
	timer := time.NewTicker(300 * time.Millisecond)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			t.publish("", "")
		}
	}
}
func NewTransfer(onEvent Notify) *Transfer { return &Transfer{callback: onEvent} }

func (t *Transfer) Run(ctx context.Context, r Request) error {
	if ctx == nil {
		return errors.New("context is required")
	}
	key, err := r.Config.Validate()
	if err != nil {
		return err
	}
	if r.Mode != Send && r.Mode != Receive {
		return errors.New("unknown transfer mode")
	}
	if r.Sources < 1 || r.Sources > 16 {
		return errors.New("sources must be in the range 1..16")
	}
	peerID, err := settings.RandomHex(12)
	if err != nil {
		return err
	}
	client := &signaling.Client{BaseURL: strings.TrimRight(r.Config.SignalURL, "/"), Room: r.Config.Room, PeerID: peerID, Token: r.Config.Token}
	if r.Config.CertPin != "" {
		httpClient, err := settings.PinnedHTTP(r.Config.CertPin, 10*time.Second)
		if err != nil {
			return err
		}
		client.HTTP = httpClient
		defer httpClient.CloseIdleConnections()
	}
	ice := rtc.Config{STUN: settings.ParseAddresses(r.Config.STUN), TURN: settings.ParseAddresses(r.Config.TURN), TURNUser: r.Config.TURNUser, TURNPassword: r.Config.TURNPassword, ForceRelay: r.Config.RelayOnly, UDPPortMin: r.Config.UDPPortMin, UDPPortMax: r.Config.UDPPortMax}
	coordinator := &rtc.Coordinator{Signal: client, ICE: ice, MaxPeers: 16, OnStatus: func(msg string) { t.publish("", msg) }}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go t.pulse(runCtx)
	t.publish("Connecting", "Joining room "+r.Config.Room)
	if r.Mode == Send {
		return t.send(runCtx, coordinator, r, key)
	}
	return t.receive(runCtx, coordinator, r, key)
}

type meterLink struct {
	swarm.Link
	uploaded *atomic.Int64
}

func (m meterLink) Send(ctx context.Context, p []byte) error {
	if err := m.Link.Send(ctx, p); err != nil {
		return err
	}
	// Records bytes actually passed to the WebRTC transport, not delivery acknowledgements.
	m.uploaded.Add(int64(len(p)))
	return nil
}

type trackedWriter struct {
	io.WriterAt
	downloaded *atomic.Int64
}

func (w trackedWriter) WriteAt(b []byte, off int64) (int, error) {
	n, err := w.WriterAt.WriteAt(b, off)
	if n > 0 {
		w.downloaded.Add(int64(n))
	}
	return n, err
}

func stableManifestID(meta *badsharing.FileMetadata, key [32]byte) {
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("badsharing-content-manifest-v1"))
	_, _ = mac.Write(meta.Checksum[:])
	meta.SessionID = binary.BigEndian.Uint64(mac.Sum(nil)[:8])
	if meta.SessionID == 0 {
		meta.SessionID = 1
	}
}

func (t *Transfer) send(ctx context.Context, c *rtc.Coordinator, r Request, key [32]byte) error {
	f, err := os.Open(r.File)
	if err != nil {
		return fmt.Errorf("open selected file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("sender requires a regular local file")
	}
	meta, err := badsharing.NewFileMetadata(info.Name(), f)
	if err != nil {
		return err
	}
	stableManifestID(meta, key)
	manifest, err := badsharing.BuildGenerationManifest(*meta, f, key)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.total = int64(meta.Size)
	t.mu.Unlock()
	t.publish("Seeding", fmt.Sprintf("Sharing %s — waiting for peers", meta.Name))
	var jobs sync.WaitGroup
	seedCtx, seedStop := context.WithCancel(ctx)
	defer func() { seedStop(); jobs.Wait() }()
	err = c.Run(seedCtx, func(id string, link *rtc.Link) {
		t.peers.Add(1)
		t.publish("Seeding", "Connected to "+id)
		jobs.Add(1)
		go func() {
			defer jobs.Done()
			defer t.peers.Add(-1)
			defer link.Close()
			wrapped := meterLink{Link: link, uploaded: &t.sendBytes}
			if err := swarm.SendManifest(seedCtx, wrapped, manifest); err != nil {
				if seedCtx.Err() == nil {
					t.publish("Seeding", "Manifest to peer failed: "+err.Error())
				}
				return
			}
			source := &swarm.Source{Manifest: manifest, Reader: f, Key: key, Redundancy: 0.6, RateLimitBytesPerSecond: 0}
			if err := source.Serve(seedCtx, wrapped); err != nil && seedCtx.Err() == nil {
				t.publish("Seeding", "Peer disconnected: "+id)
			}
		}()
	})
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type seed struct {
	id       string
	link     *rtc.Link
	manifest *badsharing.GenerationManifest
}

// OutputPath rejects traversal and never allows output filenames to escape the
// user-selected destination directory. Existing final files are never replaced.
func OutputPath(folder, name string) (string, error) {
	if folder == "" {
		return "", errors.New("choose a destination folder")
	}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, "/\\") {
		return "", errors.New("output name must be a single filename")
	}
	if strings.ContainsAny(name, "\x00\r\n:*?\"<>|") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, " ") {
		return "", errors.New("filename is not portable to Windows")
	}
	if strings.ContainsAny(name, "\x00\r\n") {
		return "", errors.New("invalid output filename")
	}
	nameBase := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch nameBase {
	case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
		return "", errors.New("reserved Windows filename")
	}
	stat, err := os.Stat(folder)
	if err != nil {
		return "", err
	}
	if !stat.IsDir() {
		return "", errors.New("destination is not a directory")
	}
	return filepath.Join(folder, name), nil
}
func (t *Transfer) receive(ctx context.Context, c *rtc.Coordinator, r Request, key [32]byte) error {
	if r.OutputDirectory == "" {
		return errors.New("choose a destination folder")
	}
	if r.Gather <= 0 {
		r.Gather = 4 * time.Second
	}
	incoming := make(chan seed, 16)
	setupErrors := make(chan error, 1)
	sessionCtx, stop := context.WithCancel(ctx)
	var readerJobs sync.WaitGroup
	defer func() { stop(); readerJobs.Wait() }()
	readerJobs.Add(1)
	go func() {
		defer readerJobs.Done()
		err := c.Run(sessionCtx, func(id string, link *rtc.Link) {
			readerJobs.Add(1)
			go func() {
				defer readerJobs.Done()
				manifest, err := swarm.ReceiveManifest(sessionCtx, link, key)
				if err != nil {
					_ = link.Close()
					if sessionCtx.Err() == nil {
						t.publish("Connecting", "Rejected manifest from "+id)
					}
					return
				}
				select {
				case incoming <- seed{id: id, link: link, manifest: manifest}:
				case <-sessionCtx.Done():
					_ = link.Close()
				}
			}()
		})
		if err != nil && sessionCtx.Err() == nil {
			select {
			case setupErrors <- err:
			default:
				{
				}
			}
		}
	}()
	var chosen []seed
	select {
	case first := <-incoming:
		chosen = append(chosen, first)
	case err := <-setupErrors:
		return err
	case <-ctx.Done():
		return nil
	}
	timer := time.NewTimer(r.Gather)
	defer timer.Stop()
gather:
	for len(chosen) < r.Sources {
		select {
		case candidate := <-incoming:
			if bytes.Equal(candidate.manifest.Signature[:], chosen[0].manifest.Signature[:]) {
				chosen = append(chosen, candidate)
			} else {
				_ = candidate.link.Close()
				t.publish("Connecting", "Skipped a peer sharing a different file")
			}
		case <-timer.C:
			break gather
		case <-ctx.Done():
			return nil
		}
	}
	defer func() {
		for _, peer := range chosen {
			_ = peer.link.Close()
		}
	}()
	manifest := chosen[0].manifest
	name := r.OutputName
	if name == "" {
		name = manifest.Metadata.Name
	}
	target, err := OutputPath(r.OutputDirectory, name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(target); err == nil {
		return errors.New("completed file already exists: " + target)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// A resumed .part file is always rehashed by swarm.Download before trusting it.
	part := target + ".part"
	if st, checkErr := os.Lstat(part); checkErr == nil {
		if !st.Mode().IsRegular() {
			return errors.New("partial output path is not a regular file")
		}
	} else if !errors.Is(checkErr, os.ErrNotExist) {
		return checkErr
	}
	out, err := os.OpenFile(part, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	initial, err := swarm.VerifyExisting(manifest, out, key)
	if err != nil {
		return err
	}
	var reused int64
	for gen := range initial {
		_, size, e := badsharing.GenerationRange(manifest.Metadata, gen)
		if e != nil {
			return e
		}
		reused += size
	}
	t.recvBytes.Store(reused)
	t.mu.Lock()
	t.total = int64(manifest.Metadata.Size)
	t.mu.Unlock()
	t.peers.Store(int32(len(chosen)))
	t.publish("Downloading", fmt.Sprintf("%s • %d verified generations resumed", name, len(initial)))
	var peers []swarm.Peer
	for _, p := range chosen {
		peers = append(peers, swarm.Peer{ID: p.id, Link: p.link})
	}
	stats, err := swarm.Download(ctx, manifest, trackedWriter{WriterAt: out, downloaded: &t.recvBytes}, key, peers, swarm.DownloadOptions{
		MaxActiveGenerations: 8, MaxAttempts: 12, RetryInterval: 2 * time.Second, ReaderAt: out,
	})
	if err != nil {
		if ctx.Err() != nil {
			t.publish("Cancelled", "Partial file kept at "+part)
			return nil
		}
		return fmt.Errorf("download interrupted (partial file at %s): %w", part, err)
	}
	if err := out.Truncate(int64(manifest.Metadata.Size)); err != nil {
		return err
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(part, target); err != nil {
		return err
	}
	t.recvBytes.Store(int64(manifest.Metadata.Size))
	t.publish("Complete", fmt.Sprintf("Verified %s • %d/%d generations (%d resumed)", name, stats.Completed, stats.Total, stats.Resumed))
	return nil
}
