package desktop

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ihatemyfcklife/badsharing-client/internal/client"
	"github.com/ihatemyfcklife/badsharing-client/internal/settings"
)

type Desktop struct {
	app    fyne.App
	window fyne.Window

	signal      *widget.Entry
	room        *widget.Entry
	token       *widget.Entry
	key         *widget.Entry
	stun        *widget.Entry
	turn        *widget.Entry
	turnUser    *widget.Entry
	turnPass    *widget.Entry
	relayOnly   *widget.Check
	advanced    *widget.Check
	localServer *settings.LocalServer
	invite      *widget.Entry
	inviteInput *widget.Entry

	file       *widget.Entry
	folder     *widget.Entry
	filename   *widget.Entry
	sources    *widget.Select
	gather     *widget.Select
	sendButton *widget.Button
	recvButton *widget.Button
	stopButton *widget.Button

	state      *widget.Label
	detail     *widget.Label
	progress   *widget.ProgressBar
	throughput *widget.Label
	log        *widget.Entry
	messages   []string
	stop       context.CancelFunc
	running    bool
}

func Run() {
	d := &Desktop{app: app.NewWithID("io.github.ihatemyfcklife.badsharing-client")}
	d.app.Settings().SetTheme(theme.DarkTheme())
	d.window = d.app.NewWindow("badsharing-client | Encrypted P2P desktop")
	d.window.Resize(fyne.NewSize(1080, 780))
	d.build()
	d.window.SetCloseIntercept(func() {
		if d.stop != nil {
			d.stop()
		}
		if d.localServer != nil {
			_ = d.localServer.Close()
		}
		d.app.Quit()
	})
	d.window.ShowAndRun()
}

func (d *Desktop) addLog(message string) {
	line := time.Now().Format("15:04:05") + "  " + message
	d.messages = append(d.messages, line)
	if len(d.messages) > 90 {
		d.messages = d.messages[len(d.messages)-90:]
	}
	d.log.SetText(strings.Join(d.messages, "\n"))
}
func (d *Desktop) notify(e client.Event) {
	fyne.Do(func() {
		d.state.SetText(e.State)
		d.detail.SetText(e.Message)
		d.throughput.SetText(fmt.Sprintf("↑ %s   ↓ %s   •   Peers %d", human(e.Sent), human(e.Received), e.Connected))
		if e.Total > 0 && (e.State == "Downloading" || e.State == "Complete") {
			d.progress.SetValue(min(1, float64(e.Received)/float64(e.Total)))
		}
		if len(d.messages) == 0 || !strings.HasSuffix(d.messages[len(d.messages)-1], "  "+e.Message) {
			if e.Message != "" {
				d.addLog(e.Message)
			}
		}
	})
}
func human(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	x := float64(n)
	for _, unit := range []string{"KiB", "MiB", "GiB", "TiB"} {
		x /= 1024
		if x < 1024 || unit == "TiB" {
			return fmt.Sprintf("%.1f %s", x, unit)
		}
	}
	return fmt.Sprintf("%d B", n)
}
func entry(value, placeholder string) *widget.Entry {
	e := widget.NewEntry()
	e.SetText(value)
	e.SetPlaceHolder(placeholder)
	return e
}
func secretEntry(placeholder string) *widget.Entry {
	e := widget.NewPasswordEntry()
	e.SetPlaceHolder(placeholder)
	return e
}
func (d *Desktop) settings() fyne.CanvasObject {
	d.signal = entry("http://127.0.0.1:8088", "https://signal.example.com")
	d.room = entry("private-room", "Letters, numbers, underscore and dash")
	d.token = secretEntry("32+ character signaling bearer token")
	d.key = secretEntry("64 hexadecimal characters / 32 bytes")
	d.stun = entry(settings.DefaultSTUN, "stun:stun.example.com:3478")
	d.turn = entry("", "turn:turn.example.com:3478")
	d.turnUser = entry("", "Temporary TURN username")
	d.turnPass = secretEntry("Temporary TURN password")
	d.advanced = widget.NewCheck("Use custom signaling server instead of automatic LAN sharing", nil)
	d.relayOnly = widget.NewCheck("Force TURN relaying (testing / restricted networks)", nil)
	generate := widget.NewButtonWithIcon("Generate secure credentials", theme.ConfirmIcon(), func() {
		token, err := settings.RandomHex(32)
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		key, err := settings.RandomHex(32)
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.token.SetText(token)
		d.key.SetText(key)
		d.addLog("New random credentials generated. Share them securely with participants.")
	})
	copyRoom := widget.NewButtonWithIcon("Copy room details (no secrets)", theme.ContentCopyIcon(), func() {
		d.window.Clipboard().SetContent("Signaling: " + strings.TrimSpace(d.signal.Text) + "\nRoom: " + strings.TrimSpace(d.room.Text))
	})
	copyKey := widget.NewButtonWithIcon("Copy file key", theme.ContentCopyIcon(), func() {
		if d.key.Text != "" {
			d.window.Clipboard().SetContent(d.key.Text)
			d.addLog("File key copied to clipboard. Clear clipboard after sharing securely.")
		}
	})
	copyToken := widget.NewButtonWithIcon("Copy signaling token", theme.ContentCopyIcon(), func() {
		if d.token.Text != "" {
			d.window.Clipboard().SetContent(d.token.Text)
			d.addLog("Signaling token copied. Clear clipboard after sharing securely.")
		}
	})
	form := widget.NewForm(
		widget.NewFormItem("Signaling server", d.signal),
		widget.NewFormItem("Private room", d.room),
		widget.NewFormItem("Signaling token", d.token),
		widget.NewFormItem("Transfer key", d.key),
		widget.NewFormItem("STUN server(s)", d.stun),
		widget.NewFormItem("TURN server(s)", d.turn),
		widget.NewFormItem("TURN username", d.turnUser),
		widget.NewFormItem("TURN password", d.turnPass),
	)
	note := widget.NewLabel("Credentials remain in memory. Clipboard is not secret storage: clear it after securely sharing keys. Use HTTPS for non-local signaling.")
	note.Wrapping = fyne.TextWrapWord
	return container.NewPadded(container.NewVScroll(container.NewVBox(
		widget.NewLabel("Automatic LAN mode is on by default. The sender starts a private HTTPS signaling service and creates a share code. Advanced mode is only for an externally hosted server."),
		d.advanced,
		widget.NewCard("Advanced connection settings", "Only needed for public Internet signaling/TURN infrastructure", form),
		d.relayOnly,
		container.NewHBox(generate, copyRoom),
		container.NewHBox(copyKey, copyToken),
		note,
	)))
}
func pathFromURI(u fyne.URI) (string, error) {
	if u == nil || u.Scheme() != "file" {
		return "", fmt.Errorf("choose a local file or folder")
	}
	p := u.Path()
	if runtime.GOOS == "windows" && len(p) > 2 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), nil
}
func (d *Desktop) sendPage() fyne.CanvasObject {
	d.file = entry("", "Choose a local file")
	browse := widget.NewButtonWithIcon("Browse file", theme.FolderOpenIcon(), func() {
		dialog.ShowFileOpen(func(f fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, d.window)
				return
			}
			if f == nil {
				return
			}
			defer f.Close()
			path, err := pathFromURI(f.URI())
			if err != nil {
				dialog.ShowError(err, d.window)
				return
			}
			d.file.SetText(path)
		}, d.window)
	})
	d.invite = widget.NewMultiLineEntry()
	d.invite.SetPlaceHolder("Your private invitation will appear here after starting a share")
	d.invite.SetMinRowsVisible(3)
	copyInvite := widget.NewButtonWithIcon("Copy invitation", theme.ContentCopyIcon(), func() {
		if d.invite.Text != "" {
			d.window.Clipboard().SetContent(strings.TrimSpace(d.invite.Text))
			d.addLog("Private share invitation copied. Send it through a trusted channel.")
		}
	})
	d.sendButton = widget.NewButtonWithIcon("Start sharing", theme.UploadIcon(), func() { d.start(client.Send) })
	d.sendButton.Importance = widget.HighImportance
	help := widget.NewLabel("Keep this window open while other peers download the file. File contents never pass through the signaling server.")
	help.Wrapping = fyne.TextWrapWord
	return container.NewPadded(container.NewVScroll(container.NewVBox(
		widget.NewCard("Share a file", "Encrypted P2P upload", container.NewVBox(
			widget.NewLabel("File to share"), d.file, browse, d.sendButton,
			widget.NewLabel("Invitation (share only with trusted recipients)"), d.invite, copyInvite,
		)),
		help,
		widget.NewCard("How it works", "",
			widget.NewLabel("The client hashes the source, signs per-generation digests, encrypts RLNC shards and serves requests from connected peers.")),
	)))
}
func (d *Desktop) receivePage() fyne.CanvasObject {
	defaultFolder := ""
	if home, err := os.UserHomeDir(); err == nil {
		defaultFolder = filepath.Join(home, "Downloads")
		if stat, e := os.Stat(defaultFolder); e != nil || !stat.IsDir() {
			defaultFolder = home
		}
	}
	d.folder = entry(defaultFolder, "Choose destination folder")
	d.inviteInput = widget.NewMultiLineEntry()
	d.inviteInput.SetMinRowsVisible(3)
	d.inviteInput.SetPlaceHolder("Paste the private invitation from the sender here")
	d.filename = entry("", "Optional: use original filename")
	browse := widget.NewButtonWithIcon("Browse folder", theme.FolderOpenIcon(), func() {
		dialog.ShowFolderOpen(func(u fyne.ListableURI, err error) {
			if err != nil {
				dialog.ShowError(err, d.window)
				return
			}
			if u == nil {
				return
			}
			p, err := pathFromURI(u)
			if err != nil {
				dialog.ShowError(err, d.window)
				return
			}
			d.folder.SetText(p)
		}, d.window)
	})
	d.sources = widget.NewSelect([]string{"1", "2", "3", "4", "6", "8", "12", "16"}, nil)
	d.sources.SetSelected("1")
	d.gather = widget.NewSelect([]string{"2s", "4s", "8s", "15s", "30s"}, nil)
	d.gather.SetSelected("4s")
	pasteInvite := widget.NewButtonWithIcon("Paste invitation", theme.ContentPasteIcon(), func() {
		d.inviteInput.SetText(strings.TrimSpace(d.window.Clipboard().Content()))
	})
	d.recvButton = widget.NewButtonWithIcon("Start downloading", theme.DownloadIcon(), func() { d.start(client.Receive) })
	d.recvButton.Importance = widget.HighImportance
	msg := widget.NewLabel("A .part file is kept on interruption; restarting with the same name verifies and reuses complete generations. Existing finished files are never overwritten.")
	msg.Wrapping = fyne.TextWrapWord
	return container.NewPadded(container.NewVScroll(container.NewVBox(
		widget.NewCard("Download a file", "Multi-source RLNC and verified resume", container.NewVBox(
			widget.NewLabel("Private invitation from sender"), d.inviteInput, pasteInvite,
			widget.NewLabel("Destination folder"), d.folder, browse,
			widget.NewLabel("Output filename (optional)"), d.filename,
			container.NewGridWithColumns(2,
				container.NewVBox(widget.NewLabel("Maximum sources"), d.sources),
				container.NewVBox(widget.NewLabel("Peer discovery time"), d.gather),
			),
			d.recvButton,
		)), msg,
	)))
}
func (d *Desktop) config() settings.Config {
	return settings.Config{
		SignalURL: strings.TrimSpace(d.signal.Text), Room: strings.TrimSpace(d.room.Text),
		Token: strings.TrimSpace(d.token.Text), KeyHex: strings.TrimSpace(d.key.Text),
		STUN: d.stun.Text, TURN: d.turn.Text, TURNUser: d.turnUser.Text,
		TURNPassword: d.turnPass.Text, RelayOnly: d.relayOnly.Checked,
	}
}
func (d *Desktop) start(mode client.Mode) {
	if d.running {
		return
	}
	cfg := d.config()
	automatic := !d.advanced.Checked
	var incoming settings.Invite
	var shareCode string
	if automatic && mode == client.Receive {
		parsed, err := settings.DecodeInvite(d.inviteInput.Text)
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		incoming = parsed
	}
	r := client.Request{Mode: mode, Config: cfg, Sources: 1, Gather: 4 * time.Second}
	if mode == client.Send {
		r.File = strings.TrimSpace(d.file.Text)
		if r.File == "" {
			dialog.ShowInformation("Missing file", "Choose a file first.", d.window)
			return
		}
	} else {
		r.OutputDirectory = strings.TrimSpace(d.folder.Text)
		r.OutputName = strings.TrimSpace(d.filename.Text)
		n, err := strconv.Atoi(d.sources.Selected)
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		r.Sources = n
		t, err := time.ParseDuration(d.gather.Selected)
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		r.Gather = t
		if r.OutputDirectory == "" {
			dialog.ShowInformation("Missing folder", "Choose a destination folder.", d.window)
			return
		}
	}
	if automatic && mode == client.Send {
		server, err := settings.StartLocalServer()
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		code, err := server.Invite.Encode()
		if err != nil {
			_ = server.Close()
			dialog.ShowError(err, d.window)
			return
		}
		d.localServer = server
		cfg = settings.Config{
			SignalURL: server.URL, Room: server.Invite.Room, Token: server.Invite.Token,
			KeyHex: server.Invite.Key, CertPin: server.Invite.Pin, UDPPortMin: server.UDPPortMin, UDPPortMax: server.UDPPortMax,
		}
		r.Config = cfg
		shareCode = code
		d.invite.SetText("")
		d.addLog("Starting private LAN signaling service; checking Linux firewall...")
	}
	if !automatic {
		if _, err := cfg.Validate(); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
	}
	serverForShare := d.localServer
	ctx, cancel := context.WithCancel(context.Background())
	d.stop = func() {
		cancel()
		if d.localServer != nil {
			_ = d.localServer.Close()
			d.localServer = nil
		}
	}
	d.running = true
	d.sendButton.Disable()
	d.recvButton.Disable()
	d.stopButton.Enable()
	d.progress.SetValue(0)
	d.throughput.SetText("↑ 0 B   ↓ 0 B   •   Peers 0")
	d.state.SetText("Starting")
	d.detail.SetText("Creating P2P session")
	d.addLog("Starting " + string(mode))
	task := client.NewTransfer(d.notify)
	go func() {
		var err error
		if automatic && mode == client.Send && serverForShare != nil {
			// Linux Mint: if UFW is active, Polkit requests authorization
			// for a temporary, LAN-only TCP rule. Never modify the
			// firewall silently and never block Fyne's UI thread.
			var message string
			message, err = serverForShare.PrepareNetwork(ctx)
			if err == nil && ctx.Err() == nil {
				fyne.Do(func() {
					if ctx.Err() != nil {
						return
					}
					d.addLog(message)
					d.addLog("LAN HTTPS service ready: " + serverForShare.URL)
					d.invite.SetText(shareCode)
					d.window.Clipboard().SetContent(shareCode)
					d.addLog("Invitation copied. Keep the sender online while downloading.")
				})
			}
		}
		if automatic && mode == client.Receive {
			// Network probing happens off the Fyne UI thread.
			fyne.Do(func() { d.addLog("Testing the sender's advertised LAN addresses (Wi-Fi/Ethernet/VPN)") })
			r.Config, err = incoming.Resolve(ctx)
			if err == nil {
				fyne.Do(func() { d.addLog("Connected to sender's private LAN signaling service") })
			}
		}
		if err == nil {
			err = task.Run(ctx, r)
		}
		if mode == client.Send && serverForShare != nil {
			_ = serverForShare.Close()
		}
		fyne.Do(func() {
			d.localServer = nil
			if mode == client.Send && automatic {
				d.invite.SetText("")
			}

			d.running = false
			d.stop = nil
			d.sendButton.Enable()
			d.recvButton.Enable()
			d.stopButton.Disable()
			if err != nil && ctx.Err() == nil {
				d.state.SetText("Error")
				d.detail.SetText(err.Error())
				d.addLog("ERROR: " + err.Error())
				dialog.ShowError(err, d.window)
			} else if ctx.Err() != nil {
				d.state.SetText("Stopped")
				d.detail.SetText("Session stopped. Partial downloads are preserved.")
				d.addLog("Transfer stopped")
			} else if mode == client.Send {
				d.state.SetText("Stopped")
			}
		})
	}()
}
func (d *Desktop) build() {
	d.state = widget.NewLabelWithStyle("Idle", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	d.detail = widget.NewLabel("Choose a file and start sharing, or paste an invitation to receive.")
	d.detail.Wrapping = fyne.TextWrapWord
	d.progress = widget.NewProgressBar()
	d.throughput = widget.NewLabel("↑ 0 B   ↓ 0 B   •   Peers 0")
	d.log = widget.NewMultiLineEntry()
	d.log.SetMinRowsVisible(5)
	d.log.Wrapping = fyne.TextWrapBreak
	d.log.Disable()
	d.stopButton = widget.NewButtonWithIcon("Stop transfer", theme.CancelIcon(), func() {
		if d.stop != nil {
			d.stop()
		}
	})
	d.stopButton.Disable()
	tabs := container.NewAppTabs(
		container.NewTabItemWithIcon("Send", theme.UploadIcon(), d.sendPage()),
		container.NewTabItemWithIcon("Receive", theme.DownloadIcon(), d.receivePage()),
		container.NewTabItemWithIcon("Advanced", theme.SettingsIcon(), d.settings()),
	)
	tabs.SelectIndex(0)
	heading := widget.NewLabelWithStyle("badsharing-client", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	subheading := widget.NewLabel("PRIVATE FILE SHARING  •  RLNC  •  WEBRTC  •  LINUX / WINDOWS")
	github, _ := url.Parse("https://github.com/ihatemyfcklife/badsharing")
	footer := container.NewBorder(nil, nil, nil, widget.NewHyperlink("Engine source", github), widget.NewLabel("Desktop client • No telemetry • Secrets are never saved"))
	monitoring := widget.NewCard("Transfer monitor", "", container.NewVBox(
		container.NewBorder(nil, nil, nil, d.stopButton, d.state), d.detail, d.progress, d.throughput,
		widget.NewLabel("Event log"), d.log,
	))
	d.window.SetContent(container.NewBorder(
		container.NewPadded(container.NewVBox(heading, subheading)),
		container.NewPadded(footer), nil, nil,
		container.NewVSplit(tabs, container.NewPadded(monitoring)),
	))
	d.addLog("Ready. Local sharing is automatic; no signaling credentials to configure.")
}
