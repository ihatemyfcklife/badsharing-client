# badsharing-client

Desktop file sharing for Linux Mint / Linux and Windows, powered by [badsharing](https://github.com/ihatemyfcklife/badsharing), **badcrypt**, **badrlnc**, and **Pion WebRTC**. The interface is written in Go with Fyne.

## For users: no setup

**Install a compiled release; do not run `go run` to install the application.** The desktop client does not require users to install Go, GCC, GLFW, X11 headers, Wayland headers, certificates, or signaling packages.

- **Linux Mint / Ubuntu (64-bit):** download `badsharing-client_<version>_amd64.deb` from the GitHub release. Open it with your package installer, which handles runtime dependencies, then launch **badsharing-client** from the application menu.
- **Windows (64-bit):** download `badsharing-client-windows-amd64.exe` from the release and double-click it. Windows may ask for firewall permission on the local network.

**Automatic sharing on the same LAN / Wi-Fi:**

1. Sender opens **Send**, chooses a file, clicks **Start sharing**.
2. The client starts a temporary **HTTPS signaling service** locally, generates fresh session credentials and a private certificate, and copies an invitation code to the clipboard.
3. Sender sends that code to a trusted recipient, e.g., in an end-to-end encrypted messenger.
4. Recipient opens **Receive**, pastes the code, clicks **Start downloading**. The client automatically finds the sender on the local network and verifies its pinned TLS certificate.
5. The client defaults to your `~/Downloads` directory when available; partial downloads are resumed and verified. Stop the sender to shut down the signaling service and invalidate the invitation.

No manual room, shared key, signaling port, IP address, TLS certificate or ICE/STUN setting is needed in **automatic LAN mode**. No external STUN server is contacted in automatic LAN mode. The sender also checks its HTTPS listener and pinned certificate before sharing the invite.

**Linux Mint firewall automation:** if UFW is active, the sender opens **temporary and narrowly scoped** inbound rules for the HTTPS signaling TCP port **and** a restricted WebRTC ICE UDP range on the detected physical Ethernet/Wi-Fi LAN interface. The operating system displays a Polkit (`pkexec`) administrator authorization dialog; users need only approve it. The allowed source is the LAN subnet, and the destination is the sender's local IP and exact session-specific TCP port / UDP range—not all public networks. The app uses a supervised helper that removes its added rules when sharing stops, even if the GUI process exits unexpectedly (subject to OS/process failure). If UFW is disabled, no privileged action occurs. No system firewall is disabled. If the OS authorization is refused or unavailable, the app gives an explicit error instead of offering a misleading invitation.

Both peers still need IP reachability and local firewalls must allow the sender's inbound HTTPS connection. The client prioritizes physical Wi-Fi/Ethernet addresses and probes all advertised addresses in parallel; it displays the actual address and connection error when pairing fails instead of incorrectly concluding that the PCs are on different networks. The invitation is a **secret**: anyone holding it may join the group; share it privately. Pinned TLS authenticates the embedded HTTPS rendezvous and file frames remain end-to-end encrypted.

### Internet transfers

**Zero-configuration Internet sharing is not yet available.** A reliable transfer across unrelated networks requires publicly reachable HTTPS signaling, plus TURN when direct ICE connectivity is blocked. Neither a public signaling service nor TURN infrastructure is included/operated by this project. The **Advanced** tab supports connecting to an existing operator-managed signaling/TURN deployment, but users of the default LAN mode do not need it. It would be misleading and insecure to embed shared public signaling credentials or TURN secrets in the application.

This project is not a DHT or a public decentralized network. A green CI build does not guarantee NAT traversal, large-scale performance or security review.

## Troubleshooting LAN pairing

If the receiver cannot reach the sender after pasting an invitation, the app displays the **candidate private IP addresses and port** that it tried, plus the network or TLS error. This is **not proof that the devices are on different LANs**.

- Keep the sender's share active and verify the invite was created by the current session.
- On **Windows**, allow `badsharing-client.exe` for **Private networks** in Windows Defender Firewall. The sender opens an inbound temporary TCP HTTPS listening port. A firewall denial may look like a connection timeout.
- On **Linux Mint**, the client now detects enabled UFW and requests permission for a temporary LAN-only exception automatically. Approve the standard Linux authorization dialog. If no dialog appears, UFW may be inactive (common default). If UFW is active and no Polkit agent is installed, install `pkexec` or use the packaged application. The client does **not** disable UFW. Other firewall products or VPN kill switches may require separate permissions.
- Avoid guest Wi-Fi, wireless client isolation, or separate VLANs that block device-to-device traffic even when connected to the same router.
- Compare the candidate IP shown by the receiver with the sender's actual Wi-Fi/Ethernet IPv4 address (`ip -4 addr` on Linux, `ipconfig` on Windows). A virtual/VPN address will usually not be reachable from the other computer.

The client cannot bypass OS security approvals, a VPN kill switch, guest Wi-Fi isolation, or router isolation. A Linux UFW permission dialog is expected when UFW is enabled. A successful local listener check cannot prove that the second PC can reach the sender. For global zero-configuration Internet sharing it would additionally need deployed signaling and TURN infrastructure, which this repository does not supply.

## Building from source (developers only)

Requires **Go 1.24+** and native desktop development packages. On Linux Mint, the helper installs missing GLFW, Wayland, X11 and OpenGL **build dependencies** before starting the application. It may prompt once for `sudo`, and requires a working package manager and Internet access to download Go modules:

```bash
bash scripts/run-linux.sh
```

Manual alternative:

```bash
go mod tidy
go run ./cmd/badsharing-client
```

On Windows use Go, a MinGW-w64 C compiler and `go run ./cmd/badsharing-client`, or prefer the prebuilt executable.

## Architecture

```text
Fyne Desktop GUI
  ├── Send: choose a file → ephemeral local HTTPS signaling + invite
  ├── Receive: paste invite → select available LAN endpoint + pinned TLS
  └── Advanced: externally hosted HTTPS signaling and TURN
       ↓
 internal/client: file I/O, progress, cancellation, authenticated resume
       ├── badsharing/signaling: temporary LAN rendezvous / external server
       ├── internal/rtc: WebRTC ICE and reliable/lossy DataChannels
       └── badsharing/swarm: multi-source RLNC and verification
```

- The sender generates a 32-byte random file key, an independent signaling bearer token and a per-share, self-signed TLS certificate **in memory**.
- The recipient receives the credentials and SHA-256 TLS certificate fingerprint in the invitation code. Pinned verification rejects MITM certificates without disabling authentication.
- `badsharing` validates generation hashes before writing to `.part` and checks the final file hash before completion. Completed destination files are not overwritten.
- Multiple full seeders can share an authenticated manifest in **Advanced** mode with externally hosted signaling. An automatic LAN invitation currently has one sender and does not create a federated swarm on its own.
- Session credentials are not persisted. Clipboard contents may persist in the OS and should be cleared after sharing. STUN services may see network metadata.

## CI and distributables

GitHub Actions builds and tests Linux and Windows on native runners and publishes release artifacts for tags (`v*`):

- Linux executable (`badsharing-client-linux-amd64`) and **Linux Mint / Ubuntu `.deb`** with runtime package dependencies.
- Windows `.exe` portable binary.

The Linux CI installs developer-only GLFW X11 **and Wayland** headers so that newer GLFW versions compile; installed end-user packages do **not** need these headers.

To publish a new repository (requires authenticated GitHub CLI `gh`), use `bash scripts/publish.sh` or `./scripts/publish.ps1`. That action creates `ihatemyfcklife/badsharing-client` and pushes `main`; it cannot overwrite an existing repository.

## Tests

```bash
go mod tidy
go test ./internal/settings ./internal/client ./internal/rtc
go vet ./...
```

Tests include invitation round trips, invalid-code rejection, TLS fingerprint verification and a local HTTPS signaling round trip. Full cross-platform binaries must still be validated through a GitHub Actions run or on target machines.

## License

MIT — [ihatemyfcklife](https://github.com/ihatemyfcklife).
