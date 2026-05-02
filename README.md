# MUTE

Ephemeral, anonymous P2P chat over Tor.  
No registration. No logs. No servers. No metadata.

---

## Install

**Windows — one command:**

```powershell
irm https://raw.githubusercontent.com/mute44/mute/main/install.ps1 | iex
```

Restart your terminal after installation. Tor (~50MB) is downloaded automatically on first run.

> Requires Python 3.11+. If you don't have it: `winget install Python.Python.3.11`

---

## Usage

Both parties open a terminal and run:

```
mute
```

1. Enter a **pseudonym** for this session
2. Enter the **same passphrase** on the **same day**

One of you becomes the host, the other the client — this happens automatically.  
Connection takes 1–2 minutes while Tor establishes the circuit.

---

## Pseudonym

Your pseudonym is visible only to your peer for the duration of the session. It is never stored, never logged, and wiped when the session ends.

- Do not use your real name, existing username, or anything tied to your identity
- Do not reuse pseudonyms across sessions — consistency creates a pattern
- Good examples: `drifter`, `node-7`, `static`, `harbour` — anything throwaway

---

## Passphrase

The passphrase is how both parties find each other. It derives the daily `.onion` address and authenticates the handshake.

- Minimum 20 characters
- Use 6+ random unrelated words (diceware style): `carpet sunday orbit lamp heavy canal`
- Changes to a different `.onion` every day — same passphrase tomorrow = different address
- Never reuse a passphrase
- Never share it over any digital channel

---

## Privacy

| What | Status |
|---|---|
| Message content | ✅ XSalsa20-Poly1305 end-to-end encrypted |
| Message length | ✅ random padding to 1–4 KB blocks |
| Send timing | ✅ randomized 0–1.5s delay |
| Your IP address | ✅ hidden by Tor |
| Peer's IP address | ✅ hidden by Tor |
| Session keys | ✅ ephemeral, wiped on exit |
| Passphrase | ✅ wiped from RAM after key derivation |
| Pseudonym | ✅ session-only, never written to disk |

**Known limitations (Tor):**

| What | Limitation |
|---|---|
| That you use Tor | ⚠️ your ISP sees Tor traffic, not its content |
| That a .onion existed today | ⚠️ HSDir nodes see the descriptor, not who |
| Global traffic correlation | ⚠️ nation-state adversaries can correlate timing |

---

## Security

- ECDH handshake with HMAC protection prevents MITM attacks
- Session confirm tokens detect key mismatches before any message is sent
- Core dumps disabled on Linux/macOS to prevent key material leaking to disk
- No chat content is ever written to disk — only `./tor_data/` (Tor operational data)

---

## Uninstall

```powershell
Remove-Item -Recurse -Force $env:USERPROFILE\.mute
```

Then remove `%USERPROFILE%\.mute` from your user PATH in System Settings.

---

## Architecture

```
mute.py          — UI, startup flow, chat loop
crypto.py        — HKDF, X25519 ECDH, SecretBox, padding, memory wipe
tor_transport.py — Tor setup, hidden service, P2P handshake
install.ps1      — Windows installer
```

---

## Roadmap

- Linux support
- PFS key rotation every 10 minutes
- Multi-person rooms
- Hybrid relay fallback