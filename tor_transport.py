"""
MUTE :: tor_transport.py
Tor management and P2P connection.

- Auto-downloads Tor Expert Bundle on Windows if not present
- Launches Tor with privacy-hardened config
- Optional obfs4 pluggable transport (hides Tor traffic from ISP)
- Creates deterministic ephemeral v3 hidden service
- Race mechanism: both peers try host + client simultaneously
  → first successful connection determines roles
"""

import asyncio
import os
import sys
import socket
import struct
import secrets
import tarfile
import tempfile
import platform
import urllib.request
import urllib.error
from pathlib import Path
from typing import Tuple, Callable, Optional

import socks          # PySocks
import stem.process
import stem.control

import crypto


# ─── Paths & Ports ─────────────────────────────────────────────────────────────

BUNDLE_DIR   = Path(__file__).parent / "tor_bundle"
DATA_DIR     = Path(__file__).parent / "tor_data"
TOR_EXE      = BUNDLE_DIR / "tor" / "tor.exe"

# obfs4proxy is shipped inside the Tor Expert Bundle on Windows
OBFS4_EXE    = BUNDLE_DIR / "tor" / "pluggable_transports" / "obfs4proxy.exe"

TOR_SOCKS_PORT   = 19050
TOR_CONTROL_PORT = 19051
HS_LOCAL_PORT    = 19052


# ─── Tor Download ──────────────────────────────────────────────────────────────

# Tor Expert Bundle for Windows x86_64
# Update TOR_VERSION if this version is no longer available
# Downloads from: https://archive.torproject.org/tor-package-archive/torbrowser/
TOR_VERSION = "15.0.9"
TOR_BUNDLE_URL = (
    f"https://archive.torproject.org/tor-package-archive/torbrowser/{TOR_VERSION}/"
    f"tor-expert-bundle-windows-x86_64-{TOR_VERSION}.tar.gz"
)


def is_tor_bundled() -> bool:
    """Check if Tor bundle already downloaded."""
    return TOR_EXE.exists()


def is_obfs4_available() -> bool:
    """Check if obfs4proxy is available (bundled on Windows, system PATH on Linux)."""
    if platform.system() == "Windows":
        return OBFS4_EXE.exists()
    import shutil
    return shutil.which("obfs4proxy") is not None


def get_obfs4_binary() -> str:
    """Return absolute path to obfs4proxy binary."""
    if platform.system() == "Windows":
        if not OBFS4_EXE.exists():
            raise RuntimeError(
                f"obfs4proxy.exe not found in Tor bundle.\n"
                f"Expected: {OBFS4_EXE}\n"
                "Re-download the Tor Expert Bundle to get it."
            )
        return str(OBFS4_EXE)
    import shutil
    binary = shutil.which("obfs4proxy")
    if not binary:
        raise RuntimeError("obfs4proxy not found. Install: sudo apt install obfs4proxy")
    return binary


def get_tor_binary() -> str:
    """Return path to tor binary (bundled on Windows, system on Linux)."""
    if platform.system() == "Windows":
        return str(TOR_EXE)
    # Linux/macOS: assume system tor
    import shutil
    tor = shutil.which("tor")
    if not tor:
        raise RuntimeError("tor not found. Install with: sudo apt install tor")
    return tor


def download_tor_bundle(status_cb: Optional[Callable[[str], None]] = None) -> None:
    """
    Download and extract Tor Expert Bundle for Windows.
    status_cb: called with progress strings during download.
    """
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.gettempdir()) / "darkchat_tor_bundle.tar.gz"

    if status_cb:
        status_cb(f"Downloading Tor {TOR_VERSION}...")

    last_pct = [-1]

    def reporthook(count, block_size, total_size):
        if total_size > 0:
            pct = min(100, int(count * block_size * 100 / total_size))
            if pct != last_pct[0] and pct % 10 == 0:
                last_pct[0] = pct
                if status_cb:
                    status_cb(f"Downloading Tor... {pct}%")

    try:
        urllib.request.urlretrieve(TOR_BUNDLE_URL, tmp, reporthook)
    except urllib.error.URLError as e:
        raise RuntimeError(
            f"Failed to download Tor: {e}\n"
            f"Manually download tor-expert-bundle-windows-x86_64-{TOR_VERSION}.tar.gz\n"
            f"from https://dist.torproject.org/torbrowser/{TOR_VERSION}/\n"
            f"and extract it to: {BUNDLE_DIR}"
        )

    if status_cb:
        status_cb("Extracting Tor bundle...")

    with tarfile.open(tmp, "r:gz") as tf:
        tf.extractall(BUNDLE_DIR)

    tmp.unlink(missing_ok=True)

    if not TOR_EXE.exists():
        # Try to find tor.exe anywhere in bundle
        found = list(BUNDLE_DIR.rglob("tor.exe"))
        if not found:
            raise RuntimeError(
                f"tor.exe not found after extraction in {BUNDLE_DIR}\n"
                "Bundle structure may have changed. Check manually."
            )
        # Move to expected location
        TOR_EXE.parent.mkdir(parents=True, exist_ok=True)
        found[0].rename(TOR_EXE)

    if status_cb:
        status_cb("Tor ready.")


# ─── Tor Process Controller ────────────────────────────────────────────────────

class TorController:
    def __init__(self):
        self._process    = None
        self._controller = None
        self._hs_id      = None   # service_id (without .onion)

    def start(
        self,
        status_cb: Optional[Callable[[str], None]] = None,
        bridges:   Optional[list] = None,
    ) -> None:
        """
        Launch Tor process and authenticate controller. Blocks until ready.

        bridges: optional list of obfs4 bridge lines, e.g.:
            ["obfs4 1.2.3.4:1234 FINGERPRINT cert=xxx iat-mode=0"]
        If provided and obfs4proxy is available, Tor will use pluggable
        transports — ISP sees random-looking traffic instead of Tor.
        """
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        if status_cb:
            status_cb("Starting Tor...")

        config = {
            "SocksPort":       f"{TOR_SOCKS_PORT} IsolateClientAddr IsolateClientProtocol",
            "ControlPort":     str(TOR_CONTROL_PORT),
            "DataDirectory":   str(DATA_DIR),
            "Log":             ["NOTICE stdout", "ERR stderr"],
            # Privacy hardening
            "ConnectionPadding":      "1",
            "EnforceDistinctSubnets": "1",
            "ExcludeExitNodes":       "{??}",
            "StrictNodes":            "0",
            # NOTE: EntryNodes removed — even as a soft preference (StrictNodes 0)
            # it causes significantly longer bootstrap times and hangs on Windows
            # where stem has no timeout mechanism. Guard diversity handled by Tor itself.
        }

        # ── obfs4 pluggable transport (activated via --bridges CLI flag) ───────
        if bridges:
            if not is_obfs4_available():
                if status_cb:
                    status_cb(
                        "obfs4proxy not found in Tor bundle — starting without bridges."
                    )
            else:
                obfs4_bin = get_obfs4_binary()
                config["UseBridges"] = "1"
                config["ClientTransportPlugin"] = f"obfs4 exec {obfs4_bin}"
                config["Bridge"] = bridges
                if status_cb:
                    status_cb(f"obfs4 enabled ({len(bridges)} bridge(s)). Traffic is camouflaged.")

        # timeout uses UNIX signals — must be None on Windows
        tor_timeout = None if platform.system() == "Windows" else 120

        self._process = stem.process.launch_tor_with_config(
            config=config,
            tor_cmd=get_tor_binary(),
            timeout=tor_timeout,
            take_ownership=True,
        )

        self._controller = stem.control.Controller.from_port(port=TOR_CONTROL_PORT)
        self._controller.authenticate()

        if status_cb:
            status_cb("Tor connected.")

    def create_hidden_service(self, key_seed: bytes) -> str:
        """
        Create ephemeral v3 hidden service with deterministic key.
        Returns the .onion hostname.
        Blocks until descriptor is published to HSDir (~30-90s).
        """
        key_b64 = crypto.key_seed_to_expanded(key_seed)

        result = self._controller.create_ephemeral_hidden_service(
            {HS_LOCAL_PORT: HS_LOCAL_PORT},
            key_type="ED25519-V3",
            key_content=key_b64,
            await_publication=True,
        )

        self._hs_id = result.service_id
        return self._hs_id + ".onion"

    def remove_hidden_service(self) -> None:
        if self._hs_id and self._controller:
            try:
                self._controller.remove_ephemeral_hidden_service(self._hs_id)
            except Exception:
                pass
            self._hs_id = None

    def shutdown(self) -> None:
        self.remove_hidden_service()
        if self._controller:
            try:
                self._controller.close()
            except Exception:
                pass
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                pass


# ─── Socket Helpers ────────────────────────────────────────────────────────────

def _tor_socket() -> socks.socksocket:
    """Create a socket pre-configured to use Tor SOCKS5."""
    s = socks.socksocket()
    s.set_proxy(socks.SOCKS5, "127.0.0.1", TOR_SOCKS_PORT)
    return s


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf


def send_framed(sock: socket.socket, data: bytes) -> None:
    """Send length-prefixed message."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_framed(sock: socket.socket) -> bytes:
    """Receive length-prefixed message."""
    header = _recv_exactly(sock, 4)
    length = struct.unpack(">I", header)[0]
    if length > 10 * 1024 * 1024:   # 10MB sanity limit
        raise ValueError(f"Message too large: {length}")
    return _recv_exactly(sock, length)


# ─── P2P Auto-Connect ──────────────────────────────────────────────────────────
#
# No manual role selection. Logic:
#   Phase 1 — CLIENT probe (2 min): try to connect to today's .onion every 10s.
#             If successful → we are the CLIENT.
#   Phase 2 — HOST (up to 12h): nobody answered → we are the HOST.
#             Publish today's hidden service and wait.
#             At midnight rotate automatically to tomorrow's HS so the
#             daily key rotation is preserved without dropping the session.

HOST_MAX_WAIT  = 12 * 3600   # seconds host waits for a peer
CLIENT_PROBE   = 120         # seconds client tries before becoming host
CLIENT_INTERVAL = 10         # seconds between client connection attempts


async def auto_connect(
    today_onion:    str,
    today_seed:     bytes,
    tomorrow_seed:  bytes,
    tor:            TorController,
    status_cb:      Optional[Callable[[str], None]] = None,
) -> Tuple[socket.socket, bool]:
    """
    Automatically determine role — no user input needed.

    Returns (socket, is_host).
    today_onion / today_seed   — derived from passphrase + today's date
    tomorrow_seed              — derived from passphrase + tomorrow's date
                                 (used for midnight key rotation while host is waiting)
    """
    loop = asyncio.get_event_loop()

    # ── Phase 1: try to be CLIENT ─────────────────────────────────────────────
    if status_cb:
        status_cb("Checking if a session already exists (up to 2 min)...")

    probe_start = loop.time()
    attempt = 0

    while loop.time() - probe_start < CLIENT_PROBE:
        attempt += 1
        remaining = int(CLIENT_PROBE - (loop.time() - probe_start))
        if status_cb:
            status_cb(f"Looking for existing session... attempt {attempt}  ({remaining}s left)")
        try:
            sock = _tor_socket()
            sock.settimeout(15)
            await loop.run_in_executor(
                None, lambda: sock.connect((today_onion, HS_LOCAL_PORT))
            )
            sock.settimeout(None)
            if status_cb:
                status_cb("Session found — joining as client.")
            return sock, False   # CLIENT
        except asyncio.CancelledError:
            raise
        except Exception:
            await asyncio.sleep(CLIENT_INTERVAL)

    # ── Phase 2: become HOST ──────────────────────────────────────────────────
    if status_cb:
        status_cb("No existing session found — creating new session (host). Waiting up to 12 h...")

    sock = await _host_wait(today_seed, tomorrow_seed, tor, loop, status_cb)
    return sock, True   # HOST


async def _host_wait(
    today_seed:    bytes,
    tomorrow_seed: bytes,
    tor:           TorController,
    loop:          asyncio.AbstractEventLoop,
    status_cb:     Optional[Callable[[str], None]] = None,
) -> socket.socket:
    """
    Internal: publish hidden service and accept one real peer connection.
    Rotates HS key at midnight to preserve daily key rotation.
    """
    from datetime import date, timedelta

    current_seed = today_seed
    server = None

    def _publish(seed: bytes) -> None:
        tor.remove_hidden_service()
        tor.create_hidden_service(seed)

    if status_cb:
        status_cb("Publishing hidden service (30-90s)...")
    await loop.run_in_executor(None, lambda: _publish(current_seed))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", HS_LOCAL_PORT))
    server.listen(5)
    server.settimeout(30)   # short so we can print status & check midnight

    start      = loop.time()
    probes     = 0
    today_date = date.today()

    try:
        while True:
            elapsed = loop.time() - start
            if elapsed > HOST_MAX_WAIT:
                raise ConnectionError("Host timeout: no peer connected within 12 hours.")

            # ── Midnight rotation ─────────────────────────────────────────────
            now_date = date.today()
            if now_date != today_date:
                # Day changed — rotate to tomorrow's seed
                if status_cb:
                    status_cb("Midnight: rotating hidden service key...")
                current_seed = tomorrow_seed
                await loop.run_in_executor(None, lambda: _publish(current_seed))
                today_date = now_date
                if status_cb:
                    status_cb("Key rotated. Still waiting for peer...")

            # ── Accept connection ─────────────────────────────────────────────
            try:
                conn, _ = await loop.run_in_executor(None, server.accept)
            except OSError:
                h = int(elapsed) // 3600
                m = (int(elapsed) % 3600) // 60
                s = int(elapsed) % 60
                probe_info = f"  ({probes} probe(s) ignored)" if probes else ""
                if status_cb:
                    status_cb(f"Waiting for peer...  {h:02d}:{m:02d}:{s:02d}{probe_info}")
                continue

            # ── Filter Tor probes (connect but send nothing) ──────────────────
            conn.settimeout(10)
            try:
                peek = conn.recv(64, socket.MSG_PEEK)
                if len(peek) < 64:
                    conn.close()
                    probes += 1
                    continue
            except OSError:
                conn.close()
                probes += 1
                continue

            conn.settimeout(None)
            server.close()
            server = None
            if status_cb:
                status_cb("Peer connected!")
            return conn

    finally:
        if server:
            try:
                server.close()
            except Exception:
                pass
        tor.remove_hidden_service()


# ─── Handshake ─────────────────────────────────────────────────────────────────

def perform_handshake(
    sock: socket.socket,
    room_key: bytearray,
) -> bytearray:
    """
    Symmetric ECDH handshake. Both sides run the same code.

    1. Generate ephemeral X25519 keypair
    2. Send pubkey + HMAC(pubkey, room_key)
    3. Receive their pubkey + HMAC, verify HMAC
    4. Compute session_key = HKDF(ECDH(priv, their_pub), room_key)
    5. Exchange confirm tokens to verify matching session keys
    6. Wipe room_key and ephemeral private key

    Returns session_key (bytearray).
    Raises ValueError on MITM detection or key mismatch.
    """
    our_priv, our_pub = crypto.generate_keypair()
    our_mac = crypto.sign_pubkey(our_pub, room_key)

    # Step 1: send our pubkey + mac (64 bytes total)
    sock.sendall(our_pub + our_mac)

    # Step 2: receive their pubkey + mac
    their_data = _recv_exactly(sock, 64)
    their_pub  = their_data[:32]
    their_mac  = their_data[32:]

    # Step 3: verify HMAC — detects MITM key substitution
    if not crypto.verify_pubkey(their_pub, their_mac, room_key):
        raise ValueError("Handshake failed: HMAC mismatch. Possible MITM attack.")

    # Step 4: derive session key
    session_key = crypto.derive_session_key(our_priv, their_pub, room_key)

    # Step 5: mutual confirmation — proves both derived the same session key
    our_confirm   = crypto.confirm_token(session_key)
    sock.sendall(our_confirm)
    their_confirm = _recv_exactly(sock, 32)

    if not __import__("hmac").compare_digest(our_confirm, their_confirm):
        raise ValueError("Handshake failed: session key mismatch.")

    # Step 6: wipe sensitive material
    crypto.wipe(room_key)
    del our_priv   # PyNaCl PrivateKey — encourage GC

    return session_key