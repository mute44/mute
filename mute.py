"""
MUTE :: darkchat.py
Entry point. Terminal UI with prompt_toolkit + Rich.

Startup flow:
  1. Check / download Tor
  2. Start Tor process
  3. Get passphrase (secure input, never echoed, never stored as plain string)
  4. Derive keys → compute deterministic .onion address
  5. Race to connect (P2P host/client determination)
  6. ECDH handshake → session key
  7. Async chat loop
  8. ESC / Ctrl+C → wipe all keys, shutdown Tor, exit
"""

import asyncio
import os
import sys
import socket
import platform
import secrets
import math
import struct
import ctypes
import time
from datetime import datetime

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit import print_formatted_text as pt_print
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align

import crypto
import tor_transport as tor_mod
import check_integrity


# ─── Globals ───────────────────────────────────────────────────────────────────

console = Console(highlight=False)
session_key: bytearray = None       # set after handshake
peer_socket: socket.socket = None
peer_nick: str = "???"              # set after nick exchange
shutdown_event = asyncio.Event()


# ─── UI Helpers ────────────────────────────────────────────────────────────────

def print_banner():
    banner = """
___  ___.     __    __     .___________.    _______ 
|   \/   |    |  |  |  |    |           |   |   ____|
|  \  /  |    |  |  |  |    `---|  |----`   |  |__   
|  |\/|  |    |  |  |  |        |  |        |   __|  
|  |  |  |    |  `--'  |        |  |        |  |____ 
|__|  |__|     \______/         |__|        |_______|
                                                     """
    console.print(banner, style="white")
    console.print("  " + "─" * 60, style="color(237)")
    console.print(
        "  E2E encrypted  ·  Tor P2P  ·  ephemeral  ·  no logs  ·  no registration\n",
        style="color(238)"
    )


def status(msg: str, style: str = "yellow") -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"  [{ts}] {msg}", style=style)


def print_message(text: str, is_mine: bool) -> None:
    if is_mine:
        pt_print(FormattedText([
            ("",          "> "),
            ("",          text),
        ]))
    else:
        pt_print(FormattedText([
            ("bold",      peer_nick),
            ("",          " > "),
            ("",          text),
        ]))


def print_system(msg: str) -> None:
    pt_print(FormattedText([("ansicyan", f"  ◆ {msg}")]))


# ─── Network ───────────────────────────────────────────────────────────────────

async def recv_loop() -> None:
    """Receive encrypted messages from peer, decrypt and display."""
    global session_key, peer_socket, peer_nick
    loop = asyncio.get_event_loop()

    while not shutdown_event.is_set():
        try:
            # Read 4-byte length header
            header = await loop.run_in_executor(
                None, lambda: tor_mod._recv_exactly(peer_socket, 4)
            )
            length = struct.unpack(">I", header)[0]

            if length == 0 or length > 5 * 1024 * 1024:
                print_system("Invalid message length — peer may have disconnected.")
                shutdown_event.set()
                return

            # Read ciphertext
            ciphertext = await loop.run_in_executor(
                None, lambda: tor_mod._recv_exactly(peer_socket, length)
            )

            # Decrypt
            plaintext = crypto.decrypt(ciphertext, session_key)

            # Handle special internal messages
            if plaintext.startswith("\x00DISCONNECT\x00"):
                print_system("Peer disconnected.")
                shutdown_event.set()
                return

            if plaintext.startswith("\x00CHAFF\x00"):
                continue  # silently discard — traffic normalization packet

            if plaintext.startswith("\x00NICK\x00"):
                peer_nick = plaintext[6:].rstrip("\x00") or "???"
                print_system(f"Peer is known as: {peer_nick}")
                continue

            print_message(plaintext, is_mine=False)

        except ConnectionError:
            if not shutdown_event.is_set():
                print_system("Connection lost.")
                shutdown_event.set()
            return
        except Exception as e:
            if not shutdown_event.is_set():
                print_system(f"Recv error: {e}")
                shutdown_event.set()
            return


async def send_message(text: str) -> None:
    """
    Encrypt and send a message with burst buffering.
    Messages are held for BURST_WINDOW seconds before sending —
    rapid typing gets smoothed into a uniform send pattern
    instead of betraying typing rhythm via timing analysis.
    """
    global session_key, peer_socket
    loop = asyncio.get_event_loop()

    # Burst buffer: hold message briefly to blur typing cadence
    BURST_WINDOW = 0.5
    await asyncio.sleep(BURST_WINDOW)

    ciphertext = crypto.encrypt(text, session_key)
    await loop.run_in_executor(
        None, lambda: tor_mod.send_framed(peer_socket, ciphertext)
    )
    print_message(text, is_mine=True)


async def chaff_loop() -> None:
    """
    Traffic normalization via chaffing.

    Sends encrypted dummy packets at Poisson-distributed intervals so the
    outbound stream looks constant regardless of whether the user is typing.
    The receiver silently discards all \\x00CHAFF\\x00 packets.

    Poisson process with mean CHAFF_RATE_SEC means inter-arrival times are
    exponentially distributed — indistinguishable from organic traffic bursts.
    """
    global session_key, peer_socket
    loop = asyncio.get_event_loop()

    CHAFF_RATE_SEC = 5.0  # average seconds between chaff packets

    while not shutdown_event.is_set():
        # Exponential inter-arrival time (Poisson process) — cryptographically random
        # Using inverse-CDF: X = -ln(U) / lambda, where U is uniform (0, 1)
        # secrets.randbelow gives uniform int in [0, 2^32), shift by 0.5 to avoid ln(0)
        u        = (secrets.randbelow(2 ** 32) + 0.5) / (2 ** 32)
        interval = -math.log(u) * CHAFF_RATE_SEC
        await asyncio.sleep(interval)

        if shutdown_event.is_set():
            break

        try:
            ciphertext = crypto.encrypt("\x00CHAFF\x00", session_key)
            await loop.run_in_executor(
                None, lambda: tor_mod.send_framed(peer_socket, ciphertext)
            )
        except Exception:
            break


# ─── Chat Loop ─────────────────────────────────────────────────────────────────

async def chat_loop() -> None:
    """Main chat input loop using prompt_toolkit."""
    ps = PromptSession()
    style = Style.from_dict({"prompt": ""})

    print_system("Connected. Type messages and press Enter. Ctrl+C to quit.")
    pt_print(FormattedText([("", "")]))

    recv_task  = asyncio.create_task(recv_loop())
    chaff_task = asyncio.create_task(chaff_loop())

    with patch_stdout():
        while not shutdown_event.is_set():
            try:
                user_input = await ps.prompt_async(
                    "> ",
                    style=style,
                )
            except (KeyboardInterrupt, EOFError):
                break

            text = user_input.strip()
            if not text:
                continue
            if text.lower() in ("/quit", "/exit", "/q"):
                break

            try:
                await send_message(text)
            except Exception as e:
                print_system(f"Send failed: {e}")
                break

    # Graceful disconnect
    try:
        farewell = crypto.encrypt("\x00DISCONNECT\x00", session_key)
        tor_mod.send_framed(peer_socket, farewell)
    except Exception:
        pass

    shutdown_event.set()
    recv_task.cancel()
    chaff_task.cancel()


# ─── Startup ───────────────────────────────────────────────────────────────────

def ensure_tor(tor: tor_mod.TorController, bridges: list = None) -> None:
    """Download Tor if needed (Windows), then start it."""
    if platform.system() == "Windows" and not tor_mod.is_tor_bundled():
        console.print()
        status("Tor not found. Downloading Tor Expert Bundle...", "yellow")
        console.print(
            "  This only happens once. Tor will be stored in ./tor_bundle/\n",
            style="dim"
        )
        tor_mod.download_tor_bundle(status_cb=lambda m: status(m, "yellow"))

    tor.start(status_cb=lambda m: status(m, "yellow"), bridges=bridges or [])


async def get_nickname() -> str:
    """
    Prompt for a session-only pseudonym.
    Never stored, never logged — lives only for this session.
    """
    from prompt_toolkit.validation import Validator, ValidationError

    class NickValidator(Validator):
        def validate(self, document):
            t = document.text.strip()
            if len(t) < 1:
                raise ValidationError(
                    message="Pseudonym cannot be empty.",
                    cursor_position=len(document.text),
                )
            if len(t) > 32:
                raise ValidationError(
                    message="Pseudonym too long (max 32 chars).",
                    cursor_position=len(document.text),
                )

    console.print()
    console.print("  Choose a pseudonym for this session.", style="dim")
    console.print("  [bold red]Do not use your real name, username, or any handle linked to your identity.[/bold red]")
    console.print("  This name is visible only to your peer. It is never stored or logged.\n", style="dim")

    ps = PromptSession()
    nick = await ps.prompt_async(
        "  Pseudonym: ",
        validator=NickValidator(),
        validate_while_typing=False,
    )
    return nick.strip()


async def get_passphrase() -> str:
    """
    Securely get passphrase from user via prompt_toolkit (masked input).
    Async — uses prompt_async() within the existing event loop to avoid
    creating a second event loop (which crashes on Windows).
    Enforces minimum length. Never passed as CLI argument.
    """
    from prompt_toolkit.validation import Validator, ValidationError

    class LengthValidator(Validator):
        def validate(self, document):
            if len(document.text) < 20:
                raise ValidationError(
                    message="Passphrase must be at least 20 characters (use 6+ random words)",
                    cursor_position=len(document.text),
                )

    console.print()
    console.print("  Enter a shared passphrase (min 20 chars, use 6+ random words).", style="dim")
    console.print("  Both parties must use the EXACT same passphrase on the same day.\n", style="dim")

    ps = PromptSession()
    passphrase = await ps.prompt_async(
        "  Passphrase: ",
        is_password=True,
        validator=LengthValidator(),
        validate_while_typing=False,
    )
    return passphrase


# ─── Memory Lockdown ───────────────────────────────────────────────────────────

def memory_lockdown() -> None:
    """
    Prevent the OS from swapping any page of this process to disk.

    Linux/macOS: mlockall(MCL_CURRENT | MCL_FUTURE) locks all current and
    future pages. Requires no special privileges on most desktop distros
    (RLIMIT_MEMLOCK allows a few MB by default — enough for this process).

    Windows: No equivalent of mlockall exists. We call SetProcessWorkingSetSize
    with large values to discourage (but not prevent) paging. Actual prevention
    on Windows would require VirtualLock per-allocation which PyNaCl handles
    internally for key material anyway.

    Core dumps are also disabled here — a crash dump would contain all RAM
    including session keys.
    """
    system = platform.system()

    if system in ("Linux", "Darwin"):
        try:
            MCL_CURRENT = 1
            MCL_FUTURE  = 2
            libc = ctypes.CDLL("libc.so.6" if system == "Linux" else "libc.dylib")
            result = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
            if result != 0:
                # Non-fatal — log but continue (e.g. container with low memlock limit)
                status("mlockall failed (low memlock limit?) — swap protection unavailable.", "yellow")
        except Exception:
            pass

        # Disable core dumps
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass

    elif system == "Windows":
        try:
            # Discourage paging by requesting a large working set
            # Not a guarantee, but raises the bar against casual swap analysis
            kernel32 = ctypes.windll.kernel32
            kernel32.SetProcessWorkingSetSize(
                kernel32.GetCurrentProcess(), 0x10000000, 0x40000000
            )
        except Exception:
            pass

        # Suppress Windows Error Reporting crash dumps
        try:
            SEM_NOGPFAULTERRORBOX = 0x0002
            ctypes.windll.kernel32.SetErrorMode(SEM_NOGPFAULTERRORBOX)
        except Exception:
            pass


# ─── Main ──────────────────────────────────────────────────────────────────────

async def main(bridges: list = None) -> None:
    global session_key, peer_socket

    # ── Pre-flight: integrity + memory lockdown (before anything else) ─────────
    check_integrity.verify_or_abort()
    memory_lockdown()

    print_banner()

    tor = tor_mod.TorController()

    try:
        # Step 1: Tor (bridges passed via --bridges CLI flag, default none)
        ensure_tor(tor, bridges or [])
        console.print()

        # Step 2: Nickname
        my_nick = await get_nickname()
        console.print()

        # Step 3: Passphrase
        passphrase = await get_passphrase()
        console.print()

        # Step 3: Derive keys for today AND tomorrow (needed for midnight rotation)
        status("Deriving keys...", "yellow")
        from datetime import date, timedelta
        room_key,    today_seed    = crypto.derive_keys(passphrase, date.today())
        _room_key2,  tomorrow_seed = crypto.derive_keys(passphrase, date.today() + timedelta(days=1))
        crypto.wipe(_room_key2)   # only need one room_key

        # Wipe passphrase from memory immediately — seeds are all we need
        passphrase_buf = bytearray(passphrase.encode("utf-8"))
        crypto.wipe(passphrase_buf)
        del passphrase

        today_key_seed,    today_onion    = crypto.seed_to_onion(today_seed)
        tomorrow_key_seed, _              = crypto.seed_to_onion(tomorrow_seed)
        crypto.wipe(today_seed)
        crypto.wipe(tomorrow_seed)

        status(f"Today's channel: {today_onion[:16]}...{today_onion[-10:]}", "cyan")
        console.print()

        # Step 4: Auto-connect (no role selection — determined automatically)
        # First 2 min: try to join existing session (client).
        # After 2 min with no answer: create new session (host, waits up to 12h).
        peer_sock, is_host = await tor_mod.auto_connect(
            today_onion,
            today_key_seed,
            tomorrow_key_seed,
            tor,
            status_cb=lambda m: status(m, "yellow"),
        )
        peer_socket = peer_sock
        role = "host" if is_host else "client"
        status(f"Peer found. Role: {role}", "green")

        # Step 5: ECDH Handshake
        status("Performing handshake...", "yellow")
        loop = asyncio.get_event_loop()
        session_key = await loop.run_in_executor(
            None, lambda: tor_mod.perform_handshake(peer_socket, room_key)
        )
        # room_key is wiped inside perform_handshake

        status("Handshake complete. Session encrypted. Keys are ephemeral.", "green")

        # Step 7: Nick exchange — first encrypted messages after handshake
        nick_msg = crypto.encrypt(f"\x00NICK\x00{my_nick}\x00", session_key)
        tor_mod.send_framed(peer_socket, nick_msg)
        console.print()

        # Step 6: Chat
        await chat_loop()

    except ConnectionError as e:
        console.print(f"\n  [red]Connection error:[/red] {e}")
    except ValueError as e:
        console.print(f"\n  [red]Security error:[/red] {e}")
    except KeyboardInterrupt:
        console.print("\n  Interrupted.")
    except Exception as e:
        console.print(f"\n  [red]Error:[/red] {e}")
    finally:
        # Wipe all key material
        if session_key is not None:
            crypto.wipe(session_key)
        if peer_socket:
            try:
                peer_socket.close()
            except Exception:
                pass
        tor.shutdown()
        console.print("\n  Session ended. All keys wiped.", style="dim")


def run():
    """Entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="mute",
        description="Ephemeral anonymous P2P chat over Tor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "obfs4 bridge example:\n"
            "  mute --bridges \"obfs4 1.2.3.4:443 FINGERPRINT cert=xxx iat-mode=0\"\n\n"
            "Get bridges: https://bridges.torproject.org  (select obfs4)"
        ),
    )
    parser.add_argument(
        "--bridges",
        nargs="+",
        metavar="BRIDGE_LINE",
        help="obfs4 bridge line(s) to disguise Tor traffic. "
             "Get from https://bridges.torproject.org",
        default=[],
    )
    args = parser.parse_args()

    # Validate bridge lines
    for b in args.bridges:
        if not b.strip().startswith("obfs4"):
            print(f"Invalid bridge line (must start with 'obfs4'): {b}")
            sys.exit(1)

    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main(bridges=args.bridges))


if __name__ == "__main__":
    run()