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
import random
import struct
import time
from datetime import datetime

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.align import Align

import crypto
import tor_transport as tor_mod


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
    ts = datetime.now().strftime("%H:%M")
    if is_mine:
        line = Text()
        line.append(f"[{ts}] ", style="dim")
        line.append("You", style="bold green")
        line.append(f": {text}", style="white")
    else:
        line = Text()
        line.append(f"[{ts}] ", style="dim")
        line.append(peer_nick, style="bold red")
        line.append(f": {text}", style="white")
    console.print(line)


def print_system(msg: str) -> None:
    console.print(f"  ◆ {msg}", style="dim cyan")


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
    """Encrypt and send a message to peer."""
    global session_key, peer_socket
    loop = asyncio.get_event_loop()

    ciphertext = crypto.encrypt(text, session_key)

    # Random send delay: 0 - 1500ms (hides message timing patterns)
    delay = random.uniform(0, 1.5)
    await asyncio.sleep(delay)

    await loop.run_in_executor(
        None, lambda: tor_mod.send_framed(peer_socket, ciphertext)
    )


# ─── Chat Loop ─────────────────────────────────────────────────────────────────

async def chat_loop() -> None:
    """Main chat input loop using prompt_toolkit."""
    ps = PromptSession()
    style = Style.from_dict({"prompt": "ansicyan bold"})

    print_system("Connected. Type messages and press Enter. Ctrl+C to quit.")
    console.print()

    recv_task = asyncio.create_task(recv_loop())

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

            print_message(text, is_mine=True)

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


# ─── Startup ───────────────────────────────────────────────────────────────────

def ensure_tor(tor: tor_mod.TorController) -> None:
    """Download Tor if needed (Windows), then start it."""
    if platform.system() == "Windows" and not tor_mod.is_tor_bundled():
        console.print()
        status("Tor not found. Downloading Tor Expert Bundle...", "yellow")
        console.print(
            "  This only happens once. Tor will be stored in ./tor_bundle/\n",
            style="dim"
        )
        tor_mod.download_tor_bundle(status_cb=lambda m: status(m, "yellow"))

    tor.start(status_cb=lambda m: status(m, "yellow"))


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


# ─── Main ──────────────────────────────────────────────────────────────────────

async def main() -> None:
    global session_key, peer_socket

    # Disable core dumps on Linux/macOS
    if platform.system() != "Windows":
        try:
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass

    print_banner()

    tor = tor_mod.TorController()

    try:
        # Step 1: Tor
        ensure_tor(tor)
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
    # Ensure passphrase is not accidentally passed as argument
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        print("Usage: python darkchat.py")
        print("Do not pass passphrase as argument.")
        sys.exit(1)

    # ProactorEventLoop (Windows default in Python 3.8+) is incompatible with
    # prompt_toolkit. Switch to SelectorEventLoop before starting the loop.
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(main())


if __name__ == "__main__":
    run()