"""
MUTE :: check_integrity.py
SHA-256 integrity verification for all project source files.

First run (or after intentional update): generate checksums.sha256
Subsequent runs: verify files match stored checksums.

If any file has been tampered with, MUTE refuses to start.
This prevents an attacker who has write access to the install directory
from silently backdooring crypto.py, tor_transport.py, or mute.py.

Usage (called automatically from mute.py):
    from check_integrity import verify_or_abort

Manual regeneration after legitimate update:
    python check_integrity.py --update
"""

import sys
import hashlib
import argparse
from pathlib import Path

BASE_DIR      = Path(__file__).parent
CHECKSUM_FILE = BASE_DIR / "checksums.sha256"

# Files that must pass integrity check before MUTE starts
GUARDED_FILES = [
    "mute.py",
    "crypto.py",
    "tor_transport.py",
    "check_integrity.py",
]


# ─── Core ──────────────────────────────────────────────────────────────────────

def sha256_file(path: Path) -> str:
    """Return hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_checksums() -> dict:
    """Compute SHA-256 for all guarded files. Returns {filename: hex_digest}."""
    result = {}
    for name in GUARDED_FILES:
        path = BASE_DIR / name
        if not path.exists():
            raise FileNotFoundError(f"Guarded file not found: {path}")
        result[name] = sha256_file(path)
    return result


def save_checksums(checksums: dict) -> None:
    """Write checksums to checksums.sha256 (one 'hash  filename' per line)."""
    lines = [f"{digest}  {name}\n" for name, digest in sorted(checksums.items())]
    CHECKSUM_FILE.write_text("".join(lines), encoding="utf-8")


def load_checksums() -> dict:
    """Parse checksums.sha256 → {filename: hex_digest}."""
    result = {}
    for line in CHECKSUM_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"Malformed checksum line: {line!r}")
        digest, name = parts
        result[name] = digest
    return result


# ─── Public API ────────────────────────────────────────────────────────────────

def verify_or_abort() -> None:
    """
    Called by mute.py at startup.

    - If checksums.sha256 doesn't exist yet: generate it and continue.
      (This happens on first run after fresh install.)
    - If it exists: verify every guarded file. Abort on mismatch.
    """
    if not CHECKSUM_FILE.exists():
        # First run — establish the baseline
        checksums = generate_checksums()
        save_checksums(checksums)
        _print_ok(f"Integrity baseline created ({len(checksums)} files).")
        return

    stored  = load_checksums()
    current = generate_checksums()
    failed  = []

    for name in GUARDED_FILES:
        if name not in stored:
            failed.append((name, "not in checksum file"))
            continue
        if current.get(name) != stored[name]:
            failed.append((name, "HASH MISMATCH"))

    if failed:
        _print_fail("INTEGRITY CHECK FAILED — refusing to start.")
        _print_fail("")
        _print_fail("Tampered files:")
        for name, reason in failed:
            _print_fail(f"  {name}: {reason}")
        _print_fail("")
        _print_fail("If this is a legitimate update, regenerate checksums:")
        _print_fail("  python check_integrity.py --update")
        sys.exit(1)

    _print_ok(f"Integrity OK ({len(GUARDED_FILES)} files verified).")


# ─── CLI ───────────────────────────────────────────────────────────────────────

def _print_ok(msg: str) -> None:
    print(f"  [\033[32mok\033[0m] {msg}")

def _print_fail(msg: str) -> None:
    print(f"  [\033[31m!!\033[0m] {msg}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MUTE integrity checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Regenerate checksums.sha256 (run after a legitimate update)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify files and print result (default action)",
    )
    args = parser.parse_args()

    if args.update:
        checksums = generate_checksums()
        save_checksums(checksums)
        print(f"\n  Checksums updated: {CHECKSUM_FILE}")
        for name, digest in sorted(checksums.items()):
            print(f"  {digest[:16]}...  {name}")
        print()
        return

    # Default: verify (also runs when called with no args)
    if not CHECKSUM_FILE.exists():
        checksums = generate_checksums()
        save_checksums(checksums)
        _print_ok(f"Baseline generated: {CHECKSUM_FILE}")
        return

    try:
        verify_or_abort()
    except SystemExit:
        raise
    except Exception as e:
        _print_fail(f"Integrity check error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()