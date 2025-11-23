#!/usr/bin/env python3

"""
Generate PostgreSQL-compatible SCRAM-SHA-256 password verifiers.

This tool computes SCRAM-SHA-256 secrets in the exact format used by PostgreSQL
and PgBouncer. Output value can be safely placed into PostgreSQL's `pg_authid`
catalog (via `ALTER USER ... PASSWORD`) or into PgBouncer's `userlist.txt`.
"""

import hmac
import sys
from argparse import (
    ArgumentDefaultsHelpFormatter,
    ArgumentParser,
    ArgumentTypeError,
    Namespace,
)
from base64 import b64decode, b64encode
from contextlib import suppress
from hashlib import pbkdf2_hmac, sha256
from os import urandom

from . import __author__, __email__, __prog__, __status__, __version__

ITERATIONS = 4096


def scram_sha256(password: bytes, iterations: int, salt: bytes | None) -> str:
    """
    Compute a PostgreSQL-compatible SCRAM-SHA-256 verifier string.

    This function implements the SCRAM-SHA-256 secret derivation algorithm used
    internally by PostgreSQL, adhering to RFC 7677 and the PostgreSQL
    authentication subsystem.

    Args:
        password (bytes):
            UTF-8 encoded user password.

        iterations (int):
            PBKDF2 iteration count (default recommended by PostgreSQL is 4096).

        salt (bytes | None):
            16-byte random salt. If None, a new random salt is generated.

    Returns:
        str: A SCRAM-SHA-256 verifier formatted as:
        `SCRAM-SHA-256$<iterations>:<salt_b64>$<stored_key_b64>$<server_key_b64>`
    """

    if salt is None:
        salt = urandom(16)

    salted = pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)
    client_key = hmac.new(salted, b"Client Key", sha256).digest()
    stored_key = sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", sha256).digest()

    salt_b64 = b64encode(salt).decode(encoding="ascii")
    stored_b64 = b64encode(stored_key).decode(encoding="ascii")
    server_b64 = b64encode(server_key).decode(encoding="ascii")

    return f"SCRAM-SHA-256${iterations}:{salt_b64}${stored_b64}${server_b64}"


def verify_scram_sha256(password: str, verifier: str) -> bool:
    """
    Verify a plaintext password against a SCRAM-SHA-256 verifier string.

    Args:
        password (str):
            Plaintext password to verify. The password is encoded using UTF-8
            before PBKDF2 derivation, matching PostgreSQL behavior.

        verifier (str):
            A SCRAM-SHA-256 verifier string in PostgreSQL format. Only the
            `StoredKey` portion is used for verification.

    Returns:
        bool:
            True if the password matches the SCRAM verifier. False otherwise.

    Raises:
        ValueError:
            If the verifier is malformed or uses an unsupported scheme.
    """

    try:
        scheme, body = verifier.split("$", 1)

    except ValueError:
        raise ValueError("Invalid SCRAM verifier format.")

    if scheme != "SCRAM-SHA-256":
        raise ValueError("Unsupported SCRAM scheme (expected SCRAM-SHA-256).")

    try:
        iter_part, stored_b64, _server_b64 = body.split("$")
        iterations_str, salt_b64 = iter_part.split(":")

    except ValueError:
        raise ValueError("Malformed SCRAM verifier structure.")

    iterations = int(iterations_str)
    salt = b64decode(salt_b64)
    stored_ref = b64decode(stored_b64)

    if len(stored_ref) != 32:
        msg = "StoredKey in SCRAM verifier must be 32 bytes"
        raise ValueError(msg)

    pwd_bytes = password.encode("utf-8")
    salted = pbkdf2_hmac("sha256", pwd_bytes, salt, iterations, dklen=32)
    client_key = hmac.new(salted, b"Client Key", sha256).digest()
    stored_key = sha256(client_key).digest()

    return hmac.compare_digest(stored_key, stored_ref)


def parse_iterations(i: int) -> int:
    """Parse PBKDF2 iterations count value."""

    if not isinstance(i, int) or i < 1:  # pyright: ignore[reportUnnecessaryIsInstance]
        msg = "PBKDF2 iterations count must be positive integer"
        raise ArgumentTypeError(msg)

    if i < ITERATIONS:
        msg = f"PBKDF2 iterations count below {ITERATIONS} is discouraged"
        raise ArgumentTypeError(msg)

    return i


def parse_salt(s: str) -> bytes:
    """
    Parse salt string as Base64 or hex-encoded bytes.

    The SCRAM specification mandates a 16-byte salt. This function accepts input
    as either BASE64 (RFC4648) or raw hexadecimal.

    Args:
        s (str):
            Salt string provided on CLI.

    Returns:
        bytes: Decoded salt value.

    Raises:
        ArgumentTypeError: If input is neither valid BASE64 nor valid hex.
    """

    with suppress():
        decoded = b64decode(s, validate=True)
        if len(decoded) != 16:
            msg = "Salt must decode to exactly 16 bytes."
            raise ArgumentTypeError(msg)

        return decoded

    with suppress():
        decoded = bytes.fromhex(s)

        if len(decoded) != 16:
            msg = "HEX salt must be exactly 32 hex digits (16 bytes)."
            raise ArgumentTypeError(msg)

        return decoded

    raise ArgumentTypeError("Salt must be either BASE64 or HEX encoded.")


def _parse_cli_args() -> Namespace:
    """Parse and validate command-line arguments."""

    cli_parser = ArgumentParser(
        prog=__prog__,
        description=__doc__,
        epilog=f"Written by {__author__} <{__email__}>.",
        formatter_class=lambda prog: ArgumentDefaultsHelpFormatter(
            prog=prog,
            max_help_position=120,
        ),
    )

    cli_parser.add_argument(
        "--version",
        action="version",
        version=f"{__prog__} v{__version__} ({__status__})",
    )

    cli_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="exit quietly",
    )

    cli_parser.add_argument(
        "password",
        help="specify plaintext password to derive a SCRAM-SHA-256 verifier from. "
        "The password will be treated as UTF-8 encoded when performing PBKDF2.",
    )

    cli_parser.add_argument(
        "verifier",
        nargs="?",
        help="specify existing SCRAM verifier. When provided, verification is performed.",
    )

    cli_parser.add_argument(
        "-i",
        "--iterations",
        type=int,
        default=ITERATIONS,
        help=f"specify PBKDF2 iteration count. PostgreSQL recommends {ITERATIONS}"
        "Increasing this value improves brute-force resistance but slows down "
        "authentication.",
    )

    cli_parser.add_argument(
        "-s",
        "--salt",
        type=parse_salt,
        help="specify 16-byte salt encoded in BASE64 or HEX. "
        "If omitted, a new random 16-byte salt will be generated.",
    )

    return cli_parser.parse_args()


def main() -> None:
    """Main CLI execution entrypoint."""

    args = _parse_cli_args()

    if args.verifier is not None:
        if not verify_scram_sha256(args.password, args.verifier.strip()):
            if not args.quiet:
                print("failed", file=sys.stderr)

            sys.exit(1)

        if not args.quiet:
            print("ok")

        sys.exit(0)

    print(
        scram_sha256(
            password=args.password.encode("utf-8"),
            iterations=args.iterations,
            salt=args.salt,
        )
    )


if __name__ == "__main__":
    with suppress(KeyboardInterrupt):
        main()
