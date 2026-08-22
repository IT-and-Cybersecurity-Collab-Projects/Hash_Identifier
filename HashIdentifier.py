import argparse
import sys
from dataclasses import dataclass
from typing import Literal
from rich.console import console
from rich.table import table

# A string can only be one of these three values:
confidence = literal["low", "medium", "high"]

#

@dataclass(frozen = true, slots = true)
class Hashcandidate:

    algorithm: str
    confidence: confidence
    reason: str

Prefix_Rules: list[list[str, str]] = [

    # Argon2 Family
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard"),
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant"),
    ("$argon2d$", "Argon2d", "PHC string, GPU-resistant variant"),

    # Bcrypt Family
    ("$2y$", "bcrypt", "bcrypt PHC string, 2y variant (PHP)"),
    ("$2b$", "bcrypt", "bcrypt PHC string, 2b variant (current)"),
    ("$2a$", "bcrypt", "bcrypt PHC string, 2a variant (legacy)"),
    ("$2x$", "bcrypt", "bcrypt PHC string, 2x variant (legacy fix)"),

    # SHA-512 crypt
    ("$6$", "SHA-512 crypt", "Unix crypt(3) using SHA-512 (default on Linux)"),
    ("$5$", "SHA-256 crypt", "Unix crypt(3) using SHA-256"),
    ("$1$", "MD5 crypt", "Unix crypt(3) using MD5 (legacy, weak)"),

    #Apache MD5-crypt
    ("$apr1$", "Apache MD5-crypt", "Apache htpasswd MD5 variant (`htpasswd -m`)"),

    # yescrypt
    ("$y$", "yescrypt", "PHC string, modern Linux crypt successor"),

    #phpass
    ("$P$", "phpass", "WordPress / phpBB password hash"),
    ("$H$", "phpass", "phpBB-style phpass variant"),

    # Drupal 7
    ("$S$", "Drupal 7 (SHA-512)", "Drupal 7 PHC-style hash"),

    # scrypt
    ("$7$", "scrypt", "scrypt PHC-style hash"),

    # Django
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256", "Django default password hash"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1", "Django legacy password hash"),
    ("bcrypt_sha256$", "Django bcrypt-SHA256", "Django bcrypt wrapper"),
    ("argon2$", "Django Argon2", "Django Argon2 wrapper"),

    # LDAP
    ("{SSHA}", "LDAP SSHA", "LDAP salted SHA-1 (base64 payload)"),
    ("{SHA}", "LDAP SHA", "LDAP SHA-1 (base64 payload)"),
    ("{SMD5}", "LDAP SMD5", "LDAP salted MD5 (base64 payload)"),
    ("{MD5}", "LDAP MD5", "LDAP MD5 (base64 payload)"),
    ("{CRYPT}", "LDAP CRYPT", "LDAP wrapping a crypt(3) hash"),
]

HEX_CHARSET: frozenset[str] = frozenset("0123456789abcdefABCDEF")

_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

HEX_LENGTH_RULES: dict[int, list[str]] = {

       16: ["MySQL323", "CRC-64"],
    # 32 hex chars = 16 bytes = 128 bits
    32: ["MD5", "NTLM", "MD4", "RIPEMD-128"],
    # 40 hex chars = 20 bytes = 160 bits
    40: ["SHA-1", "RIPEMD-160"],
    # 48 hex chars = 24 bytes = 192 bits
    48: ["Tiger-192"],
    # 56 hex chars = 28 bytes = 224 bits
    56: ["SHA-224", "SHA3-224"],
    # 64 hex chars = 32 bytes = 256 bits
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256", "RIPEMD-256"],
    # 80 hex chars = 40 bytes = 320 bits (uncommon)
    80: ["RIPEMD-320"],
    # 96 hex chars = 48 bytes = 384 bits
    96: ["SHA-384", "SHA3-384"],
    # 128 hex chars = 64 bytes = 512 bits
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
}



# =============================================================================
# Helpers
# =============================================================================


def _is_hex(text: str) -> bool:
    """
    Return True iff every character in text is a hex digit and text is non-empty

    A hash like "5f4dcc..." passes; an empty string or anything with
    a non-hex character fails. We use the HEX_CHARSET frozenset for
    membership tests because `c in frozenset` is O(1) lookup, faster
    than `c in "0123456789abcdef..."` for big inputs
    """
    return bool(text) and all(c in HEX_CHARSET for c in text)



_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1


def _is_mysql5(text: str) -> bool:
    """
    Return True for MySQL5 password format: `*` then 40 UPPERCASE hex chars

    MySQL5 stores SHA-1(SHA-1(password)) printed in uppercase hex with
    a leading `*`. Real MySQL5 output uses the `%02X` C format
    specifier, which is uppercase-only. We reject lowercase here so
    we do not return a confident HIGH-confidence "MySQL5" verdict on
    a hand-edited or mistyped string — better to fall through to
    no-match than to lie with conviction

    NOTE: we cannot just call `body.isupper()` to enforce the case.
    Python's `str.isupper` returns False when a string contains NO
    cased characters at all, which would wrongly reject an all-digit
    hex body like "0123456789ABCDEF..." with no letters in it.
    Checking membership in an uppercase-only charset is the test
    that actually matches the spec
    """
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1 :]
    return all(c in _HEX_UPPER_CHARSET for c in body)



_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13


def _is_descrypt(text: str) -> bool:
    """
    Return True for traditional 13-char DES crypt (legacy /etc/passwd)

    No prefix at all — just 13 characters drawn from `./0-9A-Za-z`.
    Old enough that you mostly see it in retro CTFs now, but real
    enough that hashcat still ships a mode (1500) for cracking it.
    We report MEDIUM (not HIGH) confidence on a match because a 13-char
    string in that charset CAN be other things (some session IDs,
    encoded values), and a beginner deserves an honest confidence
    level rather than a false-positive at HIGH
    """
    return (
        len(text) == _DESCRYPT_TOTAL_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
    )




def identify(raw_input: str) -> list[HashCandidate]:
    """
    Return ranked candidates for what algorithm produced `raw_input`

    Algorithm
    ---------
    Whitespace is trimmed from `raw_input` first. Then the six
    matching steps below run in order — each step's labeled comment
    (`# ----- Step N: ... -----`) inside the function body matches
    the number in this list, so the docstring and the code stay in
    lockstep:

    1. Walk the PREFIX_RULES table. The first prefix that matches
       wins (HIGH confidence). Each table row is unique enough that
       at most one entry can match a given input
    2. Check special non-PHC formats in order — NetNTLMv1/v2
       challenge-response records, MySQL5 (`*<40 hex>`), and the
       legacy 13-char DES crypt. Each has a distinctive shape that
       takes precedence over generic length-based matching
    3. If the input is pure hex, look up its length in
       HEX_LENGTH_RULES and report each candidate. The first entry
       at each length gets MEDIUM confidence (the modern default);
       the rest LOW
    4. If the input has a `$<algo>$...` shape but no PREFIX_RULES
       row matched, fall back to a generic PHC string match — LOW
       confidence because we only matched the shape, not a specific
       rule
    5. If the input looks like a JWT (`eyJ...`) or a base64 blob
       (contains `+`, `/`, or `=`), say so with LOW confidence —
       these are not hashes, but a beginner deserves to know what
       they pasted instead of a silent no-match
    6. If nothing matched at all, return an empty list

    Parameters
    ----------
    raw_input
        The hash string to identify. Whitespace is trimmed before
        analysis but the rest is treated literally — case matters
        because some algorithms use uppercase output

    Returns
    -------
    list[HashCandidate]
        Possibly empty. When non-empty, candidates are ordered by
        confidence (high before medium before low) and within each
        confidence band by likelihood
    """
    # Trim whitespace — copy-pasted hashes often arrive with trailing
    # newlines or leading spaces. We do not modify case because some
    # formats are case-sensitive
    text = raw_input.strip()

    if not text:
        return []


    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                HashCandidate(
                    algorithm = algorithm,
                    confidence = "high",
                    reason = f"prefix `{prefix}` — {note}",
                )
            ]


    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        # NetNTLMv2 layout:
        #   user :: domain : challenge : hmac(32 hex) : blob(>=32 hex)
        # The hmac at parts[4] is exactly 32 hex chars — that single
        # property is enough to disambiguate v2 from v1
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return [
                HashCandidate(
                    algorithm = "NetNTLMv2",
                    confidence = "high",
                    reason =
                    "user::domain:challenge:hmac(32 hex):blob shape",
                )
            ]
        # NetNTLMv1 layout:
        #   user :: domain : lmhash(48 hex) : nthash(48 hex) : challenge
        # The lmhash at parts[3] is exactly 48 hex chars
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return [
                HashCandidate(
                    algorithm = "NetNTLMv1",
                    confidence = "high",
                    reason =
                    "user::domain:lm(48 hex):nt(48 hex):challenge shape",
                )
            ]

    # MySQL5 — literal `*` + 40 uppercase hex chars
    if _is_mysql5(text):
        return [
            HashCandidate(
                algorithm = "MySQL5",
                confidence = "high",
                reason =
                "starts with `*` followed by 40 uppercase hex chars",
            )
        ]

    # Traditional 13-char DES crypt — legacy /etc/passwd format
    # with no prefix at all. We report MEDIUM (not HIGH) because the
    # 13-char `./0-9A-Za-z` shape isn't fully unique to DES crypt
    if _is_descrypt(text):
        return [
            HashCandidate(
                algorithm = "DES crypt",
                confidence = "medium",
                reason =
                "13 chars in `./0-9A-Za-z` — legacy /etc/passwd format",
            )
        ]

    # ----- Step 3: length + hex charset -----
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            # The first listed algorithm for each length is the modern
            # default and gets MEDIUM confidence. The rest are still
            # possible but less common in 2026 — LOW confidence
            confidence: Confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0 else "also possible at this length"
            )
            candidates.append(
                HashCandidate(
                    algorithm = algorithm,
                    confidence = confidence,
                    reason = f"{len(text)} hex chars — {label}",
                )
            )
        return candidates
