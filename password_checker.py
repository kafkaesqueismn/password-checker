"""A command-line password strength checker.

Scores a password on length, character variety and common patterns, then
asks the Have I Been Pwned (HIBP) "range" API whether it has appeared in a
known data breach. Only the first 5 characters of the password's SHA-1 hash
ever leave your machine (this is called k-anonymity; see README.md).
"""

import argparse
import getpass
import hashlib
import re
import string
import sys

import requests

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"

# A tiny sample of the most common passwords. Real tools use lists with
# millions of entries; the breach check below covers that case for us.
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "qwerty",
    "abc123", "football", "monkey", "letmein", "111111", "iloveyou",
    "admin", "welcome", "login", "dragon", "sunshine", "princess",
    "master", "shadow", "passw0rd", "trustno1", "baseball", "superman",
}

# Rows of a QWERTY keyboard, used to spot "walks" like "asdf" or "qwerty".
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def score_length(password):
    """Return (points, feedback) for length. Worth up to 40 points."""
    length = len(password)
    if length < 8:
        return 0, ["Too short: use at least 8 characters (12+ is better)."]
    if length < 12:
        return 15, ["Decent length, but 12+ characters is much stronger."]
    if length < 16:
        return 30, []
    return 40, []


def score_variety(password):
    """Return (points, feedback) for character variety. Worth up to 40 points.

    There are four character classes; each one present is worth 10 points.
    """
    classes = {
        "lowercase letters": any(c in string.ascii_lowercase for c in password),
        "uppercase letters": any(c in string.ascii_uppercase for c in password),
        "digits": any(c in string.digits for c in password),
        # Anything that isn't a letter or digit counts as a symbol,
        # including spaces and non-English characters.
        "symbols": any(not c.isalnum() for c in password),
    }
    points = 10 * sum(classes.values())
    missing = [name for name, present in classes.items() if not present]
    feedback = [f"Add {', '.join(missing)}."] if missing else []
    return points, feedback


def _has_sequence(text, run=3):
    """True if text contains `run` characters in a row going up or down
    by one, like "abc", "321" or "xyz"."""
    for i in range(len(text) - run + 1):
        chunk = text[i:i + run]
        steps = {ord(b) - ord(a) for a, b in zip(chunk, chunk[1:])}
        if steps == {1} or steps == {-1}:
            return True
    return False


def _has_keyboard_walk(text, run=4):
    """True if text contains `run` adjacent keys from one keyboard row,
    forwards or backwards (e.g. "qwer", "lkjh")."""
    for row in KEYBOARD_ROWS:
        for candidate in (row, row[::-1]):
            for i in range(len(candidate) - run + 1):
                if candidate[i:i + run] in text:
                    return True
    return False


def find_patterns(password):
    """Return (penalty, feedback) for predictable patterns.

    The penalty is a positive number that gets subtracted from the score.
    """
    lowered = password.lower()
    penalty = 0
    feedback = []

    if lowered in COMMON_PASSWORDS:
        penalty += 50
        feedback.append("This is one of the most common passwords.")

    # (.)\1{2,} means "any character, followed by itself 2+ more times".
    if re.search(r"(.)\1{2,}", password):
        penalty += 10
        feedback.append("Avoid repeating the same character (e.g. 'aaa').")

    if _has_sequence(lowered):
        penalty += 10
        feedback.append("Avoid sequences like 'abc' or '123'.")

    if _has_keyboard_walk(lowered):
        penalty += 10
        feedback.append("Avoid keyboard patterns like 'qwerty' or 'asdf'.")

    # 19xx or 20xx: birth years and the current year are very common.
    if re.search(r"(19|20)\d\d", password):
        penalty += 5
        feedback.append("Avoid years, which are easy to guess.")

    return penalty, feedback


def score_password(password):
    """Combine all the checks into a score from 0 to 100 plus advice."""
    length_points, length_fb = score_length(password)
    variety_points, variety_fb = score_variety(password)
    penalty, pattern_fb = find_patterns(password)

    # 80 is the most length + variety can give; the last 20 points are a
    # bonus for passwords with no detectable patterns at all.
    bonus = 20 if penalty == 0 else 0
    raw = length_points + variety_points + bonus - penalty
    score = max(0, min(100, raw))  # clamp into the range 0..100
    return score, length_fb + variety_fb + pattern_fb


def rating(score):
    """Turn a numeric score into a word."""
    if score < 40:
        return "Weak"
    if score < 70:
        return "Fair"
    if score < 90:
        return "Strong"
    return "Very strong"


# --------------------------------------------------------------------------
# Breach check (Have I Been Pwned, k-anonymity)
# --------------------------------------------------------------------------

def sha1_hex(password):
    """Return the uppercase hex SHA-1 hash of the password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def pwned_count(password, timeout=10):
    """Return how many times the password appears in HIBP's breach data.

    Only the first 5 hex characters of the SHA-1 hash are sent. HIBP replies
    with every hash suffix that starts with that prefix, and we look for
    ours in the reply locally, so the server never learns which one we had.
    """
    digest = sha1_hex(password)
    prefix, suffix = digest[:5], digest[5:]

    response = requests.get(
        HIBP_RANGE_URL + prefix,
        # Padding makes HIBP add fake entries so every reply is a similar
        # size, which stops someone watching the network from guessing the
        # prefix from how big the reply is.
        headers={"Add-Padding": "true", "User-Agent": "password-checker-cli"},
        timeout=timeout,
    )
    response.raise_for_status()  # turn HTTP errors (e.g. 503) into exceptions

    # Each line looks like "SUFFIX:COUNT", e.g.
    # "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493"
    for line in response.text.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip().upper() == suffix:
            return int(count)  # padding entries have count 0
    return 0


# --------------------------------------------------------------------------
# Command-line interface
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check how strong a password is and whether it has "
                    "appeared in a known data breach.",
    )
    parser.add_argument(
        "--offline", action="store_true",
        help="skip the Have I Been Pwned breach check",
    )
    args = parser.parse_args(argv)

    # getpass hides what you type and keeps the password out of your shell
    # history, which a command-line argument would not.
    password = getpass.getpass("Password to check: ")
    if not password:
        print("No password entered.", file=sys.stderr)
        return 2

    score, feedback = score_password(password)
    print(f"\nScore: {score}/100 ({rating(score)})")
    for tip in feedback:
        print(f"  - {tip}")

    if args.offline:
        print("\nBreach check skipped (--offline).")
        return 0

    try:
        count = pwned_count(password)
    except requests.RequestException as err:
        print(f"\nCould not reach Have I Been Pwned: {err}", file=sys.stderr)
        return 1

    if count:
        print(f"\nWARNING: this password has appeared in {count:,} known "
              "breaches. Do not use it.")
        return 3
    print("\nGood news: this password was not found in any known breach.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
