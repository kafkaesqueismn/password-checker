# Password Checker

A command-line tool that scores how strong a password is and checks whether it
has appeared in a known data breach, **without ever sending your password (or
even its full hash) over the internet.**

```
$ python password_checker.py
Password to check:

Score: 0/100 (Weak)
  - Decent length, but 12+ characters is much stronger.
  - Add uppercase letters, digits, symbols.
  - This is one of the most common passwords.

WARNING: this password has appeared in 52,372,427 known breaches. Do not use it.
```

## Setup

Requires Python 3.9+.

```bash
python3 -m venv .venv
source .venv/bin/activate        # fish: source .venv/bin/activate.fish
pip install -r requirements.txt
```

## Usage

```bash
python password_checker.py            # strength score + breach check
python password_checker.py --offline  # strength score only, no network
pytest                                # run the tests
```

The password is read with `getpass`, so it isn't shown on screen and isn't
saved in your shell history (which it would be if you passed it as an argument).

Exit codes: `0` OK, `1` network error, `2` no input, `3` found in a breach.

## How the score works

The score runs from 0 to 100 and is built from three parts:

| Part | Points | Idea |
|---|---|---|
| Length | 0–40 | Under 8 chars = 0, 8–11 = 15, 12–15 = 30, 16+ = 40. Length matters most, because every extra character multiplies the number of guesses an attacker needs. |
| Variety | 0–40 | 10 points each for lowercase, uppercase, digits and symbols. More kinds of character means more possibilities per position. |
| Patterns | +20 bonus, or a penalty | Common passwords (−50), repeated characters like `aaa` (−10), sequences like `abc`/`321` (−10), keyboard walks like `qwer` (−10), years like `1999` (−5). With no patterns at all you get a +20 bonus. |

Ratings: under 40 Weak, 40–69 Fair, 70–89 Strong, 90+ Very strong.

This is a simple rule-based scorer meant for learning. A password can score
well and still be breached (`Password1!` scores 75 but appears in breaches),
which is why the breach check matters. For production use, look at
[zxcvbn](https://github.com/dropbox/zxcvbn), which models how attackers actually guess.

## How the breach check works

[Have I Been Pwned](https://haveibeenpwned.com/Passwords) (HIBP) keeps a
database of hundreds of millions of real passwords leaked in data breaches.
Sending them your password to look it up would defeat the purpose, so
HIBP offers a **range API** that uses a technique called **k-anonymity**:

1. **Hash locally.** The program computes the SHA-1 hash of your password on
   your own machine:
   `password` → `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
2. **Send only the first 5 characters.** It requests
   `https://api.pwnedpasswords.com/range/5BAA6`.
3. **Get back a bucket.** HIBP replies with the remaining 35 characters of
   *every* breached hash that starts with `5BAA6`, plus how many times each was
   seen. That's typically several hundred to a couple of thousand entries:
   ```
   1E4C9B93F3F0682250B6CF8331B7EE68FD8:52372427
   1E4E5F1E2E4C1B1C2B5D7A4D0B2C9F1A8E7:3
   ...
   ```
4. **Compare locally.** The program looks for its own suffix
   (`1E4C9B93F3F...`) in that list. A match means the password is breached.

### Why k-anonymity protects you

"k-anonymity" means your request can't be told apart from those of at
least *k* other possibilities. Here's why that keeps you safe:

- **Your password never leaves your computer.** Neither does its full hash.
  Only 5 hex characters do, which is 20 bits out of SHA-1's 160.
- **The prefix is shared by many hashes.** There are only 16⁵ = 1,048,576
  possible prefixes, and HIBP holds hundreds of millions of hashes, so every
  prefix matches hundreds of breached passwords, and far more possible
  passwords that have never been breached. Even HIBP can't tell which one
  you were checking, or whether your password is in their list at all.
- **The answer is worked out on your side.** The server never learns whether
  you got a match.
- **Padding hides the reply size.** We send `Add-Padding: true`, so HIBP adds
  fake entries (count 0) to make every reply a similar size. Someone watching
  your network traffic can't work out the prefix from how big the reply is
  (the connection is also encrypted with HTTPS).

*A note on SHA-1:* SHA-1 is considered broken for things like digital
signatures, and it is **not** a good way to store passwords. Here it's just
used as a lookup key, because that's the format HIBP's database uses.

## Project layout

```
password_checker.py              scoring, breach check, and CLI
tests/test_password_checker.py   pytest tests (network calls are mocked)
requirements.txt                 dependencies: requests, pytest
pytest.ini                       tells pytest where to find the code
```
