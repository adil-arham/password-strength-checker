# Password Strength Checker

A command-line tool that scores a password from 0 to 100, labels it
**Weak / Medium / Strong**, and gives specific tips to improve it. Built with
Python 3 and the standard library only (no `pip install`).

The scoring follows current guidance from **NIST SP 800-63B** and the **OWASP
Authentication Cheat Sheet**: length and a common-password blocklist matter
most; forced composition rules ("must have a symbol") do not.

## What it checks

| Check | How it affects the score |
|---|---|
| Length | Biggest factor: 4 points per character, full credit at 20. Under 8 characters is capped at Weak. |
| Common passwords | Matched against a local list, including simple variations (`Password1!`, `p@ssw0rd`). A match caps the score at 10. |
| Character variety | Small bonus only (5 points per type), because NIST discourages composition rules. |
| Repeated characters | Penalty for runs like `aaa`, and for very low character diversity. |
| Sequences | Penalty for `1234`, `abcd`, `4321` (forwards or backwards). |
| Keyboard patterns | Penalty for `qwer`, `asdf`, `zxcv` (forwards or backwards). |

## How to run

Requires Python 3.9 or newer.

```bash
git clone <your-repo-url>
cd password-strength-checker
python3 password_checker.py
```

Run the tests:

```bash
python3 -m unittest -v
```

Use a bigger blocklist (for example a SecLists file):

```bash
python3 password_checker.py --wordlist path/to/10-million-password-list.txt
```

## Example output

```text
$ python3 password_checker.py
Enter password to check (input is hidden):
Strength: Weak (10/100)
Length: 10 characters

Tips:
  - This password, or a trivial variation of it, is on the common-passwords list. Attackers try these first. Pick something unrelated to it.
  - Make it longer: aim for 12+ characters. A passphrase of 4 or more unrelated words is easy to remember and hard to guess.
```

```text
Strength: Medium (64/100)
Length: 11 characters

Tips:
  - Make it longer: aim for 12+ characters. A passphrase of 4 or more unrelated words is easy to remember and hard to guess.
```

```text
Strength: Strong (90/100)
Length: 23 characters

Tips:
  - No issues found. Use a different password for every site, keep them in a password manager, and turn on multi-factor authentication where you can.
```

(The three examples above were checked with `Password1!`, `Tr0ub4dor&3`, and a
four-word passphrase. The password is never shown in the output.)

## Security notes

- **Hidden input.** The password is read with `getpass`. If the terminal cannot
  hide input (some IDE consoles), the program refuses to continue instead of
  echoing it.
- **Never on the command line.** Arguments show up in shell history and in
  process lists, so the password is not accepted as an argument.
- **Never printed, stored, or logged.** The result object holds counts and
  flags only, and tips describe problems without quoting any part of the
  password. A unit test checks that the password does not appear in output.
- **No length limit and no truncation.** Following NIST and OWASP, long
  passphrases are accepted as-is, and spaces and Unicode are allowed.
- **Fails loudly.** If the blocklist file is missing, the program exits with an
  error rather than silently skipping the check.
- **Limits, stated honestly.**
  - The score is a heuristic, not a guarantee. It does not estimate entropy
    (OWASP advises against presenting an entropy figure as proof of strength).
  - The bundled blocklist is a small sample. A real deployment needs a large
    list, ideally including breached passwords.
  - Python strings are immutable, so the password cannot be reliably wiped from
    memory after use.
  - This tool checks strength only. Sites must still hash stored passwords
    (Argon2, scrypt, bcrypt), use rate limiting, and offer MFA.

## Project structure

```text
password-strength-checker/
├── README.md
├── password_checker.py
├── test_password_checker.py
├── .gitignore
└── data/
    └── common_passwords.txt
```

## What I learned

*(Draft. Edit it so it is true to your experience.)*

- Modern guidance favors length and blocklists over complexity rules, and why:
  people respond to composition rules in predictable ways (`Password1!`).
- Splitting code into small pure functions made it easy to test without mocking
  the keyboard or the file system.
- Security tools have to avoid leaking the secret they check: no echo, no
  command-line argument, no logging, no quoting it back.
- Heuristics have blind spots, so I tested edge cases (empty input, 5,000
  characters, Unicode) and documented the limits.
