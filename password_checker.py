from __future__ import annotations

import argparse
import getpass
import string
import sys
import warnings
from dataclasses import dataclass
from itertools import groupby
from pathlib import Path
from typing import Sequence

# Constants (tune the scoring here, not inside the functions)

# Resolved relative to THIS file, so the program works from any directory.
DEFAULT_WORDLIST = Path(__file__).resolve().parent / "data" / "common_passwords.txt"

PROMPT = "Enter password to check (input is hidden): "

# Length. NIST sets a floor of 8; the other two numbers are design choices.
MIN_LENGTH = 8
RECOMMENDED_LENGTH = 12
FULL_CREDIT_LENGTH = 20   # no extra points beyond this, but longer is never blocked
POINTS_PER_CHAR = 4       # 20 chars -> 80 points: length is the biggest factor

# Variety is a small bonus only (NIST discourages mandatory composition rules).
POINTS_PER_CHAR_CLASS = 5  # 4 classes -> 20 points

# Pattern detection.
MIN_REPEAT_RUN = 3         # "aaa"
MIN_PATTERN_LENGTH = 4     # "1234", "abcd", "qwer"
LOW_UNIQUE_RATIO = 0.5     # fewer than half the characters are distinct

# Penalties (points subtracted).
REPEAT_PENALTY = 8
REPEAT_PENALTY_CAP = 16
LOW_UNIQUE_PENALTY = 10
PATTERN_PENALTY = 10
PATTERN_PENALTY_CAP = 20

# Hard caps for the worst cases.
TOO_SHORT_SCORE_CAP = 25
COMMON_PASSWORD_SCORE_CAP = 10

# Label boundaries.
WEAK_BELOW = 40
STRONG_AT_LEAST = 65

# Reference strings used to detect sequences and keyboard patterns.
# Each is also checked in reverse. The digit string wraps 9 -> 0 like a keyboard.
SEQUENCE_REFERENCES = ("abcdefghijklmnopqrstuvwxyz", "01234567890")
KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm")

# Common "leetspeak" substitutions, used only when checking the blocklist.
LEET_TABLE = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)
TRAILING_JUNK = string.digits + string.punctuation


# Data type returned by the checker

@dataclass(frozen=True)
class StrengthReport:
    """Result of checking one password. Contains NO copy of the password."""

    score: int
    label: str
    length: int
    char_classes: int
    is_common: bool
    repeated_runs: int
    sequences: int
    keyboard_patterns: int
    tips: list[str]


# --------------------------------------------------------------------------
# Loading the blocklist
# --------------------------------------------------------------------------

def load_common_passwords(path: Path) -> set[str]:
    """Load a text file of common passwords (one per line) into a set.

    Blank lines and lines starting with '#' are ignored. Entries are
    lowercased so lookups are case-insensitive. A set makes each lookup
    O(1) instead of scanning the whole list.

    Raises:
        FileNotFoundError / OSError: if the file cannot be read.
    """
    passwords: set[str] = set()
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip().lower()
            if entry and not entry.startswith("#"):
                passwords.add(entry)
    return passwords


# --------------------------------------------------------------------------
# Individual checks (each function does one job)
# --------------------------------------------------------------------------

def count_character_classes(password: str) -> int:
    """Count how many of lowercase / uppercase / digit / other are present."""
    has_lower = any(ch.islower() for ch in password)
    has_upper = any(ch.isupper() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_other = any(not ch.isalnum() for ch in password)  # symbols and spaces
    return sum([has_lower, has_upper, has_digit, has_other])


def find_repeated_runs(password: str, min_run: int = MIN_REPEAT_RUN) -> list[str]:
    """Return runs of the same character repeated min_run or more times."""
    runs = []
    for _char, group in groupby(password.lower()):
        run = "".join(group)
        if len(run) >= min_run:
            runs.append(run)
    return runs


def unique_ratio(password: str) -> float:
    """Return distinct characters divided by length (1.0 for empty input)."""
    if not password:  # avoid ZeroDivisionError
        return 1.0
    return len(set(password.lower())) / len(password)


def find_pattern_runs(
    text: str, references: Sequence[str], min_length: int
) -> list[str]:
    """Find maximal pieces of `text` that appear inside any reference string.

    Each reference is also tried reversed, so "1234" and "4321" both match
    "01234567890". Matching is case-insensitive.
    """
    text = text.lower()
    all_refs = tuple(references) + tuple(ref[::-1] for ref in references)
    found: list[str] = []
    start = 0
    while start < len(text):
        end = start
        # Grow the window while it is still a substring of some reference.
        while end < len(text) and any(text[start:end + 1] in ref for ref in all_refs):
            end += 1
        if end - start >= min_length:
            found.append(text[start:end])
            start = end          # skip past this match so hits don't overlap
        else:
            start += 1
    return found


def find_sequences(password: str) -> list[str]:
    """Find alphabet/number sequences such as 'abcd' or '4321'."""
    return find_pattern_runs(password, SEQUENCE_REFERENCES, MIN_PATTERN_LENGTH)


def find_keyboard_patterns(password: str) -> list[str]:
    """Find keyboard-row walks such as 'qwer' or 'lkjh'."""
    return find_pattern_runs(password, KEYBOARD_ROWS, MIN_PATTERN_LENGTH)


def blocklist_candidates(password: str) -> set[str]:
    """Return simple variations of a password that attackers also try.

    Handles case ("PASSWORD"), tacked-on endings ("password1!"), and
    leetspeak ("p@ssw0rd"). Without this, "Password1!" would slip past a
    plain exact-match check.
    """
    lowered = password.lower()
    stripped = lowered.rstrip(TRAILING_JUNK)
    candidates = {lowered, lowered.translate(LEET_TABLE)}
    if stripped:
        candidates.add(stripped)
        candidates.add(stripped.translate(LEET_TABLE))
    return candidates


def is_common_password(password: str, common_passwords: set[str]) -> bool:
    """Return True if the password, or a trivial variation, is blocklisted."""
    return not blocklist_candidates(password).isdisjoint(common_passwords)


# Scoring and advice

def label_for_score(score: int) -> str:
    """Convert a 0-100 score to Weak / Medium / Strong."""
    if score < WEAK_BELOW:
        return "Weak"
    if score < STRONG_AT_LEAST:
        return "Medium"
    return "Strong"


def calculate_score(
    length: int,
    char_classes: int,
    uniqueness: float,
    repeated_runs: int,
    pattern_hits: int,
    is_common: bool,
) -> int:
    """Combine the measurements into one score, clamped to 0-100."""
    score = min(length, FULL_CREDIT_LENGTH) * POINTS_PER_CHAR
    score += char_classes * POINTS_PER_CHAR_CLASS
    score -= min(repeated_runs * REPEAT_PENALTY, REPEAT_PENALTY_CAP)
    if uniqueness < LOW_UNIQUE_RATIO:
        score -= LOW_UNIQUE_PENALTY
    score -= min(pattern_hits * PATTERN_PENALTY, PATTERN_PENALTY_CAP)

    if length < MIN_LENGTH:
        score = min(score, TOO_SHORT_SCORE_CAP)
    if is_common:
        score = min(score, COMMON_PASSWORD_SCORE_CAP)
    return max(0, min(100, score))


def build_tips(
    length: int,
    char_classes: int,
    is_common: bool,
    repeated_runs: int,
    sequences: int,
    keyboard_patterns: int,
) -> list[str]:
    """Turn the findings into specific, actionable advice."""
    tips: list[str] = []
    if is_common:
        tips.append(
            "This password, or a trivial variation of it, is on the "
            "common-passwords list. Attackers try these first. Pick "
            "something unrelated to it."
        )
    if length < MIN_LENGTH:
        tips.append(
            f"Use at least {MIN_LENGTH} characters (the minimum NIST allows); "
            f"aim for {RECOMMENDED_LENGTH} or more."
        )
    elif length < RECOMMENDED_LENGTH:
        tips.append(
            f"Make it longer: aim for {RECOMMENDED_LENGTH}+ characters. A "
            "passphrase of 4 or more unrelated words is easy to remember "
            "and hard to guess."
        )
    if repeated_runs:
        tips.append("Avoid repeating the same character 3 or more times in a row.")
    if sequences:
        tips.append("Avoid sequences such as 1234 or abcd (forwards or backwards).")
    if keyboard_patterns:
        tips.append("Avoid keyboard patterns such as qwerty or asdf.")
    if char_classes < 3 and length < FULL_CREDIT_LENGTH:
        tips.append(
            "Mixing in other character types helps a little, but adding "
            "length helps more."
        )
    if not tips:
        tips.append(
            "No issues found. Use a different password for every site, keep "
            "them in a password manager, and turn on multi-factor "
            "authentication where you can."
        )
    return tips


def evaluate_password(password: str, common_passwords: set[str]) -> StrengthReport:
    """Run every check and return a StrengthReport.

    This is a pure function: no input, no output, no file access. That is
    what makes it easy to unit test.
    """
    length = len(password)
    char_classes = count_character_classes(password)
    repeated = find_repeated_runs(password)
    sequences = find_sequences(password)
    keyboard = find_keyboard_patterns(password)
    common = is_common_password(password, common_passwords)

    score = calculate_score(
        length=length,
        char_classes=char_classes,
        uniqueness=unique_ratio(password),
        repeated_runs=len(repeated),
        pattern_hits=len(sequences) + len(keyboard),
        is_common=common,
    )
    return StrengthReport(
        score=score,
        label=label_for_score(score),
        length=length,
        char_classes=char_classes,
        is_common=common,
        repeated_runs=len(repeated),
        sequences=len(sequences),
        keyboard_patterns=len(keyboard),
        tips=build_tips(
            length, char_classes, common, len(repeated), len(sequences), len(keyboard)
        ),
    )


# Input / output

def read_password(prompt: str = PROMPT) -> str:
    """Read a password without echoing it to the screen.

    Some consoles (e.g. certain IDE run windows) cannot hide input, and
    getpass then only emits a warning and echoes anyway. We turn that
    warning into an error so the password is never shown.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(prompt)


def format_report(report: StrengthReport) -> str:
    """Render a report as plain text. Never includes the password itself."""
    lines = [
        f"Strength: {report.label} ({report.score}/100)",
        f"Length: {report.length} characters",
        "",
        "Tips:",
    ]
    lines.extend(f"  - {tip}" for tip in report.tips)
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse command-line options. The password is deliberately NOT one."""
    parser = argparse.ArgumentParser(description="Check password strength.")
    parser.add_argument(
        "--wordlist",
        type=Path,
        default=DEFAULT_WORDLIST,
        help="text file of common passwords, one per line "
        "(default: data/common_passwords.txt)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point. Returns a process exit code."""
    args = parse_args(argv)

    try:
        common_passwords = load_common_passwords(args.wordlist)
    except OSError as error:
        # Fail loudly: silently skipping the blocklist would give false
        # confidence in weak passwords.
        print(f"Error: cannot read word list ({error.strerror}): {args.wordlist}",
              file=sys.stderr)
        return 2

    try:
        password = read_password()
    except getpass.GetPassWarning:
        print("Error: this terminal cannot hide typed input. "
              "Run the program in a normal terminal.", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.", file=sys.stderr)
        return 130

    if not password:
        print("No password entered.", file=sys.stderr)
        return 1
    print(format_report(evaluate_password(password, common_passwords)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
