"""Unit tests for password_checker. Run: python3 -m unittest -v"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import password_checker as pc

# A tiny blocklist so tests don't depend on the real data file.
COMMON = {"password", "qwerty", "letmein", "summer"}


class TestLoadCommonPasswords(unittest.TestCase):
    def test_skips_comments_and_blanks_and_lowercases(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "list.txt"
            path.write_text("# comment\n\nPassword\n  LetMeIn  \n", encoding="utf-8")
            self.assertEqual(pc.load_common_passwords(path), {"password", "letmein"})

    def test_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            pc.load_common_passwords(Path("does-not-exist.txt"))

    def test_bundled_list_loads(self):
        self.assertIn("password", pc.load_common_passwords(pc.DEFAULT_WORDLIST))


class TestCharacterClasses(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(pc.count_character_classes(""), 0)
        self.assertEqual(pc.count_character_classes("abc"), 1)
        self.assertEqual(pc.count_character_classes("abC1"), 3)
        self.assertEqual(pc.count_character_classes("abC1!"), 4)

    def test_space_counts_as_other(self):
        self.assertEqual(pc.count_character_classes("two words"), 2)


class TestRepeats(unittest.TestCase):
    def test_detects_runs_of_three_or_more(self):
        self.assertEqual(pc.find_repeated_runs("aaabbbc"), ["aaa", "bbb"])

    def test_two_in_a_row_is_fine(self):
        self.assertEqual(pc.find_repeated_runs("aabbcc"), [])

    def test_case_insensitive(self):
        self.assertEqual(len(pc.find_repeated_runs("aAa")), 1)

    def test_unique_ratio(self):
        self.assertEqual(pc.unique_ratio(""), 1.0)  # no ZeroDivisionError
        self.assertAlmostEqual(pc.unique_ratio("aaaa"), 0.25)


class TestPatterns(unittest.TestCase):
    def test_ascending_and_descending_sequences(self):
        self.assertTrue(pc.find_sequences("x1234y"))
        self.assertTrue(pc.find_sequences("xdcbay"))
        self.assertTrue(pc.find_sequences("ABCD"))  # case-insensitive

    def test_three_in_a_row_is_not_a_sequence(self):
        self.assertEqual(pc.find_sequences("abc"), [])

    def test_keyboard_patterns(self):
        self.assertTrue(pc.find_keyboard_patterns("myqwertypass"))
        self.assertTrue(pc.find_keyboard_patterns("fdsa"))  # reversed row

    def test_random_looking_password_has_no_patterns(self):
        for text in ("Xk9#mP2$vL", "tiger-lamp-orbit"):
            self.assertEqual(pc.find_sequences(text), [], text)
            self.assertEqual(pc.find_keyboard_patterns(text), [], text)

    def test_overlapping_matches_counted_once(self):
        self.assertEqual(len(pc.find_sequences("123456")), 1)


class TestBlocklist(unittest.TestCase):
    def test_exact_and_case(self):
        self.assertTrue(pc.is_common_password("password", COMMON))
        self.assertTrue(pc.is_common_password("PASSWORD", COMMON))

    def test_trailing_digits_and_symbols(self):
        self.assertTrue(pc.is_common_password("Password1!", COMMON))
        self.assertTrue(pc.is_common_password("Summer2024!!", COMMON))

    def test_leetspeak(self):
        self.assertTrue(pc.is_common_password("P@ssw0rd", COMMON))

    def test_unrelated_password_not_flagged(self):
        self.assertFalse(pc.is_common_password("tiger-lamp-orbit", COMMON))

    def test_digits_only_input_does_not_match_empty_entry(self):
        self.assertFalse(pc.is_common_password("2468", COMMON))


class TestLabels(unittest.TestCase):
    def test_boundaries(self):
        self.assertEqual(pc.label_for_score(0), "Weak")
        self.assertEqual(pc.label_for_score(pc.WEAK_BELOW - 1), "Weak")
        self.assertEqual(pc.label_for_score(pc.WEAK_BELOW), "Medium")
        self.assertEqual(pc.label_for_score(pc.STRONG_AT_LEAST - 1), "Medium")
        self.assertEqual(pc.label_for_score(pc.STRONG_AT_LEAST), "Strong")
        self.assertEqual(pc.label_for_score(100), "Strong")


class TestEvaluate(unittest.TestCase):
    def test_empty_password_scores_zero(self):
        report = pc.evaluate_password("", COMMON)
        self.assertEqual((report.score, report.label), (0, "Weak"))

    def test_too_short_is_capped_and_weak(self):
        report = pc.evaluate_password("Xk9#mP2", COMMON)  # 7 chars, 4 classes
        self.assertLessEqual(report.score, pc.TOO_SHORT_SCORE_CAP)
        self.assertEqual(report.label, "Weak")

    def test_common_password_is_weak_even_if_long_and_varied(self):
        report = pc.evaluate_password("Summer2024!!", COMMON)
        self.assertTrue(report.is_common)
        self.assertLessEqual(report.score, pc.COMMON_PASSWORD_SCORE_CAP)
        self.assertEqual(report.label, "Weak")

    def test_long_lowercase_passphrase_is_strong(self):
        # NIST: length beats composition rules.
        report = pc.evaluate_password("tiger lamp orbit velvet", COMMON)
        self.assertEqual(report.label, "Strong")

    def test_length_beats_variety(self):
        short_complex = pc.evaluate_password("Xk9#mP2$", COMMON)      # 8 chars
        long_simple = pc.evaluate_password("tigerlamporbitvelvet", COMMON)  # 20 chars
        self.assertGreater(long_simple.score, short_complex.score)

    def test_patterns_lower_the_score(self):
        clean = pc.evaluate_password("Xk9#mP2$vLq5", COMMON)
        patterned = pc.evaluate_password("Xk9#mP2$1234", COMMON)
        self.assertLess(patterned.score, clean.score)
        self.assertEqual(patterned.sequences, 1)

    def test_score_always_between_0_and_100(self):
        samples = ["", "a", "aaaaaaaaaaaaaaaaaaaaaaaa", "qwertyuiopasdfghjkl",
                   "Xk9#mP2$vLq5!zT8&wN3", "x" * 5000, "pässwörd-ünïcode-ok"]
        for text in samples:
            score = pc.evaluate_password(text, COMMON).score
            self.assertTrue(0 <= score <= 100, (len(text), score))

    def test_tips_are_specific(self):
        report = pc.evaluate_password("qwerty1234", COMMON)
        joined = " ".join(report.tips).lower()
        self.assertIn("keyboard", joined)
        self.assertIn("sequence", joined)

    def test_strong_password_gets_a_closing_tip(self):
        report = pc.evaluate_password("Xk9#mP2$vLq5!zT8&wN3", COMMON)
        self.assertEqual(len(report.tips), 1)
        self.assertIn("password manager", report.tips[0])


class TestPasswordNeverLeaks(unittest.TestCase):
    SECRET = "Zq7!unlikelyToAppear-9x"

    def test_report_text_does_not_contain_password(self):
        text = pc.format_report(pc.evaluate_password(self.SECRET, COMMON))
        self.assertNotIn(self.SECRET, text)
        self.assertNotIn(self.SECRET.lower(), text.lower())

    def test_report_object_has_no_password_field(self):
        report = pc.evaluate_password(self.SECRET, COMMON)
        self.assertNotIn(self.SECRET, repr(report))

    def test_main_prints_nothing_containing_password(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(pc, "read_password", return_value=self.SECRET), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pc.main([])
        self.assertEqual(code, 0)
        self.assertNotIn(self.SECRET, out.getvalue() + err.getvalue())


class TestMain(unittest.TestCase):
    def test_missing_wordlist_exits_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = pc.main(["--wordlist", "nope.txt"])
        self.assertEqual(code, 2)
        self.assertIn("cannot read word list", err.getvalue())

    def test_empty_input_exits_1(self):
        with mock.patch.object(pc, "read_password", return_value=""), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pc.main([]), 1)

    def test_ctrl_c_exits_130(self):
        with mock.patch.object(pc, "read_password", side_effect=KeyboardInterrupt), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(pc.main([]), 130)


if __name__ == "__main__":
    unittest.main()
