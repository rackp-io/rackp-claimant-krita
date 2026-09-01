"""JCS number serialization against ECMAScript Number::toString (RFC 8785).

Covers the band where Python's `repr` and ECMAScript disagree on notation:
Python switches to exponential below 1e-4, ECMAScript below 1e-6, and their
exponent spelling differs. Values here are taken from rackp-claimant-krita#1.
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from rackp_claimant.jcs import canonicalize, _num


class TestNumberFormatting(unittest.TestCase):
    def test_issue_examples(self):
        cases = [
            (0.00001, "0.00001"),
            (0.000012345, "0.000012345"),
            (1.5e-5, "0.000015"),
            (1e-7, "1e-7"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(_num(value), expected)

    def test_above_the_band_unchanged(self):
        # >= 1e-4: Python's own plain-decimal notation, unaffected by the fix.
        cases = [(0.0001, "0.0001"), (0.001, "0.001"), (0.1, "0.1"), (1.5, "1.5")]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(_num(value), expected)

    def test_exponential_threshold_boundary(self):
        # n = -6 is the last decimal-notation case (-6 < n <= 0); n = -7 is
        # the first exponential one. 1e-6 and 1e-7 sit exactly on that edge.
        self.assertEqual(_num(1e-6), "0.000001")
        self.assertEqual(_num(1e-7), "1e-7")

    def test_negative_values(self):
        self.assertEqual(_num(-0.00001), "-0.00001")
        self.assertEqual(_num(-1.5e-5), "-0.000015")

    def test_internal_and_multi_digit_mantissa(self):
        self.assertEqual(_num(100.5), "100.5")
        self.assertEqual(_num(123.456), "123.456")
        self.assertEqual(_num(1.23456789e-5), "0.0000123456789")

    def test_positive_exponent_uses_explicit_sign(self):
        # Large non-integral magnitudes are out of protocol range but should
        # still match ECMAScript, which writes "e+N" (not just "eN").
        self.assertEqual(_num(1.5e25), "1.5e+25")

    def test_denormal_minimum(self):
        self.assertEqual(_num(5e-324), "5e-324")

    def test_data_hash_band_reaches_canonicalize(self):
        # The path the issue actually cares about: an application payload
        # (not a protocol-defined field) carrying a value in the band.
        canonical = canonicalize({"n": 0.00001}).decode("utf-8")
        self.assertEqual(canonical, '{"n":0.00001}')

    def test_non_finite_still_rejected(self):
        with self.assertRaises(ValueError):
            _num(float("nan"))
        with self.assertRaises(ValueError):
            _num(float("inf"))

    def test_integers_and_integral_floats_unaffected(self):
        # The fix only touches the repr fallback; the integer fast path is untouched.
        self.assertEqual(canonicalize({"n": [0, -1, 1.0, 42]}).decode("utf-8"), '{"n":[0,-1,1,42]}')


if __name__ == "__main__":
    unittest.main()
