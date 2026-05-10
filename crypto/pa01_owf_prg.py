"""
crypto/pa01_owf_prg.py — One-Way Functions & Pseudorandom Generators (PA#1).

Allowed imports: os, math, random (SystemRandom only).
NO crypto libraries.
"""

import math
from crypto.utils import random_int, random_bits
from crypto.pa13_miller_rabin import gen_safe_prime, miller_rabin_test


class DLP_OWF:
    """
    One-Way Function based on the Discrete Logarithm Problem.
    f(x) = g^x mod p in a prime-order subgroup of Z*_p.

    Setup:
        - Use gen_safe_prime() from PA#13 to get p = 2q + 1.
        - Find generator g of the subgroup of order q:
          Pick random h in [2, p-2], compute g = h^2 mod p.
          If g == 1, pick again.
        - Store p, q, g as instance attributes.
    """

    def __init__(self, bits: int = 64):
        """Generate group parameters (p, q, g) using PA#13."""
        self.p, self.q = gen_safe_prime(bits)
        # Find generator g of the order-q subgroup (quadratic residues mod p)
        while True:
            h = random_int(2, self.p - 2)
            g = pow(h, 2, self.p)
            if g != 1:
                self.g = g
                break

    def evaluate(self, x: int) -> int:
        """Compute f(x) = g^x mod p."""
        return pow(self.g, x, self.p)

    def verify_hardness(self, num_trials: int = 1000) -> dict:
        """
        Demonstrate that random inversion fails.
        1. Pick random x, compute y = f(x).
        2. Try `num_trials` random guesses x' and check if f(x') == y.
        3. Return dict with results.
        """
        x = random_int(1, self.q - 1)
        y = self.evaluate(x)
        inversions_found = 0
        for _ in range(num_trials):
            x_guess = random_int(1, self.q - 1)
            if self.evaluate(x_guess) == y:
                inversions_found += 1
        return {
            'target_x': x,
            'target_y': y,
            'trials': num_trials,
            'inversions_found': inversions_found,
            'success_rate': inversions_found / num_trials,
        }

    def get_params(self) -> dict:
        """Return {'p': p, 'q': q, 'g': g} for use by other modules."""
        return {'p': self.p, 'q': self.q, 'g': self.g}


def goldreich_levin_bit(x: int, r: int, n_bits: int) -> int:
    """
    Goldreich-Levin hard-core predicate.

    b(x, r) = <x, r> mod 2 = XOR of (x_i AND r_i) for all bit positions.

    Args:
        x: Input value.
        r: Random public vector (same bit length as x).
        n_bits: Number of bits to consider.

    Returns:
        0 or 1.
    """
    return bin(x & r).count('1') % 2


class PRG:
    """
    Pseudorandom Generator built from a OWF using the HILL construction.

    G(x0) = b(x0) || b(x1) || ... || b(x_ℓ)
    where x_{i+1} = f(x_i) and b is the Goldreich-Levin hard-core bit.

    The seed is (x0, r) where r is the GL public vector.
    """

    def __init__(self, owf: DLP_OWF, r: int = None):
        """
        Args:
            owf: An instance of DLP_OWF (or any OWF with evaluate()).
            r: Goldreich-Levin public vector. If None, generate randomly.
        """
        self.owf = owf
        self.n_bits = owf.get_params()['q'].bit_length()
        if r is None:
            self.r = random_int(1, (1 << self.n_bits) - 1)
        else:
            self.r = r
        self._state = None

    def seed(self, s: int):
        """
        Set the PRG seed.
        Args:
            s: Seed value, an integer in Z_q.
        """
        self._state = s

    def next_bits(self, num_bits: int) -> list[int]:
        """
        Generate `num_bits` pseudorandom bits using the HILL construction.

        Algorithm:
            output = []
            x = self._state
            for i in range(num_bits):
                output.append(goldreich_levin_bit(x, self.r, self.n_bits))
                x = self.owf.evaluate(x)
            self._state = x
            return output

        Returns:
            List of 0s and 1s of length `num_bits`.
        """
        if self._state is None:
            raise ValueError("PRG not seeded. Call seed() first.")
        output = []
        x = self._state
        for _ in range(num_bits):
            output.append(goldreich_levin_bit(x, self.r, self.n_bits))
            x = self.owf.evaluate(x)
        self._state = x
        return output

    def generate(self, seed_val: int, output_length: int) -> list[int]:
        """
        One-shot generation: seed + generate.
        Returns list of `output_length` bits.
        """
        self.seed(seed_val)
        return self.next_bits(output_length)


class PRG_as_OWF:
    """
    Demonstrates that any PRG G is also a OWF.
    Define f(s) = G(s). Since G expands, f is not invertible.
    This is PA#1b — backward direction.
    """

    def __init__(self, prg: PRG):
        self.prg = prg

    def evaluate(self, s: int, output_len: int = None) -> list[int]:
        """f(s) = G(s). Returns the PRG output as the OWF output."""
        if output_len is None:
            output_len = self.prg.n_bits + 1
        return self.prg.generate(s, output_len)

    def verify_hardness(self, num_trials: int = 100) -> dict:
        """
        Given G(s), try to find s by brute force.
        Pick a random seed s, compute y = G(s).
        Try `num_trials` random seeds s' and check if G(s') == y.
        """
        q = self.prg.owf.get_params()['q']
        output_len = self.prg.n_bits + 1
        s = random_int(1, q - 1)
        y = self.evaluate(s, output_len)
        inversions_found = 0
        for _ in range(num_trials):
            s_guess = random_int(1, q - 1)
            if self.evaluate(s_guess, output_len) == y:
                inversions_found += 1
        return {
            'target_s': s,
            'trials': num_trials,
            'inversions_found': inversions_found,
            'success_rate': inversions_found / num_trials,
        }


class StatisticalTests:
    """
    Three NIST SP 800-22 statistical tests for PRG output.
    Each test returns (pass: bool, p_value: float).
    """

    @staticmethod
    def frequency_monobit(bits: list[int]) -> tuple[bool, float]:
        """
        Test 1: Frequency (Monobit) Test.
        Check if the number of 1s and 0s are approximately equal.
        """
        n = len(bits)
        # Convert to +1/-1
        S = sum(2 * b - 1 for b in bits)
        s_obs = abs(S) / math.sqrt(n)
        p_value = math.erfc(s_obs / math.sqrt(2))
        return (p_value >= 0.01, p_value)

    @staticmethod
    def runs_test(bits: list[int]) -> tuple[bool, float]:
        """
        Test 2: Runs Test.
        Check if the oscillation between 0s and 1s is as expected.
        """
        n = len(bits)
        pi = sum(bits) / n
        # Pre-test
        if abs(pi - 0.5) >= 2 / math.sqrt(n):
            return (False, 0.0)
        # Count runs (a run is a maximal sequence of identical consecutive bits)
        V = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
        expected = 2 * n * pi * (1 - pi)
        denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
        p_value = math.erfc(abs(V - expected) / denom)
        return (p_value >= 0.01, p_value)

    @staticmethod
    def serial_test(bits: list[int], block_size: int = 2) -> tuple[bool, float]:
        """
        Test 3: Serial Test (simplified, block_size=2).
        Check if all 2-bit patterns appear with equal frequency.
        """
        n = len(bits)
        m = block_size
        num_patterns = 2 ** m
        counts = [0] * num_patterns

        for i in range(n - m + 1):
            pattern = 0
            for j in range(m):
                pattern = (pattern << 1) | bits[i + j]
            counts[pattern] += 1

        total = sum(counts)
        expected = total / num_patterns
        # Chi-squared statistic
        chi_sq = sum((c - expected) ** 2 / expected for c in counts if expected > 0)
        df = num_patterns - 1

        # Chi-squared p-value using Wilson-Hilferty approximation
        # For large df, chi^2 approx N(df, 2*df)
        # p-value = P(X > chi_sq) where X ~ chi^2(df)
        p_value = _chi2_p_value(chi_sq, df)
        return (p_value >= 0.01, p_value)


def _chi2_p_value(x: float, k: int) -> float:
    """
    Approximate p-value for chi-squared distribution using the
    regularized upper incomplete gamma function.
    P(X > x) = Q(k/2, x/2) where Q is the regularized upper incomplete gamma.
    Uses a simple series approximation.
    """
    # Use the regularized incomplete gamma function approximation
    # gammainc(a, x) = lower incomplete gamma / Gamma(a)
    a = k / 2.0
    x2 = x / 2.0
    # P(X <= x) = gammainc(a, x/2) — regularized lower incomplete gamma
    lower = _regularized_lower_gamma(a, x2)
    return 1.0 - lower


def _regularized_lower_gamma(a: float, x: float) -> float:
    """
    Regularized lower incomplete gamma function P(a, x).
    Uses series expansion: P(a,x) = e^(-x) * x^a * sum_{n=0}^{inf} x^n / Gamma(a+n+1)
    """
    if x < 0:
        return 0.0
    if x == 0:
        return 0.0

    # Series expansion
    term = 1.0 / a
    total = term
    for n in range(1, 300):
        term *= x / (a + n)
        total += term
        if abs(term) < 1e-15 * abs(total):
            break

    return math.exp(-x + a * math.log(x) - math.lgamma(a + 1)) * total
