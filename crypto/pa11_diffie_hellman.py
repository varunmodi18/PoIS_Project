"""
PA#11 — Diffie-Hellman Key Exchange.

Protocol:
    Public: prime p, generator g of order-q subgroup of Z*_p.
    1. Alice: a ← Z_q, sends A = g^a mod p.
    2. Bob:   b ← Z_q, sends B = g^b mod p.
    3. Both compute K = g^(ab) mod p.

Security: CDH assumption — given g^a and g^b, computing g^(ab) is hard.
Vulnerability: No authentication → MITM attack.

Dependencies:
    - crypto.pa13_miller_rabin (gen_safe_prime, is_prime)
    - crypto.utils (random_int, mod_inverse)
"""

from crypto.pa13_miller_rabin import gen_safe_prime, is_prime
from crypto.utils import random_int


class DHParams:
    """
    Diffie-Hellman group parameters.

    Holds (p, q, g) where:
        - p = 2q + 1 is a safe prime
        - q is prime (subgroup order)
        - g is a generator of the order-q subgroup
    """

    def __init__(self, bits: int = 64):
        self.p, self.q = gen_safe_prime(bits)
        self.g = self._find_generator()

    def _find_generator(self) -> int:
        while True:
            h = random_int(2, self.p - 2)
            g = pow(h, 2, self.p)
            if g != 1:
                assert pow(g, self.q, self.p) == 1
                return g


def dh_alice_step1(params: DHParams) -> tuple:
    """Alice generates (a, A = g^a mod p)."""
    a = random_int(1, params.q - 1)
    A = pow(params.g, a, params.p)
    return a, A


def dh_bob_step1(params: DHParams) -> tuple:
    """Bob generates (b, B = g^b mod p)."""
    b = random_int(1, params.q - 1)
    B = pow(params.g, b, params.p)
    return b, B


def dh_alice_step2(a: int, B: int, params: DHParams) -> int:
    """Alice computes shared secret: K = B^a mod p."""
    return pow(B, a, params.p)


def dh_bob_step2(b: int, A: int, params: DHParams) -> int:
    """Bob computes shared secret: K = A^b mod p."""
    return pow(A, b, params.p)


def dh_full_exchange(params: DHParams) -> dict:
    """Run the full DH exchange."""
    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)
    K_alice = dh_alice_step2(a, B, params)
    K_bob = dh_bob_step2(b, A, params)
    return {
        'a': a, 'A': A, 'b': b, 'B': B,
        'K_alice': K_alice, 'K_bob': K_bob,
        'keys_match': K_alice == K_bob
    }


def mitm_attack_demo(params: DHParams) -> dict:
    """
    Man-in-the-Middle attack demonstration.

    Eve intercepts all communication between Alice and Bob.
    """
    # Alice generates keys
    a, A = dh_alice_step1(params)

    # Eve generates two key pairs (one for each side)
    e1, E1 = random_int(1, params.q - 1), None
    E1 = pow(params.g, e1, params.p)
    e2, E2 = random_int(1, params.q - 1), None
    E2 = pow(params.g, e2, params.p)

    # Bob generates keys (receives E1 from Eve, thinking it's Alice)
    b, B = dh_bob_step1(params)

    # Alice computes shared secret with Eve's E2 (thinking it's Bob's B)
    K_AE = pow(E2, a, params.p)   # Alice thinks she's talking to Bob

    # Bob computes shared secret with Eve's E1 (thinking it's Alice's A)
    K_BE = pow(E1, b, params.p)   # Bob thinks he's talking to Alice

    # Eve computes both shared secrets
    K_AE_eve = pow(A, e2, params.p)   # Eve's key with Alice
    K_BE_eve = pow(B, e1, params.p)   # Eve's key with Bob

    return {
        'alice': {'private': a, 'public': A, 'shared_secret': K_AE},
        'bob': {'private': b, 'public': B, 'shared_secret': K_BE},
        'eve': {
            'e1': e1, 'E1': E1, 'e2': e2, 'E2': E2,
            'K_with_alice': K_AE_eve, 'K_with_bob': K_BE_eve
        },
        'eve_has_alice_key': K_AE_eve == K_AE,
        'eve_has_bob_key': K_BE_eve == K_BE,
        'alice_bob_keys_differ': K_AE != K_BE,
    }


def cdh_hardness_demo(params: DHParams) -> dict:
    """
    Demonstrate CDH hardness for small parameters via Baby-Step-Giant-Step.

    Given only (A = g^a, B = g^b, g, p), recover a using BSGS in O(√q) time.
    Then compute K = B^a.
    """
    import time

    a = random_int(1, params.q - 1)
    b = random_int(1, params.q - 1)
    A = pow(params.g, a, params.p)
    B = pow(params.g, b, params.p)
    K = pow(params.g, a * b, params.p)

    p, g, q = params.p, params.g, params.q

    start = time.time()
    found_secret = False

    # Baby-Step-Giant-Step: find a such that g^a = A (mod p)
    # Set m = ceil(sqrt(q))
    m = int(q ** 0.5) + 1

    # Baby steps: table[g^j mod p] = j for j in 0..m-1
    table = {}
    curr = 1
    for j in range(m):
        table[curr] = j
        curr = (curr * g) % p

    # Giant steps: g^(-m) = g^(q-m) mod p (since g^q = 1)
    g_neg_m = pow(g, q - m, p)
    curr = A
    for i in range(m + 1):
        if curr in table:
            j = table[curr]
            a_found = (i * m + j) % q
            if pow(g, a_found, p) == A:
                K_found = pow(B, a_found, p)
                found_secret = (K_found == K)
                break
        curr = (curr * g_neg_m) % p

    elapsed = time.time() - start
    return {
        'q_bits': q.bit_length(),
        'brute_force_time': elapsed,
        'found_secret': found_secret,
    }
