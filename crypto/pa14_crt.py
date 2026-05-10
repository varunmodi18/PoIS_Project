"""
PA#14 — Chinese Remainder Theorem & Håstad Broadcast Attack.

CRT: Given x ≡ a_i (mod n_i) for pairwise coprime n_i, recover unique x mod ∏n_i.
CRT-RSA: Decrypt using smaller exponentiations mod p and mod q (4x speedup).
Håstad: If same message m encrypted to e recipients with small e, recover m via CRT.

Dependencies:
    - crypto.pa12_rsa (RSAKeyPair, rsa_encrypt_raw, rsa_decrypt_raw, pkcs15_encrypt)
    - crypto.utils (mod_inverse)
"""

from crypto.pa12_rsa import RSAKeyPair, rsa_encrypt_raw, rsa_decrypt_raw, pkcs15_encrypt
from crypto.utils import mod_inverse


def crt(residues: list, moduli: list) -> int:
    """
    Chinese Remainder Theorem solver.

    Given x ≡ a_i (mod n_i), find unique x mod N where N = ∏n_i.
    """
    N = 1
    for m in moduli:
        N *= m

    x = 0
    for a_i, n_i in zip(residues, moduli):
        M_i = N // n_i
        y_i = mod_inverse(M_i, n_i)
        x += a_i * M_i * y_i

    return x % N


def rsa_decrypt_crt(sk: dict, c: int) -> int:
    """
    CRT-based RSA decryption (Garner's Algorithm).

    ~4x faster than standard decryption.
    """
    mp = pow(c, sk['dp'], sk['p'])
    mq = pow(c, sk['dq'], sk['q'])
    h = (sk['q_inv'] * (mp - mq)) % sk['p']
    m = mq + h * sk['q']
    return m


def integer_nth_root(x: int, n: int) -> int:
    """
    Compute the integer n-th root of x: floor(x^(1/n)).

    Uses Newton's method for integer roots.
    """
    if x == 0:
        return 0
    if x == 1:
        return 1

    # Initial guess
    g = 1 << ((x.bit_length() + n - 1) // n)

    while True:
        g_next = ((n - 1) * g + x // (g ** (n - 1))) // n
        if g_next >= g:
            break
        g = g_next

    # Adjust if needed
    while g ** n > x:
        g -= 1
    while (g + 1) ** n <= x:
        g += 1

    return g


def hastad_attack(ciphertexts: list, moduli: list, e: int) -> int:
    """
    Håstad's Broadcast Attack.

    Given c_i = m^e mod N_i, recover m using CRT then nth root.
    """
    # Use CRT to recover m^e mod (N_0 * ... * N_{e-1})
    x = crt(ciphertexts, moduli)
    # Since m < each N_i, m^e < ∏N_i, so x = m^e exactly as integer
    return integer_nth_root(x, e)


def hastad_demo(e: int = 3, bits: int = 512) -> dict:
    """
    Full Håstad attack demonstration.
    """
    # Generate e independent RSA key pairs with public exponent e
    # We need to set e explicitly — use a custom key generation
    class RSAKeyPairWithE:
        def __init__(self, e_val, bits):
            from crypto.pa13_miller_rabin import gen_prime
            from crypto.utils import gcd
            self.e = e_val
            while True:
                self.p = gen_prime(bits // 2)
                self.q = gen_prime(bits // 2)
                while self.q == self.p:
                    self.q = gen_prime(bits // 2)
                self.n = self.p * self.q
                phi_n = (self.p - 1) * (self.q - 1)
                if gcd(self.e, phi_n) == 1:
                    break

        def public_key(self):
            return (self.n, self.e)

    # Small message m that fits in each modulus
    m = 123456789

    keypairs = [RSAKeyPairWithE(e, bits) for _ in range(e)]
    recipients = []
    ciphertexts = []
    moduli = []

    for kp in keypairs:
        c = rsa_encrypt_raw(kp.public_key(), m)
        ciphertexts.append(c)
        moduli.append(kp.n)
        recipients.append({'N': kp.n, 'ciphertext': c})

    recovered = hastad_attack(ciphertexts, moduli, e)

    return {
        'message': m,
        'e': e,
        'recipients': recipients,
        'recovered_message': recovered,
        'attack_succeeded': recovered == m,
    }


def hastad_fails_with_padding_demo(e: int = 3, bits: int = 512) -> dict:
    """
    Show that PKCS#1 v1.5 padding defeats Håstad's attack.
    """
    from crypto.utils import bytes_to_int

    class RSAKeyPairWithE:
        def __init__(self, e_val, bits):
            from crypto.pa13_miller_rabin import gen_prime
            from crypto.utils import gcd
            self.e = e_val
            while True:
                self.p = gen_prime(bits // 2)
                self.q = gen_prime(bits // 2)
                while self.q == self.p:
                    self.q = gen_prime(bits // 2)
                self.n = self.p * self.q
                phi_n = (self.p - 1) * (self.q - 1)
                if gcd(self.e, phi_n) == 1:
                    break
            self.byte_size = (self.n.bit_length() + 7) // 8

        def public_key(self):
            return (self.n, self.e)

    msg = b'Hello RSA!'
    keypairs = [RSAKeyPairWithE(e, bits) for _ in range(e)]
    ciphertexts = []
    moduli = []

    for kp in keypairs:
        # Each recipient gets a DIFFERENT padded message (random PS)
        c = pkcs15_encrypt(kp.public_key(), msg, kp.byte_size)
        ciphertexts.append(c)
        moduli.append(kp.n)

    # CRT gives m^e, but m differs per recipient due to padding
    x = crt(ciphertexts, moduli)
    recovered = integer_nth_root(x, e)

    # Verify it's NOT the original message
    attack_succeeded = False
    try:
        recovered_bytes = recovered.to_bytes((recovered.bit_length() + 7) // 8, 'big')
        attack_succeeded = (recovered_bytes == msg)
    except Exception:
        pass

    return {
        'attack_succeeded': attack_succeeded,
        'explanation': (
            "PKCS#1 v1.5 adds random padding to each encryption, so each "
            "recipient receives a DIFFERENT padded message. The CRT recovers "
            "the CRT of the padded messages, not m^e, so the cube root is "
            "not m. Padding defeats Håstad's attack."
        ),
    }


def crt_rsa_performance_comparison(bits: int = 1024, num_trials: int = 100) -> dict:
    """
    Benchmark standard vs CRT RSA decryption.
    """
    import time
    from crypto.utils import random_int

    kp = RSAKeyPair(bits=bits)
    # Generate test ciphertexts
    test_messages = [random_int(0, kp.n - 1) for _ in range(num_trials)]
    ciphertexts = [rsa_encrypt_raw(kp.public_key(), m) for m in test_messages]
    sk = kp.private_key()

    # Time standard decryption
    start = time.perf_counter()
    std_results = [rsa_decrypt_raw(sk, c) for c in ciphertexts]
    standard_time = time.perf_counter() - start

    # Time CRT decryption
    start = time.perf_counter()
    crt_results = [rsa_decrypt_crt(sk, c) for c in ciphertexts]
    crt_time = time.perf_counter() - start

    results_match = all(s == c for s, c in zip(std_results, crt_results))
    speedup = standard_time / crt_time if crt_time > 0 else float('inf')

    return {
        'standard_time': standard_time,
        'crt_time': crt_time,
        'speedup': speedup,
        'results_match': results_match,
    }
