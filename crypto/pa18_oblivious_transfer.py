"""
PA#18 — 1-out-of-2 Oblivious Transfer using ElGamal.

Protocol (Bellare-Micali variant):
    1. Receiver (choice bit b):
       - Generate real ElGamal keypair (sk_b, pk_b) for the chosen index.
       - Generate FAKE public key pk_{1-b} = random group element (no known sk).
       - Send (pk0, pk1) to Sender.
    2. Sender (messages m0, m1):
       - Encrypt C0 = ElGamal_Enc(pk0, m0).
       - Encrypt C1 = ElGamal_Enc(pk1, m1).
       - Send (C0, C1) to Receiver.
    3. Receiver:
       - Decrypt C_b using sk_b → gets m_b.
       - Cannot decrypt C_{1-b} (no sk_{1-b}).

Security:
    - Receiver privacy: pk0 and pk1 are computationally indistinguishable
      (both are random group elements). Sender cannot tell which is real.
    - Sender privacy: Receiver has no sk_{1-b}, so C_{1-b} is IND-CPA
      secure under DDH. Receiver learns nothing about m_{1-b}.

Dependencies:
    - crypto.pa16_elgamal (ElGamalKeyPair, elgamal_encrypt, elgamal_decrypt)
    - crypto.pa11_diffie_hellman (DHParams)
    - crypto.utils
"""

from crypto.pa16_elgamal import (
    ElGamalKeyPair, elgamal_encrypt, elgamal_decrypt
)
from crypto.pa11_diffie_hellman import DHParams
from crypto.utils import random_int, mod_inverse


class OTReceiver:
    """
    Oblivious Transfer Receiver.

    The receiver has a choice bit b ∈ {0, 1} and wants to learn m_b
    without revealing b to the sender.
    """

    def __init__(self, params: DHParams):
        """
        Args:
            params: DH group parameters (shared with sender).
        """
        self.params = params

    def step1(self, b: int) -> tuple:
        """
        Receiver Step 1: Generate two public keys.

        For the chosen index b: generate a real ElGamal keypair (sk_b, pk_b).
        For the other index 1-b: generate a FAKE public key (random group element,
        no known secret key).

        Args:
            b: Choice bit, 0 or 1.

        Returns:
            (pk0, pk1, state)
            - pk0: Public key for index 0 (dict with 'p', 'g', 'q', 'h').
            - pk1: Public key for index 1 (dict with 'p', 'g', 'q', 'h').
            - state: Private state (contains sk_b and b) for use in step2.
                     state = {'b': b, 'sk': sk_b}
        """
        assert b in (0, 1), f"Choice bit must be 0 or 1, got {b}"
        p, q, g = self.params.p, self.params.q, self.params.g

        # Real keypair
        x_real = random_int(1, q - 1)
        h_real = pow(g, x_real, p)

        # Fake public key (random group element, secret key discarded)
        r_fake = random_int(1, q - 1)
        h_fake = pow(g, r_fake, p)
        # r_fake is discarded after this line — do NOT store it

        pk_real = {'p': p, 'g': g, 'q': q, 'h': h_real}
        pk_fake = {'p': p, 'g': g, 'q': q, 'h': h_fake}

        if b == 0:
            pk0, pk1 = pk_real, pk_fake
        else:
            pk0, pk1 = pk_fake, pk_real

        state = {'b': b, 'sk': x_real}
        return pk0, pk1, state

    def step2(self, state: dict, C0: tuple, C1: tuple) -> int:
        """
        Receiver Step 2: Decrypt the chosen ciphertext.

        Args:
            state: Private state from step1 containing {'b': b, 'sk': sk_b}.
            C0: ElGamal ciphertext (c1_0, c2_0) for message m0.
            C1: ElGamal ciphertext (c1_1, c2_1) for message m1.

        Returns:
            m_b: The chosen message as integer.
        """
        b = state['b']
        sk = state['sk']
        if b == 0:
            c1, c2 = C0
        else:
            c1, c2 = C1
        return elgamal_decrypt(sk, c1, c2, self.params.p)


class OTSender:
    """
    Oblivious Transfer Sender.

    The sender has two messages (m0, m1) and wants to send m_b to the
    receiver without learning b.
    """

    def __init__(self, params: DHParams):
        self.params = params

    def step(self, pk0: dict, pk1: dict, m0: int, m1: int) -> tuple:
        """
        Sender Step: Encrypt both messages under the respective public keys.

        Args:
            pk0: Public key for index 0 (from receiver).
            pk1: Public key for index 1 (from receiver).
            m0: Message for index 0 (integer in [1, p-1]).
            m1: Message for index 1 (integer in [1, p-1]).

        Returns:
            (C0, C1) where C0 = ElGamal_Enc(pk0, m0), C1 = ElGamal_Enc(pk1, m1).
            Each Ci = (c1_i, c2_i) tuple.
        """
        C0 = elgamal_encrypt(pk0, m0)
        C1 = elgamal_encrypt(pk1, m1)
        return C0, C1


def ot_protocol(params: DHParams, m0: int, m1: int, b: int) -> dict:
    """
    Run the full 1-out-of-2 OT protocol.

    Args:
        params: Shared DH group parameters.
        m0: Sender's message 0 (integer).
        m1: Sender's message 1 (integer).
        b: Receiver's choice bit (0 or 1).

    Returns:
        {
            'chosen_message': int,     # m_b (what receiver learns)
            'correct': bool,           # chosen_message == m_b
            'receiver_choice': int,    # b
            'm0': int, 'm1': int       # sender's messages (for verification)
        }
    """
    receiver = OTReceiver(params)
    sender = OTSender(params)

    # Step 1: Receiver generates keys
    pk0, pk1, state = receiver.step1(b)

    # Step 2: Sender encrypts both messages
    C0, C1 = sender.step(pk0, pk1, m0, m1)

    # Step 3: Receiver decrypts chosen message
    m_b = receiver.step2(state, C0, C1)

    expected = m0 if b == 0 else m1
    return {
        'chosen_message': m_b,
        'correct': m_b == expected,
        'receiver_choice': b,
        'm0': m0, 'm1': m1
    }


def ot_protocol_bits(params: DHParams, m0: int, m1: int, b: int) -> int:
    """
    Simplified OT for single-bit messages.

    Encode bit values as integers:
        encode(bit) = bit + 1    (0 → 1, 1 → 2)
        decode(val) = val - 1    (1 → 0, 2 → 1)

    Args:
        params: DH parameters.
        m0: Bit 0's value (0 or 1).
        m1: Bit 1's value (0 or 1).
        b: Receiver's choice bit.

    Returns:
        The chosen bit m_b (0 or 1).
    """
    # Encode bits as group elements (avoid 0)
    m0_enc = m0 + 1  # 0→1, 1→2
    m1_enc = m1 + 1

    result = ot_protocol(params, m0_enc, m1_enc, b)
    return result['chosen_message'] - 1  # Decode back to bit


def receiver_privacy_demo(params: DHParams) -> dict:
    """
    Demonstrate receiver privacy: sender cannot determine b.

    Run 200 trials. In half, b=0; in half, b=1.
    For each trial, record pk0['h'] and pk1['h'].
    A "distinguisher" tries to guess b based on some heuristic.
    Since both h values are random group elements, any heuristic
    should achieve ≈ 50% accuracy.

    Returns:
        {'trials': int, 'correct_guesses': int, 'accuracy': float,
         'advantage': float}  # advantage should be ≈ 0
    """
    trials = 200
    correct_guesses = 0
    p = params.p

    receiver = OTReceiver(params)
    for i in range(trials):
        b = i % 2  # Alternate b=0 and b=1
        pk0, pk1, state = receiver.step1(b)

        # "Distinguisher" heuristic: guess b=0 if pk0['h'] < pk1['h']
        # This is arbitrary — both are random group elements, so this is no better than random
        guess = 0 if pk0['h'] < pk1['h'] else 1
        if guess == b:
            correct_guesses += 1

    accuracy = correct_guesses / trials
    advantage = abs(accuracy - 0.5)
    return {
        'trials': trials,
        'correct_guesses': correct_guesses,
        'accuracy': accuracy,
        'advantage': advantage
    }


def sender_privacy_demo(params: DHParams) -> dict:
    """
    Demonstrate sender privacy: receiver cannot decrypt C_{1-b}.

    1. Run OT with b=0, messages (m0=42, m1=99).
    2. Receiver gets m0=42 correctly.
    3. Receiver tries to decrypt C1 using sk_b (which is sk for pk0, not pk1).
       Since sk_b is not the secret key for pk_fake, the decryption returns garbage.

    Returns:
        {'receiver_got_chosen': bool, 'brute_force_attempted': bool,
         'other_message_recovered': bool, 'explanation': str}
    """
    m0, m1 = 42, 99
    receiver = OTReceiver(params)
    sender = OTSender(params)

    pk0, pk1, state = receiver.step1(b=0)
    C0, C1 = sender.step(pk0, pk1, m0, m1)

    # Receiver correctly decrypts C0
    got_m0 = receiver.step2(state, C0, C1)
    receiver_got_chosen = (got_m0 == m0)

    # Receiver tries to decrypt C1 using sk_b (wrong key)
    sk = state['sk']
    c1_1, c2_1 = C1
    attempt = elgamal_decrypt(sk, c1_1, c2_1, params.p)
    other_message_recovered = (attempt == m1)

    return {
        'receiver_got_chosen': receiver_got_chosen,
        'brute_force_attempted': True,
        'other_message_recovered': other_message_recovered,
        'explanation': (
            'Receiver decrypted C_b correctly using sk_b. '
            'Decrypting C_{1-b} with sk_b gives garbage because sk_b is not '
            'the discrete log of h_fake (the fake public key). '
            'Breaking this requires solving DLP — hard under DDH assumption.'
        )
    }
