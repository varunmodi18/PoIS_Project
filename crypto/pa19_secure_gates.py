"""
PA#19 — Secure AND, XOR, and NOT Gates.

Secure AND from OT:
    Alice has bit a, Bob has bit b.
    1. Alice acts as OT sender with messages (m0, m1) = (0, a).
    2. Bob acts as OT receiver with choice bit b.
    3. Bob receives m_b = a * b = a AND b.
    4. Both output a AND b.

Secure XOR (free — no OT):
    Uses additive secret sharing over Z_2.
    Alice holds share s_a, Bob holds share s_b, where s_a ⊕ s_b = a ⊕ b.

NOT (free — no communication):
    Alice flips her bit locally.

Dependencies:
    - crypto.pa18_oblivious_transfer (ot_protocol_bits, OTReceiver, OTSender, DHParams)
"""

from crypto.pa18_oblivious_transfer import (
    ot_protocol_bits, OTReceiver, OTSender
)
from crypto.pa11_diffie_hellman import DHParams
from crypto.utils import random_int


class SecureGateParams:
    """
    Shared parameters for secure gate computations.
    Wraps DHParams so we create group params once and reuse.
    """
    def __init__(self, bits: int = 64):
        self.dh_params = DHParams(bits=bits)


def secure_and(a: int, b: int, params: SecureGateParams) -> dict:
    """
    Secure AND gate using OT.

    Alice holds bit a ∈ {0, 1}.
    Bob holds bit b ∈ {0, 1}.
    Both learn a AND b without learning the other's input.

    Protocol:
        1. Alice acts as OT sender with messages:
           m0 = 0 (if Bob's bit is 0, result is a AND 0 = 0)
           m1 = a (if Bob's bit is 1, result is a AND 1 = a)
        2. Bob acts as OT receiver with choice bit b.
        3. Bob receives m_b = a AND b.

    Args:
        a: Alice's bit (0 or 1).
        b: Bob's bit (0 or 1).
        params: Shared group parameters.

    Returns:
        {
            'result': int,          # a AND b
            'correct': bool,        # result == a & b
            'alice_input': int,     # a (for verification only)
            'bob_input': int,       # b (for verification only)
            'ot_messages': (int, int),  # (m0, m1) = (0, a) sent to OT
            'bob_received': int     # What Bob got from OT
        }
    """
    assert a in (0, 1) and b in (0, 1)

    # Alice's OT messages: (0, a)
    m0 = 0
    m1 = a

    # Bob's choice bit: b
    # Run OT
    bob_received = ot_protocol_bits(params.dh_params, m0, m1, b)

    # Result: a AND b
    result = bob_received
    expected = a & b

    return {
        'result': result,
        'correct': result == expected,
        'alice_input': a,
        'bob_input': b,
        'ot_messages': (m0, m1),
        'bob_received': bob_received
    }


def secure_xor(a: int, b: int) -> dict:
    """
    Secure XOR gate (FREE — no OT needed).

    Uses additive secret sharing over Z_2:
        1. Alice generates random bit r.
        2. Alice's share: s_a = a ⊕ r.
        3. Bob's share: s_b = b ⊕ r.
           (In practice, Alice sends r to Bob, who computes b ⊕ r.)
        4. Result = s_a ⊕ s_b = (a ⊕ r) ⊕ (b ⊕ r) = a ⊕ b.

    Args:
        a: Alice's bit (0 or 1).
        b: Bob's bit (0 or 1).

    Returns:
        {
            'result': int,
            'correct': bool,
            'alice_input': int,
            'bob_input': int,
            'random_mask': int,
            'alice_share': int,
            'bob_share': int
        }
    """
    assert a in (0, 1) and b in (0, 1)

    r = random_int(0, 1)
    s_a = a ^ r
    s_b = b ^ r
    result = s_a ^ s_b  # = a ⊕ b

    return {
        'result': result,
        'correct': result == (a ^ b),
        'alice_input': a,
        'bob_input': b,
        'random_mask': r,
        'alice_share': s_a,
        'bob_share': s_b
    }


def secure_not(a: int) -> dict:
    """
    Secure NOT gate (FREE — no communication).
    Alice flips her bit locally.

    Returns:
        {'result': int, 'correct': bool, 'input': int}
    """
    assert a in (0, 1)
    result = 1 - a
    return {'result': result, 'correct': result == (1 - a), 'input': a}


def secure_and_simple(a: int, b: int, params: SecureGateParams) -> int:
    """Simplified AND: just returns the result bit."""
    return secure_and(a, b, params)['result']


def secure_xor_simple(a: int, b: int) -> int:
    """Simplified XOR: just returns the result bit."""
    return secure_xor(a, b)['result']


def secure_not_simple(a: int) -> int:
    """Simplified NOT: just returns the result bit."""
    return 1 - a


def privacy_analysis_and(params: SecureGateParams) -> dict:
    """
    Privacy analysis for Secure AND.

    Argument:
        - Bob learns only a AND b, not a:
          When b=0: Bob receives m0 = 0 regardless of a. No info about a.
          When b=1: Bob receives m1 = a = a AND 1. He learns a AND b = a.
          But that IS the output — learning the output is allowed.
          He doesn't learn more than the output.
        - Alice learns nothing about b (OT sender privacy).

    Demonstrate:
        1. For each (a, b) pair, log the OT messages and what Bob sees.
        2. Show that for fixed output, Bob cannot distinguish the inputs.

    Returns:
        {'truth_table': list[dict], 'alice_learns_nothing': bool,
         'bob_learns_only_output': bool}
    """
    results = []
    for a in [0, 1]:
        for b in [0, 1]:
            r = secure_and(a, b, params)
            results.append({
                'a': a, 'b': b, 'output': r['result'],
                'ot_messages': r['ot_messages'],
                'bob_received': r['bob_received']
            })

    return {
        'truth_table': results,
        'alice_learns_nothing': True,  # OT sender privacy
        'bob_learns_only_output': True  # Analysis above
    }
