"""
Tests for PA#18 — Oblivious Transfer.
"""


class TestOTCorrectness:
    """Core correctness: receiver always gets the chosen message."""

    def test_ot_choice_0(self):
        """Receiver chooses b=0, should get m0."""
        from crypto.pa18_oblivious_transfer import ot_protocol
        from crypto.pa11_diffie_hellman import DHParams
        from crypto.utils import random_int
        params = DHParams(bits=64)
        m0 = random_int(1, params.p - 1)
        m1 = random_int(1, params.p - 1)
        result = ot_protocol(params, m0, m1, b=0)
        assert result['correct'], f"Got {result['chosen_message']}, expected m0={m0}"
        assert result['chosen_message'] == m0

    def test_ot_choice_1(self):
        """Receiver chooses b=1, should get m1."""
        from crypto.pa18_oblivious_transfer import ot_protocol
        from crypto.pa11_diffie_hellman import DHParams
        from crypto.utils import random_int
        params = DHParams(bits=64)
        m0 = random_int(1, params.p - 1)
        m1 = random_int(1, params.p - 1)
        result = ot_protocol(params, m0, m1, b=1)
        assert result['correct'], f"Got {result['chosen_message']}, expected m1={m1}"
        assert result['chosen_message'] == m1

    def test_ot_100_trials(self):
        """Run 100 OT trials with random b, m0, m1. All must be correct."""
        from crypto.pa18_oblivious_transfer import ot_protocol
        from crypto.pa11_diffie_hellman import DHParams
        from crypto.utils import random_int
        params = DHParams(bits=64)
        for _ in range(100):
            m0 = random_int(1, params.p - 1)
            m1 = random_int(1, params.p - 1)
            b = random_int(0, 1)
            result = ot_protocol(params, m0, m1, b)
            assert result['correct'], f"OT failed for b={b}, m0={m0}, m1={m1}"

    def test_ot_bits(self):
        """OT for single-bit messages (used by PA#19)."""
        from crypto.pa18_oblivious_transfer import ot_protocol_bits
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        # All 8 combinations of (m0, m1, b)
        for m0 in [0, 1]:
            for m1 in [0, 1]:
                for b in [0, 1]:
                    result = ot_protocol_bits(params, m0, m1, b)
                    expected = m0 if b == 0 else m1
                    assert result == expected, \
                        f"ot_bits(m0={m0}, m1={m1}, b={b}) = {result}, expected {expected}"


class TestOTStepByStep:
    """Test each protocol step individually."""

    def test_step1_generates_two_keys(self):
        from crypto.pa18_oblivious_transfer import OTReceiver
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        receiver = OTReceiver(params)
        pk0, pk1, state = receiver.step1(b=0)
        assert 'h' in pk0 and 'h' in pk1
        assert pk0['h'] != pk1['h']  # Different keys (with overwhelming prob)
        assert state['b'] == 0
        assert 'sk' in state

    def test_step1_both_keys_in_subgroup(self):
        """Both public keys must be valid group elements."""
        from crypto.pa18_oblivious_transfer import OTReceiver
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        receiver = OTReceiver(params)
        pk0, pk1, state = receiver.step1(b=1)
        # Both h values should be in the order-q subgroup
        assert pow(pk0['h'], params.q, params.p) == 1
        assert pow(pk1['h'], params.q, params.p) == 1

    def test_sender_step(self):
        from crypto.pa18_oblivious_transfer import OTReceiver, OTSender
        from crypto.pa11_diffie_hellman import DHParams
        from crypto.utils import random_int
        params = DHParams(bits=64)
        receiver = OTReceiver(params)
        sender = OTSender(params)
        pk0, pk1, state = receiver.step1(b=0)
        m0 = random_int(1, params.p - 1)
        m1 = random_int(1, params.p - 1)
        C0, C1 = sender.step(pk0, pk1, m0, m1)
        assert len(C0) == 2 and len(C1) == 2  # Each is (c1, c2) tuple

    def test_receiver_step2(self):
        from crypto.pa18_oblivious_transfer import OTReceiver, OTSender
        from crypto.pa11_diffie_hellman import DHParams
        from crypto.utils import random_int
        params = DHParams(bits=64)
        receiver = OTReceiver(params)
        sender = OTSender(params)
        m0, m1 = 42, 99
        pk0, pk1, state = receiver.step1(b=0)
        C0, C1 = sender.step(pk0, pk1, m0, m1)
        result = receiver.step2(state, C0, C1)
        assert result == m0  # b=0, so should get m0


class TestOTSecurity:
    """OT security property tests."""

    def test_receiver_privacy(self):
        """Sender cannot determine b from (pk0, pk1)."""
        from crypto.pa18_oblivious_transfer import receiver_privacy_demo
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        result = receiver_privacy_demo(params)
        assert result['advantage'] < 0.15, \
            f"Receiver privacy violated: advantage = {result['advantage']}"

    def test_sender_privacy(self):
        """Receiver cannot learn m_{1-b}."""
        from crypto.pa18_oblivious_transfer import sender_privacy_demo
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        result = sender_privacy_demo(params)
        assert result['receiver_got_chosen']
        assert not result['other_message_recovered']

    def test_receiver_cannot_cheat(self):
        """
        If receiver tries to generate BOTH real keypairs (knowing both sk0 and sk1),
        the protocol still works but this violates the OT model.
        In a real implementation, we'd use a commitment scheme to prevent this.

        For this test: just verify that a receiver who honestly follows the
        protocol cannot recover both messages.
        """
        from crypto.pa18_oblivious_transfer import OTReceiver, OTSender
        from crypto.pa11_diffie_hellman import DHParams
        params = DHParams(bits=64)
        receiver = OTReceiver(params)
        sender = OTSender(params)
        m0, m1 = 42, 99
        pk0, pk1, state = receiver.step1(b=0)
        C0, C1 = sender.step(pk0, pk1, m0, m1)
        # Receiver can decrypt C0 (b=0)
        got_m0 = receiver.step2(state, C0, C1)
        assert got_m0 == m0
        # Receiver tries to decrypt C1 with the same sk — should get garbage
        from crypto.pa16_elgamal import elgamal_decrypt
        c1_1, c2_1 = C1
        attempt = elgamal_decrypt(state['sk'], c1_1, c2_1, params.p)
        assert attempt != m1, "Receiver should NOT be able to recover m_{1-b}"
