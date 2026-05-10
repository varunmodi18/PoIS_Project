"""
PA#20 — All 2-Party Secure Computation.

Given Secure AND (PA#19) and Secure XOR (free), we can securely evaluate
any boolean circuit. AND + XOR form a functionally complete basis (with NOT).

This module implements:
    1. Boolean circuit representation (DAG of gates).
    2. Secure circuit evaluation using PA#19 gates.
    3. Three mandatory circuits: comparison, equality, addition.

Dependencies:
    - crypto.pa19_secure_gates (secure_and_simple, secure_xor_simple, secure_not_simple, SecureGateParams)
    - crypto.pa18_oblivious_transfer (implicitly, via PA#19)
"""

from crypto.pa19_secure_gates import (
    secure_and_simple, secure_xor_simple, secure_not_simple,
    SecureGateParams
)
from crypto.utils import random_int


# ============================================================
# Boolean Circuit Representation
# ============================================================

class Gate:
    """
    A single gate in a boolean circuit.

    Attributes:
        gate_type: 'AND', 'XOR', or 'NOT'.
        input_wires: List of wire indices that feed into this gate.
                     AND and XOR have 2 inputs. NOT has 1 input.
        output_wire: Wire index for the output.
    """
    def __init__(self, gate_type: str, input_wires: list, output_wire: int):
        assert gate_type in ('AND', 'XOR', 'NOT')
        if gate_type == 'NOT':
            assert len(input_wires) == 1
        else:
            assert len(input_wires) == 2
        self.gate_type = gate_type
        self.input_wires = input_wires
        self.output_wire = output_wire

    def __repr__(self):
        return f"Gate({self.gate_type}, in={self.input_wires}, out={self.output_wire})"


class BooleanCircuit:
    """
    A boolean circuit represented as a DAG of gates.

    Wire numbering convention:
        - Wires 0 to n_alice_inputs-1: Alice's input bits.
        - Wires n_alice_inputs to n_alice_inputs+n_bob_inputs-1: Bob's input bits.
        - Remaining wires: intermediate and output wires.
        - Output wires: the last n_outputs wires.
    """

    def __init__(self, n_alice_inputs: int, n_bob_inputs: int,
                 n_outputs: int, gates: list, total_wires: int):
        self.n_alice_inputs = n_alice_inputs
        self.n_bob_inputs = n_bob_inputs
        self.n_outputs = n_outputs
        self.gates = gates
        self.total_wires = total_wires

    def evaluate_plaintext(self, alice_bits: list, bob_bits: list) -> list:
        """
        Evaluate the circuit on plaintext inputs (no security, for testing).

        Args:
            alice_bits: Alice's input bits [a0, a1, ...].
            bob_bits: Bob's input bits [b0, b1, ...].

        Returns:
            Output bits.
        """
        assert len(alice_bits) == self.n_alice_inputs
        assert len(bob_bits) == self.n_bob_inputs

        wires = [0] * self.total_wires
        for i, bit in enumerate(alice_bits):
            wires[i] = bit
        for i, bit in enumerate(bob_bits):
            wires[self.n_alice_inputs + i] = bit

        for gate in self.gates:
            if gate.gate_type == 'AND':
                wires[gate.output_wire] = wires[gate.input_wires[0]] & wires[gate.input_wires[1]]
            elif gate.gate_type == 'XOR':
                wires[gate.output_wire] = wires[gate.input_wires[0]] ^ wires[gate.input_wires[1]]
            elif gate.gate_type == 'NOT':
                wires[gate.output_wire] = 1 - wires[gate.input_wires[0]]

        output_start = self.total_wires - self.n_outputs
        return wires[output_start:]


def secure_evaluate(circuit: BooleanCircuit, alice_bits: list,
                    bob_bits: list, params: SecureGateParams) -> dict:
    """
    Securely evaluate a boolean circuit.

    Uses PA#19's secure gates: AND gates use OT, XOR and NOT are free.

    Args:
        circuit: BooleanCircuit to evaluate.
        alice_bits: Alice's private input bits.
        bob_bits: Bob's private input bits.
        params: Shared secure gate parameters.

    Returns:
        {
            'output': list[int],          # Circuit output bits
            'gates_evaluated': int,       # Total gates processed
            'and_gates': int,             # Number of AND gates (= OT calls)
            'xor_gates': int,             # Number of XOR gates (free)
            'not_gates': int,             # Number of NOT gates (free)
            'correct': bool               # Matches plaintext evaluation
        }
    """
    assert len(alice_bits) == circuit.n_alice_inputs
    assert len(bob_bits) == circuit.n_bob_inputs

    wires = [0] * circuit.total_wires
    for i, bit in enumerate(alice_bits):
        wires[i] = bit
    for i, bit in enumerate(bob_bits):
        wires[circuit.n_alice_inputs + i] = bit

    and_count = 0
    xor_count = 0
    not_count = 0

    for gate in circuit.gates:
        if gate.gate_type == 'AND':
            wires[gate.output_wire] = secure_and_simple(
                wires[gate.input_wires[0]], wires[gate.input_wires[1]], params
            )
            and_count += 1
        elif gate.gate_type == 'XOR':
            wires[gate.output_wire] = secure_xor_simple(
                wires[gate.input_wires[0]], wires[gate.input_wires[1]]
            )
            xor_count += 1
        elif gate.gate_type == 'NOT':
            wires[gate.output_wire] = secure_not_simple(
                wires[gate.input_wires[0]]
            )
            not_count += 1

    output_start = circuit.total_wires - circuit.n_outputs
    output = wires[output_start:]

    expected = circuit.evaluate_plaintext(alice_bits, bob_bits)

    return {
        'output': output,
        'gates_evaluated': and_count + xor_count + not_count,
        'and_gates': and_count,
        'xor_gates': xor_count,
        'not_gates': not_count,
        'correct': output == expected
    }


# ============================================================
# Circuit Builders
# ============================================================

def build_comparison_circuit(n_bits: int) -> BooleanCircuit:
    """
    Build a circuit for the Millionaire's Problem: compute x > y.

    Alice has n-bit integer x, Bob has n-bit integer y.
    Output: 1 if x > y, 0 otherwise.

    Wire layout:
        Wires 0..n-1:   Alice's bits (x), MSB first. Wire 0 = x[n-1] (MSB).
        Wires n..2n-1:   Bob's bits (y), MSB first. Wire n = y[n-1] (MSB).
        Remaining:       Intermediate and output wires.
        Last wire:       Output (1 if x > y).

    Algorithm for x > y (bit-serial comparison, MSB to LSB):
        At each bit position i (MSB first):
            gt_i = gt_{i-1} OR (eq_{i-1} AND x_i AND NOT y_i)
            eq_i = eq_{i-1} AND NOT(x_i XOR y_i)

        Start: gt_{-1} = 0, eq_{-1} = 1.
        Final: output = gt_{n-1}.

        OR(a, b) = (a XOR b) XOR (a AND b)
    """
    gates = []
    wire_counter = 2 * n_bits  # First free wire after inputs

    def new_wire():
        nonlocal wire_counter
        w = wire_counter
        wire_counter += 1
        return w

    def add_gate(gate_type, inputs):
        out = new_wire()
        gates.append(Gate(gate_type, inputs, out))
        return out

    def or_gate(a_wire, b_wire):
        """OR(a, b) = (a XOR b) XOR (a AND b)."""
        xor_ab = add_gate('XOR', [a_wire, b_wire])
        and_ab = add_gate('AND', [a_wire, b_wire])
        return add_gate('XOR', [xor_ab, and_ab])

    # Initial state
    # zero_wire: constant 0 (x_0 XOR x_0 = 0)
    # one_wire: constant 1 (NOT 0)
    zero_wire = add_gate('XOR', [0, 0])  # Always 0
    one_wire = add_gate('NOT', [zero_wire])  # Always 1

    gt_prev = zero_wire
    eq_prev = one_wire

    for i in range(n_bits):
        x_i = i               # Alice's bit i (MSB first)
        y_i = n_bits + i       # Bob's bit i (MSB first)

        # xor_i = x_i XOR y_i
        xor_i = add_gate('XOR', [x_i, y_i])

        # not_xor_i = NOT(xor_i) = (x_i XNOR y_i) = bits are equal
        not_xor_i = add_gate('NOT', [xor_i])

        # not_y_i = NOT(y_i)
        not_y_i = add_gate('NOT', [y_i])

        # x_gt_y_at_i = x_i AND NOT(y_i) — x has 1 where y has 0
        x_gt_y_at_i = add_gate('AND', [x_i, not_y_i])

        # gt_contrib = eq_prev AND x_gt_y_at_i
        gt_contrib = add_gate('AND', [eq_prev, x_gt_y_at_i])

        # gt_new = gt_prev OR gt_contrib
        gt_new = or_gate(gt_prev, gt_contrib)

        # eq_new = eq_prev AND not_xor_i
        eq_new = add_gate('AND', [eq_prev, not_xor_i])

        gt_prev = gt_new
        eq_prev = eq_new

    # Output is gt_prev (1 if x > y)
    # Ensure output is the last wire
    output_wire = gt_prev

    total_wires = wire_counter
    n_outputs = 1

    # If output_wire is not already the last wire, copy it to the end
    if output_wire != total_wires - 1:
        zero2 = add_gate('XOR', [0, 0])
        final_out = add_gate('XOR', [output_wire, zero2])
        total_wires = wire_counter
    else:
        final_out = output_wire
        total_wires = wire_counter

    return BooleanCircuit(
        n_alice_inputs=n_bits,
        n_bob_inputs=n_bits,
        n_outputs=1,
        gates=gates,
        total_wires=total_wires
    )


def build_equality_circuit(n_bits: int) -> BooleanCircuit:
    """
    Build a circuit for secure equality test: compute x == y.

    x == y iff all bits are equal: (x_0 XNOR y_0) AND (x_1 XNOR y_1) AND ...

    Algorithm:
        1. For each bit i: eq_i = NOT(x_i XOR y_i) = x_i XNOR y_i.
        2. result = eq_0 AND eq_1 AND ... AND eq_{n-1}.
    """
    gates = []
    wire_counter = 2 * n_bits

    def new_wire():
        nonlocal wire_counter
        w = wire_counter
        wire_counter += 1
        return w

    def add_gate(gate_type, inputs):
        out = new_wire()
        gates.append(Gate(gate_type, inputs, out))
        return out

    # Compute XNOR for each bit
    eq_bits = []
    for i in range(n_bits):
        x_i = i
        y_i = n_bits + i
        xor_i = add_gate('XOR', [x_i, y_i])
        xnor_i = add_gate('NOT', [xor_i])
        eq_bits.append(xnor_i)

    # AND all eq_bits together
    if len(eq_bits) == 1:
        result = eq_bits[0]
    else:
        result = eq_bits[0]
        for i in range(1, len(eq_bits)):
            result = add_gate('AND', [result, eq_bits[i]])

    total_wires = wire_counter
    return BooleanCircuit(
        n_alice_inputs=n_bits,
        n_bob_inputs=n_bits,
        n_outputs=1,
        gates=gates,
        total_wires=total_wires
    )


def build_addition_circuit(n_bits: int) -> BooleanCircuit:
    """
    Build a circuit for n-bit addition: compute (x + y) mod 2^n.

    Uses a ripple-carry adder:
        For each bit i (LSB first):
            sum_i = x_i XOR y_i XOR carry_i
            carry_{i+1} = (x_i AND y_i) OR (carry_i AND (x_i XOR y_i))

        carry_0 = 0.
        Output: [sum_0, sum_1, ..., sum_{n-1}] (n bits, ignoring final carry).

    IMPORTANT: Input bits are MSB first (wire 0 = MSB), but addition is LSB first.
    So bit i (in addition order, LSB=0) corresponds to:
        x: wire (n_bits - 1 - i)
        y: wire (2*n_bits - 1 - i)

    OR(a, b) = (a XOR b) XOR (a AND b).
    """
    gates = []
    wire_counter = 2 * n_bits

    def new_wire():
        nonlocal wire_counter
        w = wire_counter
        wire_counter += 1
        return w

    def add_gate(gate_type, inputs):
        out = new_wire()
        gates.append(Gate(gate_type, inputs, out))
        return out

    def or_gate(a_wire, b_wire):
        xor_ab = add_gate('XOR', [a_wire, b_wire])
        and_ab = add_gate('AND', [a_wire, b_wire])
        return add_gate('XOR', [xor_ab, and_ab])

    # Constant 0 for initial carry
    zero_wire = add_gate('XOR', [0, 0])
    carry = zero_wire

    sum_wires = []  # Will collect sum bits in LSB-first order

    for i in range(n_bits):
        # Bit i in addition order (LSB first)
        # Maps to: x_bit = wire (n_bits - 1 - i), y_bit = wire (2*n_bits - 1 - i)
        x_i = n_bits - 1 - i
        y_i = 2 * n_bits - 1 - i

        # sum_i = x_i XOR y_i XOR carry
        xor_xy = add_gate('XOR', [x_i, y_i])
        sum_i = add_gate('XOR', [xor_xy, carry])
        sum_wires.append(sum_i)

        # carry_{i+1} = (x_i AND y_i) OR (carry AND (x_i XOR y_i))
        and_xy = add_gate('AND', [x_i, y_i])
        and_carry_xor = add_gate('AND', [carry, xor_xy])
        carry = or_gate(and_xy, and_carry_xor)

    # sum_wires is in LSB-first order. Reverse to MSB-first for output.
    sum_wires_msb_first = list(reversed(sum_wires))

    # Copy output wires to the end of the wire array.
    # Use a single zero wire so output wires are contiguous at the end.
    zero_final = add_gate('XOR', [0, 0])
    output_wires = []
    for sw in sum_wires_msb_first:
        out = add_gate('XOR', [sw, zero_final])
        output_wires.append(out)

    total_wires = wire_counter
    return BooleanCircuit(
        n_alice_inputs=n_bits,
        n_bob_inputs=n_bits,
        n_outputs=n_bits,
        gates=gates,
        total_wires=total_wires
    )


# ============================================================
# Helper functions
# ============================================================

def int_to_bits(value: int, n_bits: int) -> list:
    """Convert integer to list of bits (MSB first)."""
    bits = []
    for i in range(n_bits - 1, -1, -1):
        bits.append((value >> i) & 1)
    return bits


def bits_to_int(bits: list) -> int:
    """Convert list of bits (MSB first) to integer."""
    result = 0
    for b in bits:
        result = (result << 1) | b
    return result


# ============================================================
# High-level MPC functions
# ============================================================

def millionaires_problem(x: int, y: int, n_bits: int = 4,
                         params: SecureGateParams = None) -> dict:
    """
    Millionaire's Problem: Who is richer?

    Alice has wealth x, Bob has wealth y. Both learn who is richer
    without revealing their actual wealth.

    Args:
        x: Alice's wealth (integer, 0 to 2^n_bits - 1).
        y: Bob's wealth (integer, 0 to 2^n_bits - 1).
        n_bits: Bit width.
        params: SecureGateParams. If None, creates new.

    Returns:
        {
            'alice_richer': bool,
            'bob_richer': bool,
            'equal': bool,
            'result_bit': int,
            'correct': bool,
            'circuit_stats': dict
        }
    """
    if params is None:
        params = SecureGateParams(bits=64)

    circuit = build_comparison_circuit(n_bits)
    alice_bits = int_to_bits(x, n_bits)
    bob_bits = int_to_bits(y, n_bits)

    result = secure_evaluate(circuit, alice_bits, bob_bits, params)

    result_bit = result['output'][0]
    return {
        'alice_richer': result_bit == 1,
        'bob_richer': result_bit == 0 and x != y,
        'equal': x == y,
        'result_bit': result_bit,
        'correct': result['correct'],
        'circuit_stats': {
            'gates': result['gates_evaluated'],
            'and_gates': result['and_gates'],
            'xor_gates': result['xor_gates'],
            'not_gates': result['not_gates']
        }
    }


def secure_equality_test(x: int, y: int, n_bits: int = 4,
                         params: SecureGateParams = None) -> dict:
    """Securely test x == y."""
    if params is None:
        params = SecureGateParams(bits=64)
    circuit = build_equality_circuit(n_bits)
    alice_bits = int_to_bits(x, n_bits)
    bob_bits = int_to_bits(y, n_bits)
    result = secure_evaluate(circuit, alice_bits, bob_bits, params)
    return {
        'equal': result['output'][0] == 1,
        'correct': result['correct'],
        'circuit_stats': {
            'gates': result['gates_evaluated'],
            'and_gates': result['and_gates'],
        }
    }


def secure_addition(x: int, y: int, n_bits: int = 4,
                    params: SecureGateParams = None) -> dict:
    """Securely compute (x + y) mod 2^n."""
    if params is None:
        params = SecureGateParams(bits=64)
    circuit = build_addition_circuit(n_bits)
    alice_bits = int_to_bits(x, n_bits)
    bob_bits = int_to_bits(y, n_bits)
    result = secure_evaluate(circuit, alice_bits, bob_bits, params)
    sum_value = bits_to_int(result['output'])
    expected = (x + y) % (2 ** n_bits)
    return {
        'sum': sum_value,
        'expected': expected,
        'correct': sum_value == expected and result['correct'],
        'circuit_stats': {
            'gates': result['gates_evaluated'],
            'and_gates': result['and_gates'],
        }
    }


def performance_report(n_bits: int = 4) -> dict:
    """
    Report OT calls and wall-clock time for each circuit at n_bits.

    Returns:
        {
            'comparison': {'and_gates': int, 'time': float},
            'equality':   {'and_gates': int, 'time': float},
            'addition':   {'and_gates': int, 'time': float}
        }
    """
    import time
    params = SecureGateParams(bits=64)
    report = {}
    for name, func in [('comparison', lambda: millionaires_problem(7, 12, n_bits, params)),
                       ('equality', lambda: secure_equality_test(5, 5, n_bits, params)),
                       ('addition', lambda: secure_addition(3, 5, n_bits, params))]:
        start = time.time()
        result = func()
        elapsed = time.time() - start
        stats = result.get('circuit_stats', {})
        report[name] = {'and_gates': stats.get('and_gates', 0), 'time': elapsed}
    return report
