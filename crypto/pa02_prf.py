"""
PA#2 — Pseudorandom Functions via GGM Tree.

Provides:
    - GGM_PRF: PRF built from PA#1's PRG using the GGM tree construction.
    - AES_PRF: PRF using AES-128 (own implementation, no library).
    - PRG_from_PRF: Backward direction (PRF → PRG).

Dependencies:
    - crypto.pa01_owf_prg (PRG class)
    - crypto.utils
"""

from crypto.pa01_owf_prg import DLP_OWF, PRG
from crypto.utils import xor_bytes, random_bytes, bytes_to_int, int_to_bytes


class GGM_PRF:
    """
    Pseudorandom Function built from a PRG using the GGM tree construction.

    Given a length-doubling PRG G: {0,1}^n → {0,1}^{2n},
    split G(s) into left half G0(s) and right half G1(s).

    F_k(x) for x = b1 b2 ... bn:
        s = k
        for each bit bi in x (left to right):
            s = G_{bi}(s)
        return s
    """

    def __init__(self, prg: PRG, n_bits: int = None):
        """
        Args:
            prg: PRG instance from PA#1 (must have .generate(seed, length) method).
            n_bits: Bit length of keys and inputs. If None, use prg.n_bits.
        """
        self.prg = prg
        self.n_bits = n_bits or prg.n_bits

    def _length_doubling_prg(self, seed_val: int) -> tuple[int, int]:
        """
        Apply the PRG as a length-doubling function.
        G(seed) → (left_half, right_half) each of self.n_bits bits.
        """
        bits = self.prg.generate(seed_val, 2 * self.n_bits)
        left_bits = bits[:self.n_bits]
        right_bits = bits[self.n_bits:]

        # Convert bit lists to integers (MSB first)
        left_int = 0
        for b in left_bits:
            left_int = (left_int << 1) | b

        right_int = 0
        for b in right_bits:
            right_int = (right_int << 1) | b

        return (left_int, right_int)

    def evaluate(self, key: int, x: int, input_bits: int = None) -> int:
        """
        Evaluate F_k(x) using the GGM tree.

        Args:
            key: The PRF key k (integer, n_bits bits).
            x: The input (integer, interpreted as `input_bits` bits).
            input_bits: Number of bits to read from x (default: self.n_bits).

        Returns:
            F_k(x) as an integer.
        """
        if input_bits is None:
            input_bits = self.n_bits

        # Parse x as bit string of length input_bits (MSB first)
        bit_string = [(x >> (input_bits - 1 - i)) & 1 for i in range(input_bits)]

        s = key
        for b in bit_string:
            left, right = self._length_doubling_prg(s)
            s = left if b == 0 else right

        return s

    def evaluate_with_trace(self, key: int, x: int, input_bits: int = None) -> dict:
        """
        Same as evaluate() but returns intermediate values for the web demo.
        """
        if input_bits is None:
            input_bits = self.n_bits

        bit_string = [(x >> (input_bits - 1 - i)) & 1 for i in range(input_bits)]

        s = key
        path = []
        for level, b in enumerate(bit_string):
            left, right = self._length_doubling_prg(s)
            state_after = left if b == 0 else right
            path.append({
                'level': level,
                'bit': b,
                'state_before': s,
                'left': left,
                'right': right,
                'state_after': state_after,
            })
            s = state_after

        return {
            'key': key,
            'input': x,
            'input_bits': ''.join(str(b) for b in bit_string),
            'path': path,
            'output': s,
        }

    def F(self, key: int, x: int) -> int:
        """Shorthand: F_k(x). Used by downstream PAs."""
        return self.evaluate(key, x)


class AES_PRF:
    """
    AES-128 as a PRF.
    F_k(x) = AES_k(x) where k, x ∈ {0,1}^128.
    Own implementation — no library AES.
    """

    # AES S-box (standard, 256 bytes)
    SBOX = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    ]

    # Inverse S-box
    INV_SBOX = [
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    ]

    # Round constants for key expansion
    RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    def __init__(self):
        pass

    @staticmethod
    def _xtime(a: int) -> int:
        """Multiply by x in GF(2^8) with poly x^8 + x^4 + x^3 + x + 1."""
        result = a << 1
        if a & 0x80:
            result ^= 0x1B
        return result & 0xFF

    @staticmethod
    def _gf_mult(a: int, b: int) -> int:
        """Multiply a and b in GF(2^8) using Russian peasant multiplication."""
        result = 0
        temp_a = a
        temp_b = b
        for _ in range(8):
            if temp_b & 1:
                result ^= temp_a
            temp_a = AES_PRF._xtime(temp_a)
            temp_b >>= 1
        return result

    def _sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        """Apply S-box to every byte in 4x4 state matrix."""
        return [[self.SBOX[state[r][c]] for c in range(4)] for r in range(4)]

    def _inv_sub_bytes(self, state: list[list[int]]) -> list[list[int]]:
        """Apply inverse S-box to every byte."""
        return [[self.INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

    def _shift_rows(self, state: list[list[int]]) -> list[list[int]]:
        """Cyclically left-shift each row by its row index."""
        return [
            [state[r][(c + r) % 4] for c in range(4)]
            for r in range(4)
        ]

    def _inv_shift_rows(self, state: list[list[int]]) -> list[list[int]]:
        """Cyclically right-shift each row by its row index."""
        return [
            [state[r][(c - r) % 4] for c in range(4)]
            for r in range(4)
        ]

    def _mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        """Mix columns using the AES MixColumns matrix in GF(2^8)."""
        new_state = [[0] * 4 for _ in range(4)]
        gm = self._gf_mult
        for c in range(4):
            s = [state[r][c] for r in range(4)]
            new_state[0][c] = gm(2, s[0]) ^ gm(3, s[1]) ^ s[2] ^ s[3]
            new_state[1][c] = s[0] ^ gm(2, s[1]) ^ gm(3, s[2]) ^ s[3]
            new_state[2][c] = s[0] ^ s[1] ^ gm(2, s[2]) ^ gm(3, s[3])
            new_state[3][c] = gm(3, s[0]) ^ s[1] ^ s[2] ^ gm(2, s[3])
        return new_state

    def _inv_mix_columns(self, state: list[list[int]]) -> list[list[int]]:
        """Inverse MixColumns using the inverse AES matrix."""
        new_state = [[0] * 4 for _ in range(4)]
        gm = self._gf_mult
        for c in range(4):
            s = [state[r][c] for r in range(4)]
            new_state[0][c] = gm(14, s[0]) ^ gm(11, s[1]) ^ gm(13, s[2]) ^ gm(9, s[3])
            new_state[1][c] = gm(9, s[0]) ^ gm(14, s[1]) ^ gm(11, s[2]) ^ gm(13, s[3])
            new_state[2][c] = gm(13, s[0]) ^ gm(9, s[1]) ^ gm(14, s[2]) ^ gm(11, s[3])
            new_state[3][c] = gm(11, s[0]) ^ gm(13, s[1]) ^ gm(9, s[2]) ^ gm(14, s[3])
        return new_state

    def _add_round_key(self, state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
        """XOR state with round key (both 4x4 matrices)."""
        return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]

    def _key_expansion(self, key: bytes) -> list[list[list[int]]]:
        """Expand 16-byte key into 11 round keys (each 4x4 matrix)."""
        # Parse key into 4 words of 4 bytes each (column-major)
        W = []
        for i in range(4):
            W.append(list(key[i*4:(i+1)*4]))

        for i in range(4, 44):
            temp = W[i - 1][:]
            if i % 4 == 0:
                # RotWord: [a,b,c,d] -> [b,c,d,a]
                temp = [temp[1], temp[2], temp[3], temp[0]]
                # SubWord: apply S-box
                temp = [self.SBOX[b] for b in temp]
                # XOR with RCON
                temp[0] ^= self.RCON[i // 4 - 1]
            W.append([W[i - 4][j] ^ temp[j] for j in range(4)])

        # Build round keys as 4x4 matrices (column-major: state[row][col])
        round_keys = []
        for rk in range(11):
            rk_matrix = [[0] * 4 for _ in range(4)]
            for col in range(4):
                word = W[rk * 4 + col]
                for row in range(4):
                    rk_matrix[row][col] = word[row]
            round_keys.append(rk_matrix)
        return round_keys

    def _bytes_to_state(self, data: bytes) -> list[list[int]]:
        """Convert 16 bytes to 4x4 state matrix (COLUMN-MAJOR)."""
        state = [[0] * 4 for _ in range(4)]
        for col in range(4):
            for row in range(4):
                state[row][col] = data[col * 4 + row]
        return state

    def _state_to_bytes(self, state: list[list[int]]) -> bytes:
        """Convert 4x4 state matrix back to 16 bytes (COLUMN-MAJOR)."""
        result = bytearray(16)
        for col in range(4):
            for row in range(4):
                result[col * 4 + row] = state[row][col]
        return bytes(result)

    def encrypt_block(self, key: bytes, plaintext: bytes) -> bytes:
        """AES-128 encrypt a single 16-byte block."""
        round_keys = self._key_expansion(key)
        state = self._bytes_to_state(plaintext)
        state = self._add_round_key(state, round_keys[0])
        for rnd in range(1, 10):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[rnd])
        # Final round (no MixColumns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[10])
        return self._state_to_bytes(state)

    def decrypt_block(self, key: bytes, ciphertext: bytes) -> bytes:
        """AES-128 decrypt a single 16-byte block."""
        round_keys = self._key_expansion(key)
        state = self._bytes_to_state(ciphertext)
        state = self._add_round_key(state, round_keys[10])
        for rnd in range(9, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, round_keys[rnd])
            state = self._inv_mix_columns(state)
        # Final
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, round_keys[0])
        return self._state_to_bytes(state)

    def F(self, key: bytes, x: bytes) -> bytes:
        """PRF interface: F_k(x) = AES_k(x)."""
        return self.encrypt_block(key, x)


class PRG_from_PRF:
    """
    Backward direction PA#2b: PRG from PRF.
    G(s) = F_s(0^n) || F_s(1_padded_to_128)
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()
        self.block_size = 16

    def generate(self, seed: bytes) -> bytes:
        """G(s) = F_s(0^128) || F_s(0^127 || 1). Returns 32 bytes."""
        zero_block = b'\x00' * 16
        one_block = b'\x00' * 15 + b'\x01'
        left = self.prf.F(seed, zero_block)
        right = self.prf.F(seed, one_block)
        return left + right

    def statistical_test(self, num_samples: int = 100) -> dict:
        """Run frequency monobit test on PRG output."""
        from crypto.pa01_owf_prg import StatisticalTests
        all_bits = []
        for _ in range(num_samples):
            seed = random_bytes(16)
            output = self.generate(seed)
            for byte in output:
                for bit_pos in range(8):
                    all_bits.append((byte >> (7 - bit_pos)) & 1)
        passed, p_value = StatisticalTests.frequency_monobit(all_bits)
        return {'passed': passed, 'p_value': p_value, 'total_bits': len(all_bits)}
