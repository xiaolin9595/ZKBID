"""Project-local Keccak compatibility helpers.

The original repository was written against the historical ``pysha3`` package
where ``sha3_256`` exposed Ethereum-style Keccak-256 semantics. Modern Python's
``hashlib.sha3_256`` implements the standardized FIPS SHA-3 variant instead,
which does not match Solidity's ``keccak256``. This module restores the legacy
behavior expected by the contracts and existing Python code.
"""

from __future__ import annotations

import hashlib as _hashlib


_MASK64 = (1 << 64) - 1
_ROUND_CONSTANTS = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]
_ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _rotl64(value: int, shift: int) -> int:
    shift %= 64
    if shift == 0:
        return value & _MASK64
    return ((value << shift) | (value >> (64 - shift))) & _MASK64


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in _ROUND_CONSTANTS:
        c = [0] * 5
        d = [0] * 5
        a = [[0] * 5 for _ in range(5)]
        b = [[0] * 5 for _ in range(5)]

        for x in range(5):
            c[x] = (
                state[x + 5 * 0]
                ^ state[x + 5 * 1]
                ^ state[x + 5 * 2]
                ^ state[x + 5 * 3]
                ^ state[x + 5 * 4]
            )

        for x in range(5):
            d[x] = c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1)

        for x in range(5):
            for y in range(5):
                a[x][y] = state[x + 5 * y] ^ d[x]

        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(a[x][y], _ROTATION_OFFSETS[x][y])

        for x in range(5):
            for y in range(5):
                a[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])

        a[0][0] ^= round_constant

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = a[x][y] & _MASK64


class _KeccakHash:
    def __init__(self, rate_bytes: int, digest_size: int, data: bytes = b""):
        self.block_size = rate_bytes
        self.digest_size = digest_size
        self._rate_bytes = rate_bytes
        self._state = [0] * 25
        self._buffer = bytearray()
        if data:
            self.update(data)

    def copy(self) -> "_KeccakHash":
        clone = _KeccakHash(self._rate_bytes, self.digest_size)
        clone._state = self._state.copy()
        clone._buffer = self._buffer.copy()
        return clone

    def update(self, data: bytes | bytearray | memoryview) -> "_KeccakHash":
        if isinstance(data, memoryview):
            data = data.tobytes()
        elif isinstance(data, bytearray):
            data = bytes(data)
        elif not isinstance(data, bytes):
            raise TypeError("Keccak update() requires a bytes-like object")

        self._buffer.extend(data)
        while len(self._buffer) >= self._rate_bytes:
            self._absorb_block(self._buffer[: self._rate_bytes], self._state)
            del self._buffer[: self._rate_bytes]
        return self

    def _absorb_block(self, block: bytes | bytearray, state: list[int]) -> None:
        for lane_index in range(self._rate_bytes // 8):
            start = 8 * lane_index
            lane = int.from_bytes(block[start : start + 8], "little")
            state[lane_index] ^= lane
        _keccak_f1600(state)

    def _finalized_state(self) -> list[int]:
        state = self._state.copy()
        final_block = bytearray(self._buffer)
        final_block.append(0x01)
        final_block.extend(b"\x00" * (self._rate_bytes - len(final_block)))
        final_block[-1] ^= 0x80
        self._absorb_block(final_block, state)
        return state

    def digest(self) -> bytes:
        state = self._finalized_state()
        output = bytearray()
        while len(output) < self.digest_size:
            for lane_index in range(self._rate_bytes // 8):
                output.extend(state[lane_index].to_bytes(8, "little"))
            if len(output) >= self.digest_size:
                break
            _keccak_f1600(state)
        return bytes(output[: self.digest_size])

    def hexdigest(self) -> str:
        return self.digest().hex()


def _new_keccak(digest_bits: int, data: bytes = b"") -> _KeccakHash:
    rate_bytes_by_digest = {
        224: 144,
        256: 136,
        384: 104,
        512: 72,
    }
    return _KeccakHash(rate_bytes_by_digest[digest_bits], digest_bits // 8, data)


def keccak_224(data: bytes = b"") -> _KeccakHash:
    return _new_keccak(224, data)


def keccak_256(data: bytes = b"") -> _KeccakHash:
    return _new_keccak(256, data)


def keccak_384(data: bytes = b"") -> _KeccakHash:
    return _new_keccak(384, data)


def keccak_512(data: bytes = b"") -> _KeccakHash:
    return _new_keccak(512, data)


sha3_224 = keccak_224
sha3_256 = keccak_256
sha3_384 = keccak_384
sha3_512 = keccak_512
shake_128 = _hashlib.shake_128
shake_256 = _hashlib.shake_256


__all__ = (
    "sha3_224",
    "sha3_256",
    "sha3_384",
    "sha3_512",
    "keccak_224",
    "keccak_256",
    "keccak_384",
    "keccak_512",
    "shake_128",
    "shake_256",
)


# The legacy code expects ``hashlib.sha3_256`` to behave like Keccak-256.
_hashlib.sha3_224 = keccak_224
_hashlib.sha3_256 = keccak_256
_hashlib.sha3_384 = keccak_384
_hashlib.sha3_512 = keccak_512
