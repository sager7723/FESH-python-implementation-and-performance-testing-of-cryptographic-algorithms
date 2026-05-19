from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property


MASK32 = 0xFFFFFFFF
BLOCK_SIZE = 16
ROUNDS = 16


def rol32(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def bytes_to_words(block: bytes) -> list[int]:
    if len(block) != BLOCK_SIZE:
        raise ValueError("FESH-128-128 block must be exactly 16 bytes")
    return [int.from_bytes(block[i : i + 4], "big") for i in range(0, BLOCK_SIZE, 4)]


def words_to_bytes(words: list[int]) -> bytes:
    return b"".join((word & MASK32).to_bytes(4, "big") for word in words)


def sub_nibble_key(x: list[int]) -> list[int]:
    r0, r1, r2, r3 = x[1], x[2], x[3], x[0]
    r1 = (~r1) & MASK32
    r2 ^= r1 | r3
    r2 &= MASK32
    r3 ^= r0 | r1
    r3 &= MASK32
    r1 ^= ((~r0) & MASK32) & r2
    r1 &= MASK32
    r0 ^= r2 & r3
    r0 &= MASK32
    return [r1, r3, r2, r0]


def mix_word_key(x: list[int]) -> list[int]:
    y0, y1, y2, y3 = x
    y0 ^= rol32(y1, 24)
    y0 &= MASK32
    y1 ^= rol32(y0, 7)
    y1 &= MASK32
    y3 ^= rol32(y2, 30)
    y3 &= MASK32
    y2 ^= rol32(y3, 18)
    y2 &= MASK32
    return [y2, y0, y3, y1]


def sub_nibble_enc(x: list[int]) -> list[int]:
    r0, r1, r2, r3 = x[1], x[2], x[0], x[3]
    r1 ^= r0 | r2
    r1 &= MASK32
    r2 ^= r3 | r1
    r2 &= MASK32
    r1 ^= r3
    r1 &= MASK32
    r3 ^= r0 & r2
    r3 &= MASK32
    r2 ^= r0
    r2 &= MASK32
    r0 ^= r1
    r0 &= MASK32
    r1 ^= ((~r2) & MASK32) | r3
    r1 &= MASK32
    r3 ^= ((~r0) & MASK32) | r1
    r3 &= MASK32
    return [r2, r0, r1, r3]


def mix_word_enc(x: list[int]) -> list[int]:
    y0, y1, y2, y3 = x
    y0 ^= rol32(y1, 29)
    y0 &= MASK32
    y1 ^= rol32(y0, 4)
    y1 &= MASK32
    y3 ^= rol32(y2, 13)
    y3 &= MASK32
    y2 ^= rol32(y3, 21)
    y2 &= MASK32
    y0 ^= rol32(y2, 15)
    y0 &= MASK32
    y2 ^= rol32(y0, 25)
    y2 &= MASK32
    y3 ^= rol32(y1, 19)
    y3 &= MASK32
    y1 ^= rol32(y3, 6)
    y1 &= MASK32
    return [y0, y1, y2, y3]


def sub_nibble_dec(x: list[int]) -> list[int]:
    r0, r1, r2, r3 = x[0], x[1], x[3], x[2]
    r0 ^= r1
    r0 &= MASK32
    r1 ^= r3
    r1 &= MASK32
    r2 ^= r0 | r1
    r2 &= MASK32
    r1 ^= r2
    r1 &= MASK32
    r1 ^= r3
    r1 &= MASK32
    r0 ^= r1 & r3
    r0 &= MASK32
    r3 = (~(r3 ^ r2)) & MASK32
    r2 ^= r0
    r2 &= MASK32
    r3 ^= r1 | r2
    r3 &= MASK32
    r2 ^= r0 & r3
    r2 &= MASK32
    return [r0, r3, r2, r1]


def mix_word_dec(x: list[int]) -> list[int]:
    y0, y1, y2, y3 = x
    y1 ^= rol32(y3, 6)
    y1 &= MASK32
    y3 ^= rol32(y1, 19)
    y3 &= MASK32
    y2 ^= rol32(y0, 25)
    y2 &= MASK32
    y0 ^= rol32(y2, 15)
    y0 &= MASK32
    y2 ^= rol32(y3, 21)
    y2 &= MASK32
    y3 ^= rol32(y2, 13)
    y3 &= MASK32
    y1 ^= rol32(y0, 4)
    y1 &= MASK32
    y0 ^= rol32(y1, 29)
    y0 &= MASK32
    return [y0, y1, y2, y3]


@dataclass(frozen=True)
class FESH128128:
    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 16:
            raise ValueError("FESH-128-128 key must be exactly 16 bytes")

    def expand_key(self, decrypt: bool = False) -> list[list[int]]:
        subkeys: list[list[int]] = [[0, 0, 0, 0] for _ in range(ROUNDS + 1)]
        state = bytes_to_words(self.key)
        subkeys[ROUNDS if decrypt else 0] = state[:]
        cst0 = 0x243F6A88
        for i in range(1, ROUNDS + 1):
            state = state[:]
            state[0] = (state[0] ^ rol32(cst0, i - 1)) & MASK32
            state = mix_word_key(sub_nibble_key(state))
            subkeys[ROUNDS - i if decrypt else i] = state[:]
        return subkeys

    @cached_property
    def encryption_subkeys(self) -> list[list[int]]:
        return self.expand_key(decrypt=False)

    @cached_property
    def decryption_subkeys(self) -> list[list[int]]:
        return self.expand_key(decrypt=True)

    def encrypt_block(self, block: bytes) -> bytes:
        state = bytes_to_words(block)
        subkeys = self.encryption_subkeys
        state = [(x ^ k) & MASK32 for x, k in zip(state, subkeys[0])]
        for round_index in range(1, ROUNDS + 1):
            state = mix_word_enc(sub_nibble_enc(state))
            state = [(x ^ k) & MASK32 for x, k in zip(state, subkeys[round_index])]
        return words_to_bytes(state)

    def decrypt_block(self, block: bytes) -> bytes:
        state = bytes_to_words(block)
        subkeys = self.decryption_subkeys
        state = [(x ^ k) & MASK32 for x, k in zip(state, subkeys[0])]
        for round_index in range(1, ROUNDS + 1):
            state = sub_nibble_dec(mix_word_dec(state))
            state = [(x ^ k) & MASK32 for x, k in zip(state, subkeys[round_index])]
        return words_to_bytes(state)
