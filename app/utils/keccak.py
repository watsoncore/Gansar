from __future__ import annotations


_MASK = (1 << 64) - 1
_ROUNDS = (
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
)
_ROTATION = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def _rotate(value: int, shift: int) -> int:
    if shift == 0:
        return value & _MASK
    return ((value << shift) | (value >> (64 - shift))) & _MASK


def _permute(state: list[int]) -> None:
    for rc in _ROUNDS:
        columns = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        delta = [columns[(x - 1) % 5] ^ _rotate(columns[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= delta[x]

        temp = [0] * 25
        for x in range(5):
            for y in range(5):
                temp[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate(state[x + 5 * y], _ROTATION[x][y])

        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = temp[x + 5 * y] ^ ((~temp[((x + 1) % 5) + 5 * y]) & temp[((x + 2) % 5) + 5 * y])
                state[x + 5 * y] &= _MASK
        state[0] ^= rc


def keccak_256(data: bytes) -> bytes:
    rate = 136
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0)
    padded.append(0x80)

    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for index in range(rate // 8):
            state[index] ^= int.from_bytes(block[index * 8 : index * 8 + 8], "little")
        _permute(state)

    out = bytearray()
    while len(out) < 32:
        for index in range(rate // 8):
            out.extend(state[index].to_bytes(8, "little"))
            if len(out) >= 32:
                break
        if len(out) < 32:
            _permute(state)
    return bytes(out[:32])
