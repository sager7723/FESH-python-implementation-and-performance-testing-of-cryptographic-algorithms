from __future__ import annotations

from pathlib import Path

from fesh_core import BLOCK_SIZE, FESH128128


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def require_blocks(data: bytes) -> None:
    if len(data) % BLOCK_SIZE:
        raise ValueError("data length must be a multiple of 16 bytes")


def encrypt_ecb(cipher: FESH128128, data: bytes) -> bytes:
    require_blocks(data)
    output = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        output.extend(cipher.encrypt_block(data[i : i + BLOCK_SIZE]))
    return bytes(output)


def decrypt_ecb(cipher: FESH128128, data: bytes) -> bytes:
    require_blocks(data)
    output = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        output.extend(cipher.decrypt_block(data[i : i + BLOCK_SIZE]))
    return bytes(output)


def encrypt_cbc(cipher: FESH128128, data: bytes, iv: bytes | None = None) -> bytes:
    require_blocks(data)
    previous = iv or (b"\x00" * BLOCK_SIZE)
    if len(previous) != BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")

    output = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = xor_bytes(data[i : i + BLOCK_SIZE], previous)
        encrypted = cipher.encrypt_block(block)
        output.extend(encrypted)
        previous = encrypted
    return bytes(output)


def decrypt_cbc(cipher: FESH128128, data: bytes, iv: bytes | None = None) -> bytes:
    require_blocks(data)
    previous = iv or (b"\x00" * BLOCK_SIZE)
    if len(previous) != BLOCK_SIZE:
        raise ValueError("CBC IV must be exactly 16 bytes")

    output = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i : i + BLOCK_SIZE]
        output.extend(xor_bytes(cipher.decrypt_block(block), previous))
        previous = block
    return bytes(output)


def encrypt_bmp(input_path: Path, output_path: Path, cipher: FESH128128, mode: str) -> Path:
    raw = input_path.read_bytes()
    if raw[:2] != b"BM":
        raise ValueError(f"{input_path} is not a BMP file")

    pixel_offset = int.from_bytes(raw[10:14], "little")
    header, body = raw[:pixel_offset], raw[pixel_offset:]
    if len(body) % BLOCK_SIZE:
        body += b"\x00" * (BLOCK_SIZE - len(body) % BLOCK_SIZE)

    if mode.lower() == "ecb":
        encrypted = encrypt_ecb(cipher, body)
    elif mode.lower() == "cbc":
        encrypted = encrypt_cbc(cipher, body)
    else:
        raise ValueError("mode must be 'ecb' or 'cbc'")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(header + encrypted)
    return output_path
