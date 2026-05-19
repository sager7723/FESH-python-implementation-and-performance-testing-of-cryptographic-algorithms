from __future__ import annotations

import argparse
import time
from pathlib import Path

from fesh_core import FESH128128
from fesh_modes import decrypt_cbc, decrypt_ecb, encrypt_bmp, encrypt_cbc, encrypt_ecb


DEMO_KEY = bytes.fromhex("a0a3a2a5a4a7a6a9abaca2a9a3a7a2a8")


def read_hex_vector(path: Path) -> bytes:
    return bytes.fromhex(path.read_text(encoding="ascii").strip())


def find_vector_root(root: Path) -> Path:
    fesh_candidates = [path for path in root.iterdir() if path.is_dir() and path.name.startswith("FESH")]
    if not fesh_candidates:
        raise FileNotFoundError("FESH material directory was not found")
    fesh_dir = fesh_candidates[0]
    test_dir = next(path for path in fesh_dir.iterdir() if path.is_dir() and path.name.startswith("3-"))
    return next(path for path in test_dir.iterdir() if path.is_dir() and path.name.startswith("FESH128_128"))


def validate_vectors(root: Path) -> tuple[int, int, int]:
    passed = 0
    total = 0
    skipped = 0
    vector_root = find_vector_root(root)

    for mode_dir in vector_root.iterdir():
        if not mode_dir.is_dir():
            continue
        is_ecb = "ECB" in mode_dir.name
        for case_dir in sorted(mode_dir.iterdir(), key=lambda p: int(p.name)):
            key = read_hex_vector(case_dir / "key.dat")
            plaintext = read_hex_vector(case_dir / "p.dat")
            ciphertext = read_hex_vector(case_dir / "c.dat")
            if len(plaintext) != len(ciphertext):
                skipped += 1
                continue

            cipher = FESH128128(key)
            if is_ecb:
                encrypted = encrypt_ecb(cipher, plaintext)
                decrypted = decrypt_ecb(cipher, ciphertext)
            else:
                encrypted = encrypt_cbc(cipher, plaintext)
                decrypted = decrypt_cbc(cipher, ciphertext)

            total += 2
            passed += int(encrypted == ciphertext)
            passed += int(decrypted == plaintext)
    return passed, total, skipped


def print_sample_comparison() -> None:
    cipher = FESH128128(DEMO_KEY)
    plaintext = bytes(range(32))

    ecb_ciphertext = encrypt_ecb(cipher, plaintext)
    ecb_decrypted = decrypt_ecb(cipher, ecb_ciphertext)
    cbc_ciphertext = encrypt_cbc(cipher, plaintext)
    cbc_decrypted = decrypt_cbc(cipher, cbc_ciphertext)

    print("sample key:       ", DEMO_KEY.hex())
    print("sample plaintext: ", plaintext.hex())
    print("ECB ciphertext:   ", ecb_ciphertext.hex())
    print("ECB decrypted:    ", ecb_decrypted.hex())
    print("ECB correct:      ", ecb_decrypted == plaintext)
    print("CBC ciphertext:   ", cbc_ciphertext.hex())
    print("CBC decrypted:    ", cbc_decrypted.hex())
    print("CBC correct:      ", cbc_decrypted == plaintext)


def benchmark_best_large(cipher: FESH128128, size_mib: int = 1, rounds: int = 3) -> dict[str, float]:
    data = bytes((i * 37 + 11) & 0xFF for i in range(size_mib * 1024 * 1024))
    result: dict[str, float] = {}
    for name, func in [("ECB", encrypt_ecb), ("CBC", encrypt_cbc)]:
        timings = []
        for _ in range(rounds):
            start = time.perf_counter()
            func(cipher, data)
            timings.append(time.perf_counter() - start)
        result[name] = len(data) / min(timings) / 1024 / 1024
    return result


def benchmark_average_small(cipher: FESH128128, size_kib: int = 16, rounds: int = 100) -> dict[str, float]:
    data = bytes((i * 37 + 11) & 0xFF for i in range(size_kib * 1024))
    total_times = {"ECB": 0.0, "CBC": 0.0}
    funcs = {"ECB": encrypt_ecb, "CBC": encrypt_cbc}
    for round_index in range(rounds):
        order = ("ECB", "CBC") if round_index % 2 == 0 else ("CBC", "ECB")
        for name in order:
            start = time.perf_counter()
            funcs[name](cipher, data)
            total_times[name] += time.perf_counter() - start
    result: dict[str, float] = {}
    for name, total_time in total_times.items():
        average_time = total_time / rounds
        result[name] = len(data) / average_time / 1024 / 1024
    return result


def print_benchmark_result(title: str, result: dict[str, float]) -> None:
    ecb = result["ECB"]
    cbc = result["CBC"]
    gap = (ecb - cbc) / cbc * 100 if cbc else 0.0
    print(title)
    print(f"ECB throughput: {ecb:.4f} MiB/s")
    print(f"CBC throughput: {cbc:.4f} MiB/s")
    print(f"ECB vs CBC gap: {gap:.2f}%")


def encrypt_bmp_samples(root: Path, cipher: FESH128128) -> None:
    bmp_candidates = list(root.glob("*.bmp"))
    if not bmp_candidates:
        print("BMP sample not found.")
        return

    bmp_path = bmp_candidates[0]
    raw = bmp_path.read_bytes()
    print("BMP input:        ", bmp_path)
    print("BMP header:       ", raw[:2], "pixel offset =", int.from_bytes(raw[10:14], "little"))

    for mode in ("ecb", "cbc"):
        output_path = root / "output" / f"{bmp_path.stem}_fesh128128_{mode}.bmp"
        encrypt_bmp(bmp_path, output_path, cipher, mode)
        output = output_path.read_bytes()
        print(f"{mode.upper()} BMP output:  ", output_path)
        print(f"{mode.upper()} BMP header:  ", output[:2], "size =", len(output))


def run_all(root: Path) -> None:
    cipher = FESH128128(DEMO_KEY)

    print("== sample data encryption ==")
    print_sample_comparison()

    print("\n== test vectors ==")
    passed, total, skipped = validate_vectors(root)
    print(f"test vectors: {passed}/{total} passed, {skipped} inconsistent case(s) skipped")

    print("\n== throughput ==")
    print_benchmark_result(
        "large benchmark: 1 MiB data, best of 3 runs",
        benchmark_best_large(cipher),
    )
    print_benchmark_result(
        "small benchmark: 16 KiB data, average of 100 runs",
        benchmark_average_small(cipher),
    )

    print("\n== BMP encryption ==")
    encrypt_bmp_samples(root, cipher)


def main() -> None:
    parser = argparse.ArgumentParser(description="FESH-128-128 tests and BMP encryption demo")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    run_all(args.root)


if __name__ == "__main__":
    main()
