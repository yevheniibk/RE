#!/usr/bin/env python3
"""ЛР 2, варіант 3: статична деобфускація x86/unicode_mixed."""

import sys
from pathlib import Path

PREFIX = b"IA" * 14 + b"4444"
CORE = (
    b"jXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JB"
)
STUB = PREFIX + CORE
ALPHABET = set(b"abcdefghijklmnopqrstuvwxyzBCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")


def load_encoded(filename):
    """Прочитати файл і повернути весь зразок та лише пари даних."""
    raw = Path(filename).read_bytes()
    if not raw.startswith(STUB):
        raise ValueError("Інший декодер: потрібні ECX, BufferOffset=0, -i 1, -f raw.")
    if not raw.endswith(b"AA"):
        raise ValueError("Відсутній завершувач AA.")
    pairs = raw[len(STUB):-2]
    if not pairs or len(pairs) % 2:
        raise ValueError("Очікується непорожня послідовність пар символів.")
    if any(c not in ALPHABET for c in pairs):
        raise ValueError("Дані містять символ поза алфавітом Alpha2.")
    return raw, pairs


def decode_pairs(pairs):
    """Зворотне перетворення: два закодовані символи -> один байт."""
    restored = bytearray()
    for i in range(0, len(pairs), 2):
        a = pairs[i]
        b = pairs[i + 1]
        value = ((a << 4) + b) & 0xFF
        restored.append(value)
    return bytes(restored)


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Використання: python _dec_static.py encoded.bin decoded_static.bin")
    raw, pairs = load_encoded(sys.argv[1])
    restored = decode_pairs(pairs)
    Path(sys.argv[2]).write_bytes(restored)
    print(f"Зразок: {len(raw)}; декодер: {len(STUB)}; пари: {len(pairs)}; AA: 2")
    print("Перші пари: символи | hex -> початковий байт")
    for i in range(0, min(16, len(pairs)), 2):
        a, b = pairs[i:i + 2]
        print(f"{chr(a)}{chr(b)} | {a:02x} {b:02x} -> {restored[i // 2]:02x}")
    print(f"Відновлено: {len(restored)} байтів")
    print(repr(restored))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(f"Помилка: {error}")
