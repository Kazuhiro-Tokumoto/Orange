#!/usr/bin/env python3
"""wasm が外から何も取り込んでいないことを確かめる。

ブラウザのウォレットは `WebAssembly.instantiate(bytes, {})` だけで
動かしている。取り込みが 1 つでも増えると、それを満たす JS の糊が要る。
糊が要るということは、`wasm-bindgen` のような外部の道具に頼ることを
意味し、`cargo build` だけでは作り直せなくなる。

**そうなっていないことを、変更のたびに確かめる。**
"""

import sys


def leb128(data, at):
    result = shift = 0
    while True:
        byte = data[at]
        at += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return result, at


def imports_of(data):
    if data[:4] != b"\0asm":
        raise SystemExit("wasm ではない")
    found = []
    at = 8
    while at < len(data):
        section = data[at]
        at += 1
        size, at = leb128(data, at)
        end = at + size
        if section == 2:  # import
            count, cursor = leb128(data, at)
            for _ in range(count):
                length, cursor = leb128(data, cursor)
                module = data[cursor : cursor + length].decode()
                cursor += length
                length, cursor = leb128(data, cursor)
                name = data[cursor : cursor + length].decode()
                cursor += length
                cursor += 1  # 種別
                _, cursor = leb128(data, cursor)
                found.append(f"{module}::{name}")
        at = end
    return found


def main():
    if len(sys.argv) != 2:
        raise SystemExit("使い方: wasm-imports.py <ファイル>")
    found = imports_of(open(sys.argv[1], "rb").read())
    if found:
        print("取り込みが増えている:", file=sys.stderr)
        for entry in found:
            print(f"  {entry}", file=sys.stderr)
        print(
            "\nブラウザ側は糊を持たない。crates/oag-node/assets/README.md を読むこと。",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print("取り込みは無い")


if __name__ == "__main__":
    main()
