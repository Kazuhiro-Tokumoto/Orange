#!/usr/bin/env python3
"""Check that the wasm imports nothing from outside.

The browser wallet runs on `WebAssembly.instantiate(bytes, {})` alone. One
added import means JS glue is needed to satisfy it. Needing glue means
depending on external tooling such as `wasm-bindgen`, and then it can no
longer be rebuilt with `cargo build` alone.

**That this has not happened is checked on every change.**
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
        raise SystemExit("not a wasm file")
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
                cursor += 1  # kind
                _, cursor = leb128(data, cursor)
                found.append(f"{module}::{name}")
        at = end
    return found


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: wasm-imports.py <file>")
    found = imports_of(open(sys.argv[1], "rb").read())
    if found:
        print("imports have grown:", file=sys.stderr)
        for entry in found:
            print(f"  {entry}", file=sys.stderr)
        print(
            "\nThe browser side has no glue. See crates/oag-node/assets/README.md.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print("no imports")


if __name__ == "__main__":
    main()
