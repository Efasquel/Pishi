#!/usr/bin/env python3
import os
import subprocess
import sys


def edit_got(kext_bytes: bytearray, ori_sym: bytes, new_sym: bytes, addrs: list) -> bytearray:
    if len(ori_sym) != len(new_sym):
        print("Original and new symbols must be of the same length.", file=sys.stderr)
        sys.exit(1)

    for addr in addrs:
        if kext_bytes[addr:addr + len(ori_sym)] != ori_sym:
            print(
                f"Mismatch at address {addr:x}: expected {ori_sym!r}, found {kext_bytes[addr:addr + len(ori_sym)]!r}",
                file=sys.stderr,
            )
            sys.exit(1)
        kext_bytes[addr:addr + len(ori_sym)] = new_sym

    print(f"Successfully edited GOT from {ori_sym!r} to {new_sym!r}")
    return kext_bytes


def is_fat(kext_bytes: bytes) -> bool:
    # FAT_MAGIC / FAT_CIGAM (32- and 64-bit fat headers)
    return kext_bytes[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
                              b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca")


def is_macho(kext_bytes: bytes) -> bool:
    # MH_MAGIC / MH_CIGAM for 32- and 64-bit thin Mach-O
    return kext_bytes[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                              b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")


def edit_entitle(kext_bytes: bytearray) -> bytearray:
    sym1 = b"__ZN12IOUserClient21copyClientEntitlementEP4taskPKc"
    idx = kext_bytes.find(sym1)
    ridx = kext_bytes.rfind(sym1)
    if idx != -1:
        print(f"{sym1!r} found")
        kext_bytes = edit_got(kext_bytes, sym1, b"__ZN12IOFuzzClient21copyClientEntitlementEP4taskPKc", [idx, ridx])
    else:
        print(f"{sym1!r} not found, no patch needed")

    sym2 = b"__ZN24AppleMobileFileIntegrity16copyEntitlementsEP4proc"
    idx = kext_bytes.find(sym2)
    ridx = kext_bytes.rfind(sym2)
    if idx != -1:
        print(f"{sym2!r} found")
        kext_bytes = edit_got(kext_bytes, sym2, b"__ZN12IOFuzzClient25AMFIcopyClientEntitlementEP4taskPKc", [idx, ridx])
    else:
        print(f"{sym2!r} not found, no patch needed")

    return kext_bytes


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_universal_binary> <output_path>", file=sys.stderr)
        sys.exit(1)

    input_binary = sys.argv[1]
    output_path = sys.argv[2]

    with open(input_binary, "rb") as f:
        input_bytes = f.read()

    if is_fat(input_bytes):
        # Universal binary: extract the arm64e slice into output_path.
        result = subprocess.run(["lipo", "-extract", "arm64e", "-output", output_path, input_binary])
        if result.returncode != 0:
            print(f"Error running lipo command: {result.returncode}", file=sys.stderr)
            sys.exit(1)
        with open(output_path, "rb") as f:
            kext_bytes = bytearray(f.read())
    elif is_macho(input_bytes):
        # Already a thin Mach-O: nothing to extract, operate on it directly.
        kext_bytes = bytearray(input_bytes)
    else:
        print("Input is neither a fat binary nor a Mach-O file", file=sys.stderr)
        sys.exit(1)

    kext_bytes = edit_entitle(kext_bytes)

    with open(output_path, "wb") as f:
        f.write(kext_bytes)
    os.chmod(output_path, 0o755)

    print(f"Edited kext saved in {output_path}")


if __name__ == "__main__":
    main()
