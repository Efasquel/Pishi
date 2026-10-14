#!/usr/bin/env python3
import argparse
import os
import plistlib
import re
import struct
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


# (original imported symbol, equal-length fuzz replacement exported by Pishi).
# Rewriting the import string makes the boot kernel collection bind the call to
# the fuzz stub, which always reports the task as entitled. Each replacement MUST
# be the same byte length as the original (edit_got enforces this) and must be
# exported by Pishi.kext (see pishi.cpp).
ENTITLEMENT_PATCHES = [
    (b"__ZN12IOUserClient21copyClientEntitlementEP4taskPKc",
     b"__ZN12IOFuzzClient21copyClientEntitlementEP4taskPKc"),
    (b"__ZN24AppleMobileFileIntegrity16copyEntitlementsEP4proc",
     b"__ZN12IOFuzzClient25AMFIcopyClientEntitlementEP4taskPKc"),
    # free C entitlement checkers used by some drivers in initWithTask
    (b"_IOTaskHasEntitlement",
     b"_IOFuzzHasEntitlement"),
    (b"_IOCurrentTaskHasEntitlement",
     b"_IOFuzzCurrentHasEntitlement"),
]

# These return a C bool, so the fuzz stub's `true` can never be misused by the
# caller. The others return an OSObject* and the fuzz stub returns kOSBooleanTrue,
# which is only correct when the caller treats the result as a yes/no answer.
BOOL_RETURNING = {b"_IOTaskHasEntitlement", b"_IOCurrentTaskHasEntitlement"}


# ---------------------------------------------------------------------------
# Call-site analysis
#
# For every call to an OSObject-returning entitlement API we follow the returned
# pointer (x0 and every register it is copied to) along all paths after the call
# and classify how it is consumed:
#   SAFE    only compared (e.g. against kOSBooleanTrue), NULL-checked,
#           OSDynamicCast<OSBoolean>, or release()d.
#   UNSAFE  cast to another class (OSString, OSDictionary, ...) or a virtual
#           method other than release() is called on it. Returning
#           kOSBooleanTrue there yields NULL derefs / bogus vtable calls.
#   UNKNOWN the pointer escapes (passed to a call, stored, returned, ...) or the
#           path budget ran out. Treated as "do not hook" unless --force.
# ---------------------------------------------------------------------------

SAFE, UNKNOWN, UNSAFE = "SAFE", "UNKNOWN", "UNSAFE"
# OSMetaClassBase vtable slots that behave correctly on kOSBooleanTrue.
BENIGN_VTABLE_SLOTS = {
    0x28: "release()",
    0x40: "isEqualTo()",  # e.g. obj->isEqualTo(kOSBooleanTrue)
}
SAFE_META_CAST = "__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass"
# Imports taking no arguments: a stale copy of the pointer left in x0..x7 is not
# actually passed to them.
NO_ARG_FUNCTIONS = {
    "_ml_get_interrupts_enabled", "_current_task", "_current_thread",
    "_proc_selfpid", "_kern_config_is_development", "_mach_absolute_time",
}
ARG_REGS = {f"x{i}" for i in range(8)}
CALL_CLOBBERED = {f"x{i}" for i in range(19)}
PATH_BUDGET = 4000  # instructions explored per call site, all paths together


def run(*args) -> str:
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def xreg(op: str):
    m = re.fullmatch(r"[xw](\d+)", op)
    return f"x{m.group(1)}" if m else None


def split_ops(text: str) -> list:
    text = re.sub(r"\s*<[^>]*>", "", text.split(" ;")[0])
    ops, depth, cur = [], 0, ""
    for ch in text:
        depth += (ch == "[") - (ch == "]")
        if ch == "," and depth == 0:
            ops.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        ops.append(cur.strip())
    return ops


def parse_mem(op: str):
    """`[xB, #off]!` -> (xB, off, writeback); None if not a simple base+imm operand."""
    m = re.fullmatch(r"\[(\w+)(?:, #(-?0x[0-9a-f]+|-?\d+))?\](!?)", op)
    if not m:
        return None
    return m.group(1), int(m.group(2) or "0", 0), m.group(3) == "!"


def imm(op: str):
    m = re.fullmatch(r"#(-?0x[0-9a-f]+|-?\d+)", op)
    return int(m.group(1), 0) if m else None


def is_branch(mnem: str) -> bool:
    return (mnem in ("b", "bl", "br", "blr", "cbz", "cbnz", "tbz", "tbnz")
            or mnem.startswith(("b.", "braa", "brab", "blraa", "blrab")))


class Insn:
    def __init__(self, addr, word, text):
        self.addr = addr
        self.word = word
        self.text = text
        mnem, _, rest = text.partition(" ")
        self.mnem = mnem
        self.ops = split_ops(rest)
        self.sym = None  # call target symbol, or symbol loaded from the GOT
        self.target = None  # branch target address
        self.ref = None  # address formed by adrp + add/ldr


class Disassembly:
    def __init__(self, path: str):
        stubs = {}  # stub / GOT address -> imported symbol (indirect symbol table)
        for line in run("otool", "-arch", "arm64e", "-Iv", path).splitlines():
            m = re.match(r"\s*0x([0-9a-f]+)\s+\d+\s+(\S+)", line)
            if m:
                stubs[int(m.group(1), 16)] = m.group(2)
        self.stubs = stubs

        self.insns, self.func_starts = [], set()
        pending_label = False
        for line in run("objdump", "-d", "--arch=arm64e", path).splitlines():
            # Labels are printed either as "addr <name>:" or as a bare "name:".
            m = re.match(r"^([0-9a-f]+) <(.+)>:$", line)
            if m:
                self.func_starts.add(int(m.group(1), 16))
                continue
            if re.match(r"^\S+:$", line) and not line.startswith(("Disassembly", "/")):
                pending_label = True
                continue
            # Raw encoding is printed either as 4 bytes ("b2 02 00 94") or one word.
            m = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} ){3}[0-9a-f]{2}|[0-9a-f]{8})\s+(.*)$", line)
            if m:
                raw = m.group(2)
                word = int.from_bytes(bytes.fromhex(raw), "little") if " " in raw else int(raw, 16)
                ins = Insn(int(m.group(1), 16), word, re.sub(r"\s+", " ", m.group(3).strip()))
                if pending_label:
                    self.func_starts.add(ins.addr)
                    pending_label = False
                self.insns.append(ins)
        self.index = {ins.addr: i for i, ins in enumerate(self.insns)}

        # Resolve branch targets and symbols. objdump prints two styles depending on
        # the kext's fixup format ("adrp x8, 0x50000 <..>" vs "adrp x8, 16 ; 0x14000",
        # with or without "symbol stub for:" / "literal pool symbol address:").
        pages = {}
        for ins in self.insns:
            if ins.mnem == "pacibsp":
                self.func_starts.add(ins.addr)
            m = re.match(r"adrp (x\d+), (?:-?\d+ ; )?0x([0-9a-f]+)", ins.text)
            if m:
                pages[m.group(1)] = int(m.group(2), 16)
            if ins.mnem in ("b", "bl"):
                imm26 = ins.word & 0x3ffffff
                ins.target = ins.addr + 4 * (imm26 - (1 << 26) if imm26 >> 25 else imm26)
            elif ins.mnem in ("cbz", "cbnz", "tbz", "tbnz") or ins.mnem.startswith("b."):
                last = ins.ops[-1] if ins.ops else ""
                ins.target = int(last, 16) if last.startswith("0x") else None
            if ins.target is not None:
                m = re.search(r"symbol stub for: (\S+)", ins.text)
                ins.sym = m.group(1) if m else stubs.get(ins.target)
            elif ins.mnem in ("ldr", "add") and len(ins.ops) >= 2:
                m = re.search(r"literal pool symbol address: (\S+)", ins.text)
                if m:
                    ins.sym = m.group(1)
                else:
                    base, off = None, None
                    mem = parse_mem(ins.ops[1])
                    if ins.mnem == "ldr" and mem:
                        base, off = mem[0], mem[1]
                    elif ins.mnem == "add" and len(ins.ops) == 3:
                        base, off = ins.ops[1], imm(ins.ops[2])
                    if base in pages and off is not None:
                        ins.ref = pages[base] + off
                        ins.sym = stubs.get(ins.ref)

        self._load_segments(path)

    def _load_segments(self, path: str):
        """Map vmaddr -> file bytes of the arm64e slice, to read jump tables."""
        with open(path, "rb") as f:
            data = arm64e_slice(f.read())
        self.data, self.segments = data, []
        ncmds = struct.unpack("<I", data[16:20])[0]
        p = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack("<II", data[p:p + 8])
            if cmd == 0x19:  # LC_SEGMENT_64
                vmaddr, vmsize, fileoff, filesize = struct.unpack("<QQQQ", data[p + 24:p + 56])
                self.segments.append((vmaddr, filesize, fileoff))
            p += size

    def read_s32(self, addr: int):
        for vmaddr, filesize, fileoff in self.segments:
            if vmaddr <= addr and addr + 4 <= vmaddr + filesize:
                o = fileoff + addr - vmaddr
                return struct.unpack("<i", self.data[o:o + 4])[0]
        return None

    def jump_table_targets(self, i: int):
        """Targets of a `br` that dispatches a clang switch table:
             cmp xI, #N ; ... adrp/add xT ; ldrsw xE, [xT, xI, lsl #2] ; adr xB, #k ; add xD, xB, xE ; br xD
        Returns None for any other shape."""
        window = self.insns[max(0, i - 10):i]
        table = count = base = None
        for ins in window:
            if ins.mnem == "cmp" and len(ins.ops) == 2 and imm(ins.ops[1]) is not None:
                count = imm(ins.ops[1]) + 1
            elif ins.mnem == "add" and ins.ref is not None:
                table = ins.ref
            elif ins.mnem == "adr" and len(ins.ops) == 2 and imm(ins.ops[1]) is not None:
                base = ins.addr + imm(ins.ops[1])
        if not any(ins.mnem == "ldrsw" and ", lsl #2]" in ins.text for ins in window):
            return None
        if None in (table, count, base) or count > 4096:
            return None
        targets = []
        for k in range(count):
            delta = self.read_s32(table + 4 * k)
            if delta is None or base + delta not in self.index:
                return None
            targets.append(base + delta)
        return targets

    def is_outlined_helper(self, target: int) -> bool:
        """A short straight-line body ending in ret (e.g. _OUTLINED_FUNCTION_N).
        These don't follow the calling convention, so we analyze them inline."""
        i = self.index.get(target)
        if i is None:
            return False
        for ins in self.insns[i:i + 32]:
            if ins.mnem in ("ret", "retab", "retaa"):
                return True
            if is_branch(ins.mnem):
                return False
        return False

    def call_sites(self, symbol: str) -> list:
        return [i for i, ins in enumerate(self.insns) if ins.mnem == "bl" and ins.sym == symbol]

    def metaclass_before(self, i: int):
        for ins in reversed(self.insns[max(0, i - 8):i]):
            m = re.fullmatch(r"__ZN\d+(\w+?)9metaClassE", ins.sym or "")
            if m:
                return m.group(1)
        return None


class State:
    def __init__(self, tracked, vt=None, method=None, consts=None, slots=None, nulls=None):
        self.tracked = set(tracked)        # registers holding the returned object
        self.vt = dict(vt or {})           # reg -> offset into the object's vtable
        self.method = dict(method or {})   # reg -> vtable slot it was loaded from
        self.consts = dict(consts or {})   # reg -> known immediate
        self.slots = set(slots or ())      # [sp, #off] stack slots holding the object
        # Registers holding OSDynamicCast<X>(object) for an X other than OSBoolean.
        # With the hook, object is kOSBooleanTrue, so that cast is always NULL.
        self.nulls = set(nulls or ())

    def copy(self):
        return State(self.tracked, self.vt, self.method, self.consts, self.slots, self.nulls)

    def kill(self, reg):
        self.tracked.discard(reg)
        self.vt.pop(reg, None)
        self.method.pop(reg, None)
        self.consts.pop(reg, None)
        self.nulls.discard(reg)

    def live(self):
        return bool(self.tracked or self.slots or self.nulls)

    def key(self):
        return (frozenset(self.tracked), frozenset(self.vt.items()),
                frozenset(self.method.items()), frozenset(self.slots), frozenset(self.nulls))


def analyze_site(dis: Disassembly, call_idx: int):
    """Follow the object returned by the call at call_idx. Returns (verdict, reason)."""
    # Work items: (insn index, state, return stack for inlined outlined helpers).
    work = [(call_idx + 1, State({"x0"}), ())]
    seen, budget = set(), PATH_BUDGET
    while work:
        i, st, rets = work.pop()
        inlined = False
        while True:
            if not st.live():
                break  # every copy of the pointer is dead or NULL on this path
            if i >= len(dis.insns):
                return UNKNOWN, "ran off the end of __text"
            ins = dis.insns[i]
            if ins.addr in dis.func_starts and i != call_idx + 1 and not inlined:
                if st.tracked & ARG_REGS:
                    return UNKNOWN, f"passed to function at {ins.addr:#x}"
                break
            inlined = False
            if (i, rets, st.key()) in seen:
                break
            seen.add((i, rets, st.key()))
            budget -= 1
            if budget <= 0:
                return UNKNOWN, "path budget exhausted"

            mnem, ops = ins.mnem, ins.ops
            regs = [xreg(o) for o in ops]

            # -- calls ---------------------------------------------------------
            if mnem in ("blr", "blraa", "blraaz", "blrab", "blrabz"):
                fn = regs[0]
                if fn in st.nulls:
                    return UNSAFE, f"call through a NULL cast result @{ins.addr:#x}"
                if fn in st.method:
                    off = st.method[fn]
                    if off not in BENIGN_VTABLE_SLOTS:
                        return UNSAFE, f"virtual call at vtable+{off:#x} on the returned object @{ins.addr:#x}"
                elif (st.tracked | st.nulls) & ARG_REGS:
                    return UNKNOWN, f"passed to indirect call @{ins.addr:#x}"
                for r in CALL_CLOBBERED:
                    st.kill(r)
                i += 1
                continue
            if mnem == "bl" and not ins.sym and dis.is_outlined_helper(ins.target):
                rets = rets + (i + 1,)
                i = dis.index[ins.target]
                inlined = True
                continue
            if mnem == "bl":
                if ins.sym == SAFE_META_CAST and "x0" in st.tracked:
                    cls = dis.metaclass_before(i)
                    if cls is None:
                        return UNSAFE, f"OSDynamicCast<?> on the returned object @{ins.addr:#x}"
                    if cls != "OSBoolean":
                        # The hooked call returns kOSBooleanTrue, so this cast yields
                        # NULL: follow the result and require a NULL check before use.
                        for r in CALL_CLOBBERED:
                            st.kill(r)
                        st.nulls.add("x0")
                        i += 1
                        continue
                elif (st.tracked | st.nulls) & ARG_REGS and ins.sym not in NO_ARG_FUNCTIONS:
                    return UNKNOWN, f"passed to {ins.sym or hex(ins.target or 0)} @{ins.addr:#x}"
                for r in CALL_CLOBBERED:
                    st.kill(r)
                i += 1
                continue

            # -- control flow --------------------------------------------------
            if mnem in ("ret", "retab", "retaa"):
                if rets:  # back from an inlined outlined helper
                    i, rets = rets[-1], rets[:-1]
                    continue
                if "x0" in st.tracked or "x0" in st.nulls:
                    return UNKNOWN, f"returned to the caller @{ins.addr:#x}"
                break
            if mnem in ("br", "braa", "braaz", "brab", "brabz"):
                targets = dis.jump_table_targets(i)
                if targets is not None:
                    for t in targets:
                        work.append((dis.index[t], st.copy(), rets))
                    break
                if any(p.mnem in ("autibsp", "autiasp") for p in dis.insns[max(0, i - 8):i]):
                    # Tail call after the frame was torn down.
                    if (st.tracked | st.nulls) & ARG_REGS:
                        return UNKNOWN, f"tail-called with the object as argument @{ins.addr:#x}"
                    break
                return UNKNOWN, f"indirect jump @{ins.addr:#x}"
            if mnem == "b":
                if ins.sym:  # tail call into a stub
                    if (st.tracked | st.nulls) & ARG_REGS:
                        return UNKNOWN, f"tail-called into {ins.sym} @{ins.addr:#x}"
                    break
                if ins.target not in dis.index:
                    return UNKNOWN, f"branch outside __text @{ins.addr:#x}"
                i = dis.index[ins.target]
                continue
            if mnem in ("cbz", "cbnz", "tbz", "tbnz") or mnem.startswith("b."):
                if ins.target not in dis.index:
                    return UNKNOWN, f"branch outside __text @{ins.addr:#x}"
                taken, fall = st.copy(), st
                if mnem in ("cbz", "cbnz") and regs[0] in st.nulls:
                    # A NULL cast result: only the NULL side is reachable when hooked.
                    if mnem == "cbz":
                        taken.nulls.discard(regs[0])
                        i = dis.index[ins.target]
                        st = taken
                    else:
                        st.nulls.discard(regs[0])
                        i += 1
                    continue
                if mnem in ("cbz", "cbnz") and regs[0] in st.tracked:
                    # On the NULL side every alias of the pointer is NULL too.
                    null_side = taken if mnem == "cbz" else fall
                    null_side.tracked.clear()
                    null_side.slots.clear()
                work.append((dis.index[ins.target], taken, rets))
                i += 1
                continue

            # -- stores: the pointer escapes to memory --------------------------
            if mnem.startswith("st"):
                srcs = [r for r, o in zip(regs, ops) if not o.startswith("[")]
                mem = next((parse_mem(o) for o in ops if o.startswith("[")), None)
                if set(srcs) & st.nulls:
                    return UNKNOWN, f"NULL cast result stored to memory @{ins.addr:#x}"
                if mem and mem[0] == "sp" and not mem[2] and mnem in ("str", "stur", "stp"):
                    # Spill to a stack slot: keep following it.
                    for k, r in enumerate(srcs):
                        (st.slots.add if r in st.tracked else st.slots.discard)(mem[1] + 8 * k)
                elif set(srcs) & st.tracked:
                    return UNKNOWN, f"stored to memory @{ins.addr:#x}"
                i += 1
                continue

            # -- data processing -----------------------------------------------
            dests = regs[:2] if mnem in ("ldp", "ldnp") else regs[:1]
            srcs = [r for r in regs[len(dests):] if r]

            if mnem in ("cmp", "cmn", "tst", "ccmp", "ccmn", "nop"):
                i += 1
                continue
            if mnem in ("autibsp", "autiasp"):
                st.slots.clear()  # epilogue: the stack frame is gone
                i += 1
                continue
            if mnem in ("autda", "autdb", "autia", "autib", "xpaci", "xpacd"):
                i += 1  # strips/validates a PAC, value is unchanged
                continue

            new_tracked, new_vt, new_method, new_const = False, None, None, None
            new_null = False
            reloaded = set()  # dests reloaded from a stack slot holding the object
            mem = next((parse_mem(o) for o in ops if o.startswith("[")), None)
            if mem and mem[0] in st.nulls:
                return UNSAFE, f"dereferences a NULL cast result @{ins.addr:#x}"
            if mnem == "mov" and len(ops) == 2 and regs[1] in st.nulls:
                new_null = True
            elif set(srcs) & st.nulls:
                return UNKNOWN, f"NULL cast result used by `{ins.text}` @{ins.addr:#x}"
            elif mnem in ("ldr", "ldur", "ldp") and mem and mem[0] == "sp" and not mem[2]:
                reloaded = {d for k, d in enumerate(dests) if mem[1] + 8 * k in st.slots}
            elif mnem == "mov" and len(ops) == 2:
                if regs[1] in st.tracked:
                    new_tracked = True
                elif regs[1] in st.vt:
                    new_vt = st.vt[regs[1]]
                elif imm(ops[1]) is not None:
                    new_const = imm(ops[1])
            elif mnem in ("ldr", "ldur") and len(ops) >= 2 and parse_mem(ops[1]):
                base, off, wb = parse_mem(ops[1])
                if base in st.tracked:
                    if off != 0:
                        return UNKNOWN, f"field load at +{off:#x} from the returned object @{ins.addr:#x}"
                    new_vt = 0
                elif base in st.vt:
                    new_method = st.vt[base] + off
                    if wb:
                        st.vt[base] += off
            elif mnem.startswith("ld") and any(
                    (parse_mem(o) or ("",))[0] in st.tracked for o in ops):
                return UNKNOWN, f"field load from the returned object @{ins.addr:#x}"
            elif mnem == "add" and len(ops) == 3 and regs[1] in st.vt:
                delta = imm(ops[2]) if imm(ops[2]) is not None else st.consts.get(regs[2])
                if delta is not None:
                    new_vt = st.vt[regs[1]] + delta
            elif mnem == "csel" and set(srcs) & st.tracked:
                new_tracked = True
            elif set(srcs) & st.tracked:
                return UNKNOWN, f"used by `{ins.text}` @{ins.addr:#x}"

            for d in dests:
                if d:
                    st.kill(d)
            st.tracked |= reloaded
            d = dests[0] if dests else None
            if d:
                if new_null:
                    st.nulls.add(d)
                if new_tracked:
                    st.tracked.add(d)
                if new_vt is not None:
                    st.vt[d] = new_vt
                if new_method is not None:
                    st.method[d] = new_method
                if new_const is not None:
                    st.consts[d] = new_const
            i += 1
    return SAFE, ""


def arm64e_slice(data: bytes) -> bytes:
    """The arm64e Mach-O inside a fat binary (or the binary itself if thin)."""
    if not is_fat(data):
        return data
    nfat = struct.unpack(">I", data[4:8])[0]
    for k in range(nfat):
        cputype, cpusub, off, size = struct.unpack(">iiII", data[8 + 20 * k: 24 + 20 * k])
        if cputype == 0x0100000C and (cpusub & 0xff) == 2:  # CPU_TYPE_ARM64 / ARM64E
            return data[off:off + size]
    raise ValueError("no arm64e slice")


def nm_symbols(path: str, flag: str) -> set:
    out = subprocess.run(["nm", "-arch", "arm64e", flag, path], capture_output=True, text=True).stdout
    return {line.split()[-1] for line in out.splitlines() if line.strip()}


class SymbolReport:
    """What the analysis concluded for one (original, replacement) pair.
    kind: "exported" (defined by the kext), "absent" (not imported), "bool"
    (C bool return) or "object" (OSObject* return, see verdicts/worst)."""

    def __init__(self, ori_sym, new_sym, kind, verdicts=()):
        self.ori_sym, self.new_sym, self.kind = ori_sym, new_sym, kind
        self.name, self.fuzz = ori_sym.decode(), new_sym.decode()
        self.verdicts = list(verdicts)  # (verdict, reason, call address)
        self.worst = max((v for v, _, _ in self.verdicts), key=[SAFE, UNKNOWN, UNSAFE].index) \
            if self.verdicts else None

    def hookable(self, force: bool) -> bool:
        if self.kind == "bool":
            return True
        if self.kind == "object":
            return self.worst == SAFE or (self.worst == UNKNOWN and force)
        return False


def analyze_symbols(input_binary: str) -> list:
    imported = nm_symbols(input_binary, "-u")
    defined = nm_symbols(input_binary, "-gU")
    dis = None
    reports = []
    for ori_sym, new_sym in ENTITLEMENT_PATCHES:
        name = ori_sym.decode()
        if name in defined:
            reports.append(SymbolReport(ori_sym, new_sym, "exported"))
        elif name not in imported:
            reports.append(SymbolReport(ori_sym, new_sym, "absent"))
        elif ori_sym in BOOL_RETURNING:
            reports.append(SymbolReport(ori_sym, new_sym, "bool"))
        else:
            dis = dis or Disassembly(input_binary)
            sites = dis.call_sites(name)
            if sites:
                verdicts = [(*analyze_site(dis, i), dis.insns[i].addr) for i in sites]
            else:
                verdicts = [(UNKNOWN, "imported but no direct call site found", None)]
            reports.append(SymbolReport(ori_sym, new_sym, "object", verdicts))
    return reports


def print_plan(reports: list, force: bool) -> list:
    """Print the per-symbol decision; return the (ori, new) pairs to patch."""
    approved = []
    for r in reports:
        if r.kind == "absent":
            continue
        if r.kind == "exported":
            print(f"[skip]   {r.name}: defined/exported by this kext, renaming it would break its importers")
            continue
        if r.kind == "bool":
            print(f"[hook]   {r.name}: returns a C bool")
            approved.append((r.ori_sym, r.new_sym))
            continue
        for v, why, addr in r.verdicts:
            where = f"call @{addr:#x}" if addr is not None else "-"
            print(f"         {where:<16} {v:<8} {why}")
        if r.hookable(force):
            tag = "[hook]  " if r.worst == SAFE else "[force] "
            n = len([a for _, _, a in r.verdicts if a is not None])
            print(f"{tag} {r.name}: {n} call site(s), all {'safe' if r.worst == SAFE else 'safe or unknown'}")
            approved.append((r.ori_sym, r.new_sym))
        else:
            hint = " (use --force to hook anyway)" if r.worst == UNKNOWN else ""
            print(f"[skip]   {r.name}: result is not used as a plain yes/no answer{hint}")
    return approved


def all_offsets(kext_bytes: bytearray, sym: bytes) -> list:
    # Only exact, NUL-delimited symbol strings, so a name that is a substring of
    # a longer symbol is never touched.
    offsets = []
    start = 0
    while True:
        i = kext_bytes.find(sym, start)
        if i == -1:
            break
        if kext_bytes[i - 1] == 0 and kext_bytes[i + len(sym)] == 0:
            offsets.append(i)
        start = i + 1  # allow overlapping/adjacent matches
    return offsets


def edit_entitle(kext_bytes: bytearray, patches: list) -> bytearray:
    for ori_sym, new_sym in patches:
        offsets = all_offsets(kext_bytes, ori_sym)
        if not offsets:
            print(f"{ori_sym!r} not found, no patch needed")
            continue
        print(f"{ori_sym!r} found at {len(offsets)} location(s)")
        kext_bytes = edit_got(kext_bytes, ori_sym, new_sym, offsets)
    return kext_bytes


def print_dry_run(input_bytes: bytes, patches: list):
    """Show exactly which bytes of the arm64e slice a real run would rewrite."""
    print()
    if not patches:
        print("dry run: nothing would be patched")
        return
    slice_bytes = arm64e_slice(input_bytes)
    for ori_sym, new_sym in patches:
        offs = all_offsets(bytearray(slice_bytes), ori_sym)
        print(f"dry run: {ori_sym.decode()} -> {new_sym.decode()}")
        print(f"         {len(offs)} location(s) in the arm64e slice: {', '.join(hex(o) for o in offs)}")


# ---------------------------------------------------------------------------
# Verification of an already patched binary
# ---------------------------------------------------------------------------

def bundle_info_plist(binary: str):
    """<X>.kext/Contents/MacOS/<exe> -> <X>.kext/Contents/Info.plist, if that layout."""
    macos = os.path.dirname(os.path.abspath(binary))
    contents = os.path.dirname(macos)
    if os.path.basename(macos) == "MacOS" and os.path.basename(contents) == "Contents":
        plist = os.path.join(contents, "Info.plist")
        return plist if os.path.isfile(plist) else None
    return None


def pishi_exports(pishi: str) -> set:
    if os.path.isdir(pishi):  # Pishi.kext bundle
        with open(os.path.join(pishi, "Contents", "Info.plist"), "rb") as f:
            exe = plistlib.load(f)["CFBundleExecutable"]
        pishi = os.path.join(pishi, "Contents", "MacOS", exe)
    return nm_symbols(pishi, "-gU")


def verify(original: str, patched: str, pishi=None) -> bool:
    """Check that `patched` is `original` with exactly the hooks the analysis
    allows, and that it can link against Pishi. Prints one line per check."""
    failures, warnings = [], []

    def ok(msg):
        print(f"[ok]     {msg}")

    def fail(msg):
        failures.append(msg)
        print(f"[FAIL]   {msg}")

    def warn(msg):
        warnings.append(msg)
        print(f"[warn]   {msg}")

    reports = analyze_symbols(original)
    orig_imp, orig_def = nm_symbols(original, "-u"), nm_symbols(original, "-gU")
    pat_imp, pat_def = nm_symbols(patched, "-u"), nm_symbols(patched, "-gU")

    # 1. each entitlement API: hooked iff the analysis allows it
    hooked = []
    for r in reports:
        is_hooked, still_orig = r.fuzz in pat_imp, r.name in pat_imp
        if r.kind == "absent":
            if is_hooked:
                fail(f"{r.fuzz} imported although the original never imported {r.name}")
            continue
        if r.kind == "exported":
            if r.name in pat_def:
                ok(f"{r.name}: still exported (kext defines it, must not be renamed)")
            else:
                fail(f"{r.name}: exported by the original but renamed in the patched binary")
            continue
        if is_hooked and still_orig:
            fail(f"{r.name}: only partially hooked (both {r.name} and {r.fuzz} imported)")
            continue
        if is_hooked:
            hooked.append(r)
            if r.kind == "bool" or r.worst == SAFE:
                ok(f"{r.name}: hooked ({'C bool' if r.kind == 'bool' else 'all call sites safe'})")
            elif r.worst == UNKNOWN:
                warn(f"{r.name}: hooked although some call sites are UNKNOWN (was --force used on purpose?)")
            else:
                bad = [f"{a:#x}" for v, _, a in r.verdicts if v == UNSAFE]
                fail(f"{r.name}: hooked but UNSAFE call site(s) at {', '.join(bad)}")
        elif still_orig:
            if r.hookable(force=False):
                fail(f"{r.name}: safe to hook but not hooked")
            else:
                ok(f"{r.name}: left unhooked ({r.worst}), as expected")
        else:
            fail(f"{r.name}: neither original nor replacement imported in the patched binary")

    # 2. nothing else in the symbol tables changed
    renames = {r.name: r.fuzz for r in hooked}
    if pat_def != orig_def:
        fail(f"exported symbols differ: -{sorted(orig_def - pat_def)} +{sorted(pat_def - orig_def)}")
    else:
        ok(f"exported symbols unchanged ({len(orig_def)})")
    expected_imp = {renames.get(s, s) for s in orig_imp}
    if pat_imp != expected_imp:
        fail(f"unexpected import changes: -{sorted(expected_imp - pat_imp)} +{sorted(pat_imp - expected_imp)}")
    else:
        ok(f"imports unchanged apart from the hooks ({len(orig_imp)})")

    # 3. byte-level: only the hooked symbol strings differ
    with open(original, "rb") as f:
        a = arm64e_slice(f.read())
    with open(patched, "rb") as f:
        b = arm64e_slice(f.read())
    if len(a) != len(b):
        fail(f"arm64e slice size changed ({len(a)} -> {len(b)} bytes)")
    else:
        allowed = set()
        for r in hooked:
            for o in all_offsets(bytearray(a), r.ori_sym):
                if b[o:o + len(r.new_sym)] == r.new_sym:
                    allowed.update(range(o, o + len(r.new_sym)))
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        stray = [i for i in diff if i not in allowed]
        if stray:
            fail(f"{len(stray)} byte(s) changed outside the hooked symbol strings, first at {stray[0]:#x}")
        else:
            ok(f"only the hooked symbol strings changed ({len(diff)} byte(s))")

    # 4. the bundle must depend on Pishi, and Pishi must export the stubs
    if hooked:
        plist = bundle_info_plist(patched)
        if plist is None:
            warn("patched binary is not inside a .kext bundle, cannot check its Pishi dependency")
        else:
            with open(plist, "rb") as f:
                libs = plistlib.load(f).get("OSBundleLibraries", {})
            if "Kcov.macOS.Pishi" in libs:
                ok("Info.plist: OSBundleLibraries has Kcov.macOS.Pishi")
            else:
                fail("Info.plist: OSBundleLibraries lacks Kcov.macOS.Pishi, the hooks will not link")
        if pishi:
            missing = [r.fuzz for r in hooked if r.fuzz not in pishi_exports(pishi)]
            if missing:
                fail(f"Pishi does not export: {', '.join(missing)}")
            else:
                ok("Pishi exports every hook target")

    print()
    if failures:
        print(f"VERIFY FAILED: {len(failures)} failure(s), {len(warnings)} warning(s)")
    else:
        print(f"VERIFY OK ({len(hooked)} hook(s), {len(warnings)} warning(s))")
    return not failures


def main():
    parser = argparse.ArgumentParser(
        description="Redirect a kext's entitlement checks to Pishi's always-entitled stubs, "
                    "skipping any API whose result the kext uses as more than a yes/no answer.",
        epilog="examples:\n"
               "  %(prog)s KDK/IOSurface IOSurface             patch\n"
               "  %(prog)s --dry-run KDK/IOSurface             show what would be hooked and where\n"
               "  %(prog)s --verify KDK/IOSurface IOSurface \\\n"
               "           --pishi Extensions/Pishi/Pishi.kext check an already patched binary",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input_binary", help="original kext Mach-O (universal or thin)")
    parser.add_argument("output_path", nargs="?",
                        help="where to write the patched arm64e binary (with --verify: the patched binary)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true",
                      help="print the call-site analysis and the bytes that would change, write nothing")
    mode.add_argument("--verify", action="store_true",
                      help="check that output_path is input_binary correctly hooked; exit 1 on failure")
    parser.add_argument("--force", action="store_true",
                        help="also hook APIs whose call sites could not be classified (never UNSAFE ones)")
    parser.add_argument("--pishi", help="with --verify: Pishi.kext (or its binary) to check the stubs are exported")
    args = parser.parse_args()
    if not args.dry_run and not args.output_path:
        parser.error("output_path is required unless --dry-run is given")

    input_binary = args.input_binary
    output_path = args.output_path

    with open(input_binary, "rb") as f:
        input_bytes = f.read()
    if not (is_fat(input_bytes) or is_macho(input_bytes)):
        print("Input is neither a fat binary nor a Mach-O file", file=sys.stderr)
        sys.exit(1)

    if args.verify:
        sys.exit(0 if verify(input_binary, output_path, args.pishi) else 1)

    patches = print_plan(analyze_symbols(input_binary), args.force)
    if args.dry_run:
        print_dry_run(input_bytes, patches)
        return

    if is_fat(input_bytes):
        # Universal binary: extract the arm64e slice into output_path.
        result = subprocess.run(["lipo", "-extract", "arm64e", "-output", output_path, input_binary])
        if result.returncode != 0:
            print(f"Error running lipo command: {result.returncode}", file=sys.stderr)
            sys.exit(1)
        with open(output_path, "rb") as f:
            kext_bytes = bytearray(f.read())
    else:
        # Already a thin Mach-O: nothing to extract, operate on it directly.
        kext_bytes = bytearray(input_bytes)

    kext_bytes = edit_entitle(kext_bytes, patches)

    with open(output_path, "wb") as f:
        f.write(kext_bytes)
    os.chmod(output_path, 0o755)

    print(f"Edited kext saved in {output_path}")


if __name__ == "__main__":
    main()
