#!/usr/bin/env python3
"""cloakcrack — derive and apply the CloakBrowser license patch, self verifiably.

    cloakcrack.py derive  <container>  --out sites.json
    cloakcrack.py patch   <container>  --sites sites.json
    cloakcrack.py verify  <container>  --probe probe.html

The license runtime is native C++ inside the browser binary. Every denial path
calls one local noreturn wrapper (exit codes 76 seat limit / 77 missing key /
78 transport / 79 other) and the browser dies before Playwright sees a page.

A denial is defused by replacing the wrapper call with a branch to the enclosing
function's epilogue, so the caller continues in its default (unlicensed) state.

Nothing is hardcoded per version: the license functions are found through the
`/api/license/session/*` string anchors, and the wrapper is identified by shape
(it is the only heavily called, tiny, ret-less local function whose call sites
load a small immediate exit code into the first argument register).
"""

from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

ARM64, X64 = "arm64", "x64"
PAD = 0xCC  # int3 padding on every platform; also what arm64 pads with in Mach-O

# Message strings that only the license runtime references.
ANCHORS = [
    b"/api/license/session/start",
    b"/api/license/session/end",
    b"/api/license/session/heartbeat",
    b"CLOAKBROWSER_LICENSE_KEY",
    b"CLOAKBROWSER_LICENSE_API",
    b"CLOAKBROWSER_LICENSE_STATUS_FILE",
    b"BlockUntilFingerprintTableKeyResolved",
    b"k_wrapped",
    b"install_id",
]
# Exit codes the wrapper is called with, plus neighbours seen in the runtime.
CODE_RANGE = range(0x40, 0x60)
WRAPPER_MAX_LEN = 48


class Fatal(RuntimeError):
    pass


# --------------------------------------------------------------------------- #
# Containers
# --------------------------------------------------------------------------- #
@dataclass
class Seg:
    name: str
    addr: int
    off: int
    size: int


@dataclass
class Bin:
    path: Path
    data: bytearray
    kind: str  # macho | elf | pe
    arch: str
    segs: list[Seg] = field(default_factory=list)

    def seg_of(self, va: int) -> Seg | None:
        for s in self.segs:
            if s.addr <= va < s.addr + s.size:
                return s
        return None

    def fileoff(self, va: int) -> int:
        s = self.seg_of(va)
        if s is None:
            raise Fatal(f"{va:#x} outside mapped segments")
        return s.off + (va - s.addr)

    def read(self, va: int, n: int) -> bytes:
        p = self.fileoff(va)
        return bytes(self.data[p : p + n])

    def code(self) -> Seg:
        for s in self.segs:
            if s.name in ("__text", ".text", "text"):
                return s
        for s in self.segs:  # Mach-O section table absent: whole __TEXT is code+rodata
            if s.name == "__TEXT":
                return s
        raise Fatal("no code segment")

    _cache: dict = field(default_factory=dict)

    def code_blob(self) -> memoryview:
        seg = self.code()
        if "blob" not in self._cache:
            raw = bytes(self.data[seg.off : seg.off + seg.size])
            self._cache["blob"] = memoryview(raw[: len(raw) // 4 * 4])
        return self._cache["blob"]

    def code_base(self) -> int:
        return self.code().addr

    def word(self, va: int) -> int | None:
        seg = self.code()
        i = va - seg.addr
        if i < 0 or i % 4 or i + 4 > seg.size:
            return None
        return struct.unpack_from("<I", self.code_blob(), i)[0]

    def save(self) -> None:
        self.path.write_bytes(bytes(self.data))


def open_bin(path: Path) -> Bin:
    data = bytearray(path.read_bytes())
    magic = bytes(data[:4])
    if magic[:4] == b"\xca\xfe\xba\xbe":
        raise Fatal("fat Mach-O: slice it first (lipo -thin)")
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return _macho(path, data)
    if magic == b"\x7fELF":
        return _elf(path, data)
    if magic[:2] == b"MZ":
        return _pe(path, data)
    raise Fatal("unrecognised container")


def _macho(path: Path, data: bytearray) -> Bin:
    is64 = data[0:4] == b"\xcf\xfa\xed\xfe"
    ncmds = struct.unpack_from("<I", data, 0x10)[0]
    cputype = struct.unpack_from("<I", data, 4)[0]
    arch = ARM64 if cputype == 0x0100000C else X64
    b = Bin(path, data, "macho", arch)
    off = 0x20 if is64 else 0x1C
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            name = data[off + 8 : off + 24].split(b"\0")[0].decode()
            addr, sz, foff = struct.unpack_from("<QQQ", data, off + 24)
            if sz:
                b.segs.append(Seg(name, addr, foff, sz))
                nsec = struct.unpack_from("<I", data, off + 64)[0]
                for k in range(nsec):
                    so = off + 72 + k * 80
                    sname = data[so : so + 16].split(b"\0")[0].decode()
                    saddr, ssize, soff = struct.unpack_from("<QQI", data, so + 32)
                    if ssize:
                        b.segs.append(Seg(sname, saddr, soff, ssize))
        elif cmd == 0x1:  # LC_SEGMENT
            name = data[off + 8 : off + 24].split(b"\0")[0].decode()
            addr, sz, foff = struct.unpack_from("<III", data, off + 24)
            if sz:
                b.segs.append(Seg(name, foff, foff, sz))
        off += size
    return b


def _elf(path: Path, data: bytearray) -> Bin:
    # section headers map file offset -> vaddr for a static PIE
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    machine = struct.unpack_from("<H", data, 0x12)[0]
    if machine != 0x3E:
        raise Fatal(f"unsupported ELF machine {machine}")
    hdrs = [struct.unpack_from("<IIQQQQ", data, shoff + i * shentsize) for i in range(shnum)]
    strtab = hdrs[shstrndx]
    b = Bin(path, data, "elf", X64)
    for nameoff, _typ, _flags, addr, off, size in hdrs:
        p = off and strtab[4] + nameoff
        try:
            name = data[p : data.index(b"\0", p)].decode() if p else ""
        except ValueError:
            name = ""
        name = name or f"sec{len(b.segs)}"
        if size:
            b.segs.append(Seg(name, addr, off, size))  # addr != off: map properly
    return b


def _pe(path: Path, data: bytearray) -> Bin:
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe : pe + 4] != b"PE\0\0":
        raise Fatal("MZ without PE header")
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    if machine != 0x8664:
        raise Fatal(f"unsupported PE machine {machine:#x}")
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    base = pe + 24 + optsz
    b = Bin(path, data, "pe", X64)
    for i in range(nsec):
        off = base + i * 40
        name = data[off : off + 8].split(b"\0")[0].decode()
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        if rawsize:
            b.segs.append(Seg(name, rawptr, rawptr, rawsize))
    return b


# --------------------------------------------------------------------------- #
# Disassembly helpers
# --------------------------------------------------------------------------- #
def insns(b: Bin, start: int, count: int) -> list[tuple[int, int, str]]:
    """Linear sweep. Returns (addr, wordsize, enc) with enc = 32/64-bit int."""
    out: list[tuple[int, int, str]] = []
    if b.arch == ARM64:
        for i in range(count):
            va = start + i * 4
            w = b.word(va)
            if w is None:
                break
            out.append((va, 4, struct.pack("<I", w).hex()))
    elif b.kind == "pe":
        out = _capstone(b, start, count)  # llvm-objdump gives up on big PE images
    else:
        # x86 needs a real decoder; delegate to llvm-objdump (same start-address
        # sweep, which resynchronises correctly from a function boundary).
        out = _objdump(b, start, count)
    return out


def _capstone(b: Bin, start: int, count: int) -> list[tuple[int, int, str]]:
    import capstone

    blob = b.read(start, count)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = False
    out: list[tuple[int, int, str]] = []
    for ins in md.disasm(blob, start):
        out.append((ins.address, ins.size, ins.bytes.hex() + "|" + ins.mnemonic + " " + ins.op_str))
    return out


_OD_CACHE: dict[tuple[str, int, int], list[tuple[int, int, str]]] = {}


def _objdump(b: Bin, start: int, count: int) -> list[tuple[int, int, str]]:
    key = (str(b.path), start, count)
    if key in _OD_CACHE:
        return _OD_CACHE[key]
    import subprocess

    stop = start + count * 8
    res = subprocess.run(
        ["objdump", "-d", f"--start-address={start}", f"--stop-address={stop}", str(b.path)],
        capture_output=True,
        text=True,
    )
    out: list[tuple[int, int, str]] = []
    for line in res.stdout.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)", line)
        if not m:
            continue
        va = int(m.group(1), 16)
        raw = m.group(2).split()
        enc = "".join(raw)
        text = line.split("\t")[-1].strip()
        out.append((va, len(raw), enc + "|" + text))
        if len(out) >= count:
            break
    _OD_CACHE[key] = out
    return out


PAD_WORDS = {0xCCCCCCCC, 0x00000000}


def is_pad(b: Bin, va: int) -> bool:
    """Padding check; arm64 decodes as words, x86 as bytes."""
    seg = b.code()
    i = va - seg.addr
    if i < 0 or i >= seg.size:
        return True
    if b.arch == ARM64:
        w = b.word(va)
        return w is None or w in PAD_WORDS
    return b.code_blob()[i] == PAD


RETS = {0xD65F03C0, 0xD65F0BFF, 0xD65F0FFF}
STEP = 4
BACK_LIMIT = 0x4000


def func_bounds(b: Bin, va: int) -> tuple[int, int]:
    """Enclosing function via padding, with a ret stop so a missed pad cannot
    swallow a whole segment."""
    seg = b.code()
    step = 4 if b.arch == ARM64 else 1
    rets = RETS if b.arch == ARM64 else None
    lo = va
    while lo - step > seg.addr and va - lo < BACK_LIMIT:
        prev = lo - step
        if is_pad(b, prev):
            break
        if rets:
            if b.word(prev) in rets:
                break
        elif b.code_blob()[prev - seg.addr] == 0xC3:
            break
        lo = prev
    hi = va
    while hi < seg.addr + seg.size - step and not is_pad(b, hi):
        hi += step
    return lo, hi


# --------------------------------------------------------------------------- #
# Encodings
# --------------------------------------------------------------------------- #
def bl_target(b: Bin, va: int) -> int | None:
    if b.arch == ARM64:
        w = b.word(va)
        if w is None or (w & 0xFC000000) != 0x94000000:
            return None
        imm = w & 0x03FFFFFF
        if imm & 0x02000000:
            imm -= 0x04000000
        return va + imm * 4
    raw = b.read(va, 5)
    if len(raw) < 5 or raw[0] != 0xE8:
        return None
    return va + 5 + struct.unpack("<i", raw[1:5])[0]


def as_jump(b: Bin, va: int, target: int) -> bytes:
    """Rewrite a call to an unconditional branch, same width."""
    if b.arch == ARM64:
        delta = (target - va) // 4
        if not -(1 << 25) <= delta < (1 << 25):
            raise Fatal("arm64 branch out of range")
        return struct.pack("<I", 0x14000000 | (delta & 0x03FFFFFF))
    delta = target - (va + 5)
    if not -(1 << 31) <= delta < (1 << 31):
        raise Fatal("x64 jump out of range")
    return b"\xE9" + struct.pack("<i", delta)


def call_sites_of(b: Bin, target: int, lo: int, hi: int) -> list[int]:
    """Addresses in [lo, hi) that hold `call rel32 target`.

    The linear sweep desynchronises on big PE images, and a missed call site
    is an unpatched deny path, so recover them with a byte scan: an E8 whose
    rel32 lands exactly on `target` is a call with overwhelming probability.
    """
    seg = b.code()
    blob = bytes(b.code_blob())
    out: list[int] = []
    i = max(0, lo - seg.addr)
    end = min(len(blob) - 4, hi - seg.addr)
    while i < end:
        if blob[i] == 0xE8:
            va = seg.addr + i
            if va + 5 + struct.unpack("<i", blob[i + 1 : i + 5])[0] == target:
                out.append(va)
        i += 1
    return out


def loads_code(b: Bin, va: int) -> bool:
    """True if this instruction puts a small exit code in the first arg register."""
    if b.arch == ARM64:
        w = b.word(va)
        if w is None:
            return False
        # movz w0|x0, #imm  (optionally movk follows)
        if (w & 0xFF800000) not in (0x52800000, 0xD2800000):
            return False
        return (w & 0x1F) == 0 and ((w >> 5) & 0xFFFF) in CODE_RANGE
    raw = b.read(va, 5)
    # mov r32, imm32 : B8+rd
    if 0xB8 <= raw[0] <= 0xBF:
        return raw[1] in CODE_RANGE
    return False


def ret_epilogue(b: Bin, lo: int, hi: int) -> int | None:
    """Start of the stack-restoring sequence feeding the final ret."""
    ins = insns(b, lo, max(1, (hi - lo) // 4))
    if not ins:
        return None
    if b.arch == ARM64:
        rets = [a for a, _w, e in ins if struct.unpack("<I", bytes.fromhex(e))[0] in (0xD65F03C0, 0xD65F0BFF, 0xD65F0FFF)]
    else:
        rets = [a for a, _w, e in ins if e.split("|")[-1].startswith(("ret", "rep ret"))]
    if not rets:
        return None
    end = rets[-1]
    # walk back over stack-restore instructions
    idx = [i for i, (a, _w, _e) in enumerate(ins) if a == end]
    if not idx:
        return None
    i = idx[-1]
    while i > 0:
        a, _w, e = ins[i - 1]
        text = e.split("|")[-1]
        if b.arch == ARM64:
            w = struct.unpack("<I", bytes.fromhex(e))[0]
            restore = (
                (w & 0xFFC07FFF) in (0xA9407BFD, 0xA9417BFD, 0xA9427BFD, 0xA9437BFD,
                                     0xA9447BFD, 0xA9457BFD, 0xA9467BFD, 0xA9477BFD,
                                     0xA9487BFD, 0xA9497BFD, 0xA94A7BFD, 0xA94B7BFD,
                                     0xA94C7BFD, 0xA94D7BFD, 0xA94E7BFD, 0xA94F7BFD)
                or (w & 0xFFC003FF) == 0x910003FD  # mov sp, x29
                or (w & 0xFFC07FFF) in (0xF9407BFD, 0xF9417BFD, 0xF9427BFD, 0xF9437BFD)
                or (w & 0xFFFFFC1F) == 0xD503233F  # pacibsp / autiasp family
            )
        else:
            restore = text.startswith(("pop", "leave", "add rsp", "add\t%rsp", "ldp")) or re.match(
                r"(pop|leave)|add\s+\$0x[0-9a-f]+,%rsp", text
            )
        if not restore:
            break
        i -= 1
    return ins[i][0]


# --------------------------------------------------------------------------- #
# Exit stubs: the anchor that actually identifies the wrapper
# --------------------------------------------------------------------------- #
EXIT_NAMES = {"exit", "_exit", "__exit", "_Exit", "abort", "_abort"}


def exit_stubs(b: Bin) -> set[int]:
    """Addresses that terminate the process: Mach-O __stubs, ELF .plt, PE IAT."""
    if b.kind == "macho":
        return _macho_stubs(b)
    if b.kind == "elf":
        return _elf_stubs(b)
    return _pe_iat(b)


def _macho_stubs(b: Bin) -> set[int]:
    """Symbol -> address via `otool -Iv` (indirect table), kept to stub sections."""
    import subprocess

    res = subprocess.run(["otool", "-Iv", str(b.path)], capture_output=True, text=True)
    stub_secs = [s for s in b.segs if s.name in ("__stubs", "__auth_stubs")]
    if not stub_secs:
        return set()
    out: set[int] = set()
    for line in res.stdout.splitlines():
        m = re.match(r"\s*(0x[0-9a-f]+)\s+\d+\s+(\S+)\s*$", line)
        if not m:
            continue
        name = m.group(2)
        if name not in EXIT_NAMES:
            continue
        addr = int(m.group(1), 16)
        if any(sec.addr <= addr < sec.addr + sec.size for sec in stub_secs):
            out.add(addr)
        else:  # a __got slot: the call goes through it, patch the same way
            out.add(addr)
    return out


def _elf_stubs(b: Bin) -> set[int]:
    data = b.data
    out: set[int] = set()
    plts = [s for s in b.segs if s.name == ".plt"]
    rela = [s for s in b.segs if s.name == ".rela.plt"]
    dsym = [s for s in b.segs if s.name == ".dynsym"]
    dstr = [s for s in b.segs if s.name == ".dynstr"]
    if not (plts and rela and dsym and dstr):
        return out
    plt, ds, dstrs = plts[0], dsym[0], dstr[0]
    for i in range(rela[0].size // 24):
        off, info, _ = struct.unpack_from("<QQq", data, rela[0].off + i * 24)
        sym = info >> 32
        if sym >= ds.size // 24:
            continue
        name_off = struct.unpack_from("<I", data, ds.off + sym * 24)[0]
        name = bytes(data[dstrs.off + name_off : dstrs.off + name_off + 32]).split(b"\0")[0].decode(
            errors="ignore"
        )
        if name not in EXIT_NAMES:
            continue
        # several stubs can jump through the same GOT slot (twin PLT groups);
        # keep them all so the real call target is always in the set
        for o in range(plt.off, plt.off + plt.size - 6, 16):
            if data[o] == 0xFF and data[o + 1] == 0x25:
                disp = struct.unpack_from("<i", data, o + 2)[0]
                if plt.addr + (o - plt.off) + 6 + disp == off:
                    out.add(plt.addr + (o - plt.off))
    return out


def _pe_iat(b: Bin) -> set[int]:
    data = b.data
    out: set[int] = set()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optsz = struct.unpack_from("<H", data, pe + 20)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    dirs = opt + (0x70 if magic == 0x20B else 0x60)
    imp_rva = struct.unpack_from("<I", data, dirs + 8)[0]
    if not imp_rva:
        return out
    for s in b.segs:  # rva -> file offset for the section that holds imports
        if s.name == ".idata":
            import rva2off
            break
    def to_off(rva: int) -> int:
        sec_hdr = pe + 24 + optsz
        for i in range(struct.unpack_from("<H", data, pe + 6)[0]):
            o = sec_hdr + i * 40
            vaddr, vsize, raw = struct.unpack_from("<III", data, o + 12)
            if vaddr <= rva < vaddr + max(vsize, raw):
                return raw + (rva - vaddr)
        return rva
    o = to_off(imp_rva)
    while True:
        names_rva, _ts, _fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", data, o)
        if not (names_rva or name_rva or iat_rva):
            break
        if iat_rva:
            n_o = to_off(names_rva)
            k = 0
            while True:
                entry = struct.unpack_from("<Q", data, n_o + k * 8)[0]
                if entry == 0:
                    break
                if entry >> 63 == 0:
                    no = to_off((entry & 0x7FFFFFFF) + 2)
                    nm = bytes(data[no : no + 24]).split(b"\0")[0].decode(errors="ignore")
                    if nm in EXIT_NAMES:
                        out.add((b.segs and next(s for s in b.segs if s.name == ".text").addr) and iat_rva + k * 8)
                k += 1
        o += 20
    return out


# --------------------------------------------------------------------------- #
# Derivation
# --------------------------------------------------------------------------- #
def anchor_vaddrs(b: Bin) -> list[int]:
    out: list[int] = []
    blob = bytes(b.data)
    for a in ANCHORS:
        for s in b.segs:
            if s.name in ("__text", ".text", "text"):
                continue
            i = bytes(blob[s.off : s.off + s.size]).find(a)
            while i != -1:
                out.append(s.addr + i)
                i = bytes(blob[s.off : s.off + s.size]).find(a, i + 1)
    return sorted(set(out))


def xrefs(b: Bin, targets: set[int]) -> list[int]:
    seg = b.code()
    out: list[int] = []
    if b.arch == ARM64:
        blob = b.code_blob()
        arr = memoryview(blob).cast("I")
        n = len(arr) - 1
        for i in range(n):
            w = arr[i]
            if (w & 0x9F000000) != 0x90000000:  # adrp
                continue
            va = seg.addr + i * 4
            page = (va & ~0xFFF) + ((((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)) * 0x1000
            nxt = arr[i + 1]
            if (nxt & 0x7F800000) != 0x11000000:  # add imm
                continue
            imm = (nxt >> 10) & 0xFFF
            if (nxt >> 22) & 1:
                imm <<= 12
            if page + imm in targets:
                out.append(va)
    else:
        for va in range(seg.addr, seg.addr + seg.size - 7):
            raw = b.read(va, 3)
            if raw[0] in (0x48, 0x4C, 0x49, 0x4D) and raw[1] == 0x8D and raw[2] in (
                0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D
            ):
                if va + 7 + struct.unpack("<i", b.read(va + 3, 4))[0] in targets:
                    out.append(va)
    return out


def is_ret(b: Bin, va: int) -> bool:
    if b.arch == ARM64:
        return b.word(va) in RETS
    raw = b.read(va, 2)
    return bool(raw) and (raw[0] == 0xC3 or (raw[0] == 0xF3 and len(raw) > 1 and raw[1] == 0xC3))


def is_restore(b: Bin, va: int) -> bool:
    if b.arch == ARM64:
        w = b.word(va)
        if w is None:
            return False
        rn = (w >> 5) & 0x1F
        ldp_sp = (w & 0xFFC00000) in (0xA9400000, 0xA8C00000, 0xA9C00000) and rn == 31
        ldr_sp = (w & 0xFFC00000) == 0xF9400000 and rn == 31
        add_sp = (w & 0x7FE003FF) == 0x110003FF or (w & 0xFFC003FF) == 0x910003FF
        mov_sp = (w & 0xFFC003FF) == 0x910003FD
        pac = w in (0xD503233F, 0xD50323BF, 0xD50323FF, 0xD65F0BFF, 0xD65F0FFF)
        return ldp_sp or ldr_sp or add_sp or mov_sp or pac
    raw = b.read(va, 8)
    if not raw:
        return False
    if raw[0] == 0xC9:  # leave
        return True
    if len(raw) >= 2 and raw[0] == 0x41 and 0x58 <= raw[1] <= 0x5F:  # pop r8-r15
        return True
    if 0x58 <= raw[0] <= 0x5F:  # pop r64
        return True
    if len(raw) >= 4 and raw[0] == 0x48 and raw[1] in (0x81, 0x83) and raw[2] == 0xC4:
        return True  # add rsp, imm
    return False


RESTORE_LDP = {0xA9407BFD, 0xA9417BFD, 0xA9427BFD, 0xA9437BFD, 0xA9447BFD, 0xA9457BFD,
               0xA9467BFD, 0xA9477BFD, 0xA9487BFD, 0xA9497BFD, 0xA94A7BFD, 0xA94B7BFD,
               0xA94C7BFD, 0xA94D7BFD, 0xA94E7BFD, 0xA94F7BFD,
               0xF9407BFD, 0xF9417BFD, 0xF9427BFD, 0xF9437BFD,
               0xD503233F, 0xD50323BF, 0xD50323FF}


def jmp_target(b: Bin, va: int) -> int | None:
    if b.arch == ARM64:
        w = b.word(va)
        if w is not None and (w & 0xFC000000) == 0x14000000:  # b (unconditional)
            imm = w & 0x03FFFFFF
            if imm & 0x02000000:
                imm -= 0x04000000
            return va + imm * 4
        return bl_target(b, va)
    raw = b.read(va, 5)
    if len(raw) == 5 and raw[0] == 0xE9:
        return va + 5 + struct.unpack("<i", raw[1:])[0]
    return bl_target(b, va)


def _walk_back(b: Bin, ret_va: int, span: int = 0x60) -> int:
    """Start of the stack-restore run that feeds this ret. x86 is variable
    length, so walk a decoded list instead of address arithmetic."""
    if b.arch == ARM64:
        start = ret_va
        while start > ret_va - span and is_restore(b, start - 4):
            start -= 4
        return start
    # byte-wise backwards: capstone cannot always start mid-stream here, and the
    # restore run (add rsp,imm / pop r64 / leave) is unambiguous byte-wise
    va = ret_va - 1
    limit = ret_va - span
    while va > limit:
        if b.read(va, 1) == b"\xc9":  # leave
            va -= 1
            continue
        if len(b.read(va - 1, 2)) == 2 and b.read(va - 1, 1) == b"\x41":
            if 0x58 <= b.read(va, 1)[0] <= 0x5F:  # pop rN
                va -= 2
                continue
        if 0x58 <= b.read(va, 1)[0] <= 0x5F:  # pop r64
            va -= 1
            continue
        # add rsp, imm32 / imm8 whose immediate ends exactly here
        tail7 = b.read(va - 6, 7)
        tail4 = b.read(va - 3, 4)
        if len(tail7) == 7 and tail7[:3] == b"\x48\x81\xc4":
            va -= 7
            continue
        if len(tail4) == 4 and tail4[:3] == b"\x48\x83\xc4":
            va -= 4
            continue
        break
    return va + 1 if va + 1 <= ret_va else ret_va


def epilogue_after(b: Bin, site: int, cap: int = 0x3000) -> int | None:
    """First return path at or after `site`: either a ret (return the start of
    its restore sequence) or an unconditional branch to one."""
    seg = b.code()
    end = min(seg.addr + seg.size, site + cap)
    if b.arch == ARM64:
        back = site - 4
        while back > site - cap and back > seg.addr:
            if is_ret(b, back):
                return _walk_back(b, back)
            back -= 4
        va = site
        while va < end:
            if is_ret(b, va):
                return _walk_back(b, va)
            raw = b.read(va, 4)
            if raw and (struct.unpack("<I", raw)[0] & 0xFC000000) == 0x14000000:
                imm = struct.unpack("<I", raw)[0] & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                dest = va + imm * 4
                if dest > site and is_ret(b, dest):
                    return _walk_back(b, dest)
            va += 4
        return None
    # x86 is variable length: a raw byte scan hits 0xC3 inside call rel32
    # operands, so sweep on decoded boundaries only.
    # Prefer the function's own epilogue: the deny block usually sits after its
    # ret, so look for the last ret before the site first.
    back = None
    for cur, _w, _t in insns(b, max(seg.addr, site - 0x800), min(0x800 + 16, site - seg.addr)):
        if cur < site and is_ret(b, cur):
            back = cur
    if back is not None:
        # bound by the enclosing function: int3/ud2 padding marks its start
        bound = max(seg.addr, site - 0x2000)
        run = 0
        off = site
        while off > bound:
            b1 = b.read(off, 1)
            if b1 in (b"\xcc", b"\x0f"):
                run += 1
                if run >= 2:
                    bound = off + 1
                    break
            else:
                run = 0
            off -= 1
        if back >= bound:
            return _walk_back(b, back)

    # The site may sit inside a loop or an inlined block, so chase forward to
    # the END of the enclosing function (marked by int3 padding) and use the
    # last return on the way.
    last = None
    pad = 0
    va = site
    for _hop in range(8):
        moved = False
        for cur, _w, text in insns(b, va, min(cap, end - va)):
            raw = b.read(cur, 1)
            if raw in (b"\xcc", b"\x0f"):
                pad += 1
                if pad >= 2 and last is not None:
                    return _walk_back(b, last)
                continue
            pad = 0
            if is_ret(b, cur):
                last = cur
                continue
            if text.split("|")[-1].startswith("jmp"):
                dest = jmp_target(b, cur)
                if dest is not None and cur < dest < end:
                    if is_ret(b, dest):
                        return _walk_back(b, dest)
                    va = dest
                    moved = True
                    break
        if not moved:
            break
    return _walk_back(b, last) if last else None


def head_insns(b: Bin, start: int, count: int) -> list[tuple[int, bytes]]:
    step = 4 if b.arch == ARM64 else 0x40
    if b.arch == ARM64:
        return [(start + i * 4, b.read(start + i * 4, 4)) for i in range(count)]
    rows = insns(b, start, step * count)
    return [(va, bytes.fromhex(e.split("|")[0])) for va, _w, e in rows[:count]]


def ends_with_ret(b: Bin, va: int) -> bool:
    return b.read(va, 1) == b"\xc3" or b.read(va, 2) == b"\xf3\xc3"


def wait_sites(b: Bin) -> list[int]:
    seg = b.code()
    out: list[int] = []
    if b.arch == ARM64:
        # arm64 has no inline 32-bit literal: the 31 s TimeDelta is built with
        # movz (low half) + movk (high half). Scan for that pair on any reg.
        raw = bytes(b.code_blob())
        lo16, hi16 = WAIT_US & 0xFFFF, WAIT_US >> 16
        for off in range(0, len(raw) - 7, 4):
            w = struct.unpack_from("<I", raw, off)[0]
            if (w & 0xFF800000) != 0x52800000 or ((w >> 5) & 0xFFFF) != lo16:
                continue
            reg = w & 0x1F
            nxt = struct.unpack_from("<I", raw, off + 4)[0]
            if (nxt & 0xFFE00000) == 0x72A00000 and (nxt & 0x1F) == reg and ((nxt >> 5) & 0xFFFF) == hi16:
                out.append(seg.addr + off)
        return out
    raw = bytes(b.code_blob())
    pat = struct.pack("<I", WAIT_US)
    i = raw.find(pat)
    while i >= 0:
        out.append(seg.addr + i)
        i = raw.find(pat, i + 1)
    return out


def derive(b: Bin) -> dict:
    # Primary anchors: the license-runtime strings. These are the only
    # version-specific inputs, so when they drift we fall back to the
    # fingerprint-table wait constant (31 s TimeDelta), which is a unique
    # numeric literal that sits in the middle of the license code on every
    # platform and has survived every version so far.
    av = anchor_vaddrs(b)
    xr = xrefs(b, set(av)) if av else []
    if xr:
        span_lo = min(xr) - 0x400
        span_hi = max(xr) + 0x400
    else:
        # the compiler emits no rip-relative leas to these strings on win/elf,
        # and a future macOS rename would drop the anchors entirely: either way
        # the wait constant alone pins the license window.
        sites = wait_sites(b)
        if not sites:
            raise Fatal(
                "no license-anchor xrefs and no fingerprint-table wait "
                "constant — wrong binary or the runtime changed shape"
            )
        span_lo = min(sites) - 0x30000
        span_hi = max(sites) + 0x30000
        if not av:
            print("# anchors drifted; deriving from the wait constant alone")

    # every call out of the license code window
    calls: dict[int, list[int]] = {}
    if b.arch == ARM64:
        addrs = [va for va in range(span_lo, span_hi, 4) if not is_pad(b, va)]
    else:
        addrs = [a for a, _w, _e in insns(b, span_lo, (span_hi - span_lo))]
    for va in addrs:
        t = bl_target(b, va)
        if t is not None:
            calls.setdefault(t, []).append(va)

    exits = exit_stubs(b)
    scored = []
    for tgt, sites in calls.items():
        if span_lo <= tgt < span_hi:
            continue  # local block, not a wrapper
        head = head_insns(b, tgt, 6)
        if any(ends_with_ret(b, va) for va, _r in head):
            continue  # returns, so not the noreturn wrapper
        with_code = sum(1 for s in sites if s >= 4 and loads_code(b, s - 4))
        # the real wrapper is a stub: a few instructions then a tail call to
        # exit/_exit. Anything that runs on before terminaing is a logger.
        head = head_insns(b, tgt, 64)
        depth = 24
        calls_exit = False
        has_call = False
        indirect_at = None
        for i, (va, _raw) in enumerate(head):
            t2 = bl_target(b, va)
            if t2 is not None:
                has_call = True
                depth = i + 1
                if t2 in exits and depth <= 6:
                    calls_exit = True  # a deny stub exits almost immediately
                break
            if _raw[:1] == b"\xff":  # call [rip+n]
                has_call = True
                depth = i + 1
                indirect_at = i
                break
            if _raw in (b"\xcc", b"\x0f"):
                depth = i + 1
                break
        # win64 reaches exit through the IAT, so no direct call resolves: accept
        # an indirect call immediately followed by int3/ud2 instead
        if indirect_at is not None and b.kind == "pe":
            seq = [r for _v, r in head[:24]]
            if not any(r == b"\xc3" for r in seq) and any(r in (b"\xcc", b"\x0f") for r in seq):
                calls_exit = True  # indirect exit call, no return, int3 right after
        ret_soon = any(is_ret(b, va) for va, _r in head[:24])
        scored.append((1 if calls_exit else 0, with_code / len(sites), -depth, len(sites), tgt, sites, ret_soon))
    if not scored:
        raise Fatal("no wrapper candidate")
    scored.sort(key=lambda r: (r[0], r[1], r[2], r[3]), reverse=True)
    exits_ok, ratio, negdepth, count, wrapper, sites = scored[0][:6]
    if not exits_ok:
        raise Fatal(f"no wrapper tail-calls exit (best {wrapper:#x})")
    wrappers = {wrapper}
    # the sweep can drop call sites when it desynchronises, so scan for them
    site_set = set(sites) | set(call_sites_of(b, wrapper, span_lo, span_hi))
    missed = len(site_set) - len(sites)
    if missed:
        print(f"# sweep missed {missed} site(s); recovered by byte scan")
    # a logger funnelling into the wrapper is a deny path too
    changed = True
    while changed:
        changed = False
        for row in scored[1:]:
            _e2, r2, _d2, _c2, w2, s2, ret_soon = row
            if w2 in wrappers or len(s2) < 2 or r2 < 0.9 or ret_soon:
                continue  # returns to its caller: skipping the body is enough
            if True:
                if len(wrappers) < 4:
                    wrappers.add(w2)
                    site_set |= set(s2)
                    site_set |= set(call_sites_of(b, w2, span_lo, span_hi))
                    changed = True
    print("# wrappers " + ", ".join(hex(w) for w in sorted(wrappers)))

    patches = []
    for s in sorted(site_set):
        epi = epilogue_after(b, s)
        if epi is None or epi == s:
            raise Fatal(f"no return path for site {s:#x}")
        patches.append({"call": s, "to": epi})

    return {
        "arch": b.arch,
        "kind": b.kind,
        "wrappers": [hex(w) for w in sorted(wrappers)],
        "wrapper_sites": len(site_set),
        "wrapper_depth": -negdepth,
        "license_span": [hex(span_lo), hex(span_hi)],
        "patches": patches,
        "wait_consts": wait_consts(b, span_lo, span_hi),
    }


# --------------------------------------------------------------------------- #
# Fingerprint-table key wait (31 s -> 2.5 s)
# --------------------------------------------------------------------------- #
WAIT_US = 31_000_000
WAIT_NEW_US = 2_500_000


def wait_consts(b: Bin, lo: int, hi: int) -> list[dict]:
    """Find the inline TimeDelta handed to BlockUntilFingerprintTableKeyResolved."""
    out = []
    if b.arch == ARM64:
        for va, width, e in insns(b, lo, max(1, (hi - lo) // 4)):
            w = struct.unpack("<I", bytes.fromhex(e))[0]
            reg = w & 0x1F
            if (w & 0xFF800000) != 0x52800000 or ((w >> 5) & 0xFFFF) != (WAIT_US & 0xFFFF):
                continue
            nxt = b.word(va + 4) or 0
            if (nxt & 0xFFE00000) == 0x72A00000 and (nxt & 0x1F) == reg and ((nxt >> 5) & 0xFFFF) == (WAIT_US >> 16):
                out.append({"at": va, "kind": "arm64-movz-movk", "reg": reg})
        return out
    # x86: the decoded sweep desyncs on data in the text section and can drop the
    # literal, so byte-scan for the 4-byte immediate and classify the opcode that
    # precedes it (`mov edx, imm32` = BA; `mov r8d, imm32` = 41 B8).
    seg = b.code()
    raw = bytes(b.code_blob())
    pat = struct.pack("<I", WAIT_US)
    base = seg.addr
    i = raw.find(pat)
    while i >= 0:
        imm_at = base + i
        if lo <= imm_at < hi:
            if i >= 1 and raw[i - 1] == 0xBA:
                out.append({"at": imm_at - 1, "kind": "x64-mov-imm32", "imm_at": imm_at})
            elif i >= 2 and raw[i - 2] == 0x41 and raw[i - 1] == 0xB8:
                out.append({"at": imm_at - 2, "kind": "x64-mov-imm32", "imm_at": imm_at})
        i = raw.find(pat, i + 1)
    return out


def patch(b: Bin, manifest: dict) -> None:
    for p in manifest["patches"]:
        va, to = p["call"], p["to"]
        if b.arch != ARM64 and b.read(va, 1) != b"\xe8":
            raise Fatal(f"site {va:#x} is not a call")
        new = as_jump(b, va, to)
        off = b.fileoff(va)
        b.data[off : off + len(new)] = new
    for w in manifest["wait_consts"]:
        if w["kind"] == "arm64-movz-movk":
            reg = w["reg"]
            at = w["at"]
            movz = 0x52800000 | ((WAIT_NEW_US & 0xFFFF) << 5) | reg
            movk = 0x72A00000 | (((WAIT_NEW_US >> 16) & 0xFFFF) << 5) | reg
            off = b.fileoff(at)
            b.data[off : off + 4] = struct.pack("<I", movz)
            b.data[off + 4 : off + 8] = struct.pack("<I", movk)
        else:
            off = b.fileoff(w["imm_at"])
            b.data[off : off + 4] = struct.pack("<I", WAIT_NEW_US)


# --------------------------------------------------------------------------- #
# Static verification: confirm a patch is sound without launching a browser
# --------------------------------------------------------------------------- #
def verify_patched(b: Bin, manifest: dict) -> list[str]:
    """Structurally check that `b` carries `manifest`'s patch. Returns a list of
    problems; an empty list means the patch is present and well-formed.

    This never runs code, so it is the cheap gate CI uses before the expensive
    launch test, and the only check available for the two platforms whose engine
    cannot run on the build host.
    """
    problems: list[str] = []
    span = manifest.get("license_span")
    lo, hi = (int(span[0], 16), int(span[1], 16)) if span else (0, 0)
    wrappers = {int(w, 16) for w in manifest.get("wrappers", [])}

    for p in manifest["patches"]:
        va, to = p["call"], p["to"]
        # 1. the deny site must now be an unconditional jump to the epilogue.
        dest = jmp_target(b, va)
        if dest is None:
            problems.append(f"{va:#x}: not an unconditional jump after patching")
        elif dest != to:
            problems.append(f"{va:#x}: jumps to {dest:#x}, manifest says {to:#x}")
        # 2. the epilogue it lands on must really end in a return.
        if not _reaches_ret(b, to):
            problems.append(f"{va:#x}: target {to:#x} does not reach a ret")

    # 3. no call to an exit-wrapper may survive inside the license window: any
    #    that does is an unpatched deny path that will still kill a launch.
    if lo and hi:
        for w in wrappers:
            survivors = [s for s in call_sites_of_any(b, w, lo, hi)
                         if jmp_target(b, s) != manifest_to(manifest, s)]
            for s in survivors:
                if bl_target(b, s) == w:  # still a live call, not our jump
                    problems.append(f"{s:#x}: live call to wrapper {w:#x} survived")

    # 4. the fingerprint-table wait, if the manifest recorded one, must be cut.
    for wcon in manifest.get("wait_consts", []):
        at = wcon["at"]
        if wcon["kind"] == "arm64-movz-movk":
            w = b.word(at) or 0
            if ((w >> 5) & 0xFFFF) != (WAIT_NEW_US & 0xFFFF):
                problems.append(f"{at:#x}: wait constant not reduced")
        else:
            cur = struct.unpack("<I", b.read(wcon["imm_at"], 4))[0]
            if cur != WAIT_NEW_US:
                problems.append(f"{at:#x}: wait constant still {cur}")
    return problems


def manifest_to(manifest: dict, site: int) -> int | None:
    for p in manifest["patches"]:
        if p["call"] == site:
            return p["to"]
    return None


def call_sites_of_any(b: Bin, target: int, lo: int, hi: int) -> list[int]:
    """Every bl/call landing on `target` in [lo, hi), format-agnostic."""
    out: list[int] = []
    if b.arch == ARM64:
        va = lo
        while va < hi:
            if bl_target(b, va) == target:
                out.append(va)
            va += 4
        return out
    return call_sites_of(b, target, lo, hi)


def _reaches_ret(b: Bin, va: int, cap: int = 0x80) -> bool:
    """True if a forward run from `va` hits a ret before padding/branching out."""
    if b.arch == ARM64:
        cur = va
        for _ in range(cap):
            if is_ret(b, cur):
                return True
            if is_pad(b, cur):
                return False
            cur += 4
        return False
    for cur, _w, _e in insns(b, va, cap * 0x10):
        if is_ret(b, cur):
            return True
        if b.read(cur, 1) in (b"\xcc",):
            return False
    return False


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("derive")
    d.add_argument("container")
    d.add_argument("--out", required=True)
    p = sub.add_parser("patch")
    p.add_argument("container")
    p.add_argument("--sites", required=True)
    v = sub.add_parser("verify")
    v.add_argument("container")
    v.add_argument("--sites", required=True)
    a = sub.add_parser("dump")
    a.add_argument("container")
    a.add_argument("--at", type=lambda s: int(s, 0))
    a.add_argument("--count", type=int, default=24)
    args = ap.parse_args()

    b = open_bin(Path(args.container))
    if args.cmd == "derive":
        man = derive(b)
        Path(args.out).write_text(json.dumps(man, indent=2) + "\n")
        print(
            f"{args.container}: {b.kind}/{b.arch} wrappers " + ",".join(man["wrappers"])
            + f" from {man['wrapper_sites']} sites, {len(man['patches'])} patched, "
            + f"{len(man['wait_consts'])} wait const(s)"
        )
        for pt in man["patches"]:
            print(f"  {pt['call']:#x} -> {pt['to']:#x}")
        return 0
    if args.cmd == "patch":
        man = json.loads(Path(args.sites).read_text())
        patch(b, man)
        b.save()
        print(f"patched {args.container}")
        return 0
    if args.cmd == "verify":
        man = json.loads(Path(args.sites).read_text())
        problems = verify_patched(b, man)
        if problems:
            print(f"{args.container}: NOT patched soundly ({len(problems)} issue(s)):")
            for pr in problems:
                print(f"  - {pr}")
            return 1
        print(
            f"{args.container}: patch verified — "
            f"{len(man['patches'])} deny site(s) defused, "
            f"{len(man['wait_consts'])} wait const(s) cut"
        )
        return 0
    for va, w, e in insns(b, args.at, args.count):
        extra = ""
        if w == 4 and e.isalnum():
            extra = f"  ; bl->{bl_target(b, va):#x}" if bl_target(b, va) else ""
        print(f"{va:#x} {e}{extra}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Fatal as exc:
        print(f"cloakcrack: {exc}", file=sys.stderr)
        sys.exit(1)
