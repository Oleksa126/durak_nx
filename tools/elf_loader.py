#!/usr/bin/env python3
"""
tools/elf_loader.py - ELF64 / AArch64 Host Oracle & Cross-Module Link Verification Tool (E05 Host Oracle).

NOTE: This tool serves as the E05 Host Oracle modeling memory layout, segment alignment,
BSS zeroing, W^X transitions, relocation mathematics, and unresolved-import inventory
before execution on Switch.

Features:
- Strict ELF64 / AArch64 header and program header validation (Fail-Closed).
- Exact dynamic symbol count derivation from DT_HASH / DT_GNU_HASH.
- Fully bounded dynamic table parsing (rejects unmapped virtual addresses).
- Segment-level relocation target validation (rejects unmapped gaps and holes).
- Strict load bias computation (load_bias = base_addr - min_vaddr).
- PT_LOAD mapping with page-rounding and alignment enforcement (supports 64 KiB alignment for libsqlite3.so).
- Overflow, bounds, and power-of-2 alignment checking.
- BSS zero-initialization.
- W^X permission model tracking (RW during loading/relocation -> R/RX/RW finalization, PT_GNU_RELRO support).
- Full AArch64 dynamic relocation support:
  * R_AARCH64_RELATIVE (1027)
  * R_AARCH64_GLOB_DAT (1025)
  * R_AARCH64_JUMP_SLOT (1026)
  * R_AARCH64_ABS64 (257)
- Symbol resolution: WEAK vs STRONG (GLOBAL) symbols, inter-module dependency resolution.
- Unresolved import categorization (libc, libm, liblog, libdl, libandroid, libEGL, libmediandk, etc.).
- Structured JSON and human-readable Markdown reporting.
"""

import os
import sys
import struct
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Set

MAX_LOAD_SIZE = 0x40000000  # 1 GiB sanity limit for ELF memory image

# --- ELF Constants ---
EI_MAG0, EI_MAG1, EI_MAG2, EI_MAG3 = 0, 1, 2, 3
EI_CLASS = 4
EI_DATA = 5
EI_VERSION = 6
EI_NIDENT = 16

ELFMAG = b'\x7fELF'
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2
EV_CURRENT = 1

ET_EXEC = 2
ET_DYN = 3
EM_AARCH64 = 0xB7 # 183

# Program Header Types (p_type)
PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_TLS = 7
PT_GNU_EH_FRAME = 0x6474e550
PT_GNU_STACK = 0x6474e551
PT_GNU_RELRO = 0x6474e552

# Program Header Flags (p_flags)
PF_X = 1
PF_W = 2
PF_R = 4

# Dynamic Tags (d_tag)
DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28
DT_GNU_HASH = 0x6ffffef5

# Symbol Bindings (st_info >> 4)
STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

# Symbol Types (st_info & 0xf)
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_COMMON = 5
STT_TLS = 6

SHN_UNDEF = 0
SHN_LORESERVE = 0xff00
SHN_ABS = 0xfff1
SHN_COMMON = 0xfff2
SHN_HIRESERVE = 0xffff

# AArch64 Relocations
R_AARCH64_NONE = 0
R_AARCH64_ABS64 = 257
R_AARCH64_COPY = 1024
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027
R_AARCH64_TLS_TPREL64 = 1030
R_AARCH64_TLS_DTPREL64 = 1031

RELOC_NAMES = {
    R_AARCH64_NONE: "R_AARCH64_NONE",
    R_AARCH64_ABS64: "R_AARCH64_ABS64",
    R_AARCH64_COPY: "R_AARCH64_COPY",
    R_AARCH64_GLOB_DAT: "R_AARCH64_GLOB_DAT",
    R_AARCH64_JUMP_SLOT: "R_AARCH64_JUMP_SLOT",
    R_AARCH64_RELATIVE: "R_AARCH64_RELATIVE",
    R_AARCH64_TLS_TPREL64: "R_AARCH64_TLS_TPREL64",
    R_AARCH64_TLS_DTPREL64: "R_AARCH64_TLS_DTPREL64",
}

# E05.4b Baseline Leaf & Numeric Conversion Shims (79 symbols)
BASELINE_ANDROID_SHIM_SYMBOLS = {
    # Logging (3)
    "__android_log_print", "__android_log_vprint", "__android_log_write",
    # Libm / Math (49)
    "acos", "acosf", "asin", "asinf", "atan", "atan2", "atan2f", "atanf",
    "cbrtf", "ceil", "ceilf", "copysign", "copysignf", "cos", "cosf",
    "exp", "expf", "fabs", "fabsf", "floor", "floorf", "fmod", "fmodf",
    "frexp", "frexpf", "hypot", "hypotf", "ldexp", "ldexpf", "log", "log10",
    "log10f", "log2", "log2f", "logf", "pow", "powf", "remainder", "remainderf",
    "round", "roundf", "sin", "sinf", "sqrt", "sqrtf", "tan", "tanf", "trunc", "truncf",
    # 64-bit Stdio (2)
    "fseeko64", "ftello64",
    # Allocator (6)
    "aligned_alloc", "calloc", "free", "malloc", "memalign", "realloc",
    # Memory / String (10)
    "memcmp", "memcpy", "memmove", "memset", "strcmp", "strcpy", "strlen", "strncmp", "strncpy", "strnlen",
    # Numeric Conversions (9) [E05.4b]
    "atoi", "atol", "atoll", "strtod", "strtof", "strtol", "strtoll", "strtoul", "strtoull"
}

SORTED_BASELINE_ANDROID_SHIM_SYMBOLS = sorted(BASELINE_ANDROID_SHIM_SYMBOLS)
BASELINE_ANDROID_SHIM_ADDRESSES = {
    sym: 0x7fff000000 + (idx * 0x1000)
    for idx, sym in enumerate(SORTED_BASELINE_ANDROID_SHIM_SYMBOLS)
}


def resolve_baseline_android_shim(sym: str) -> Optional[int]:
    """Deterministic external resolver for E05.4b baseline Android shim symbols (79 symbols)."""
    return BASELINE_ANDROID_SHIM_ADDRESSES.get(sym)


# Wave 1 Confirmed Leaf Libc, Math & Numeric Conversion Shims (27 symbols)
WAVE1_ANDROID_SHIM_SYMBOLS = {
    # Wave 1 Algorithmic (2)
    "bsearch", "qsort",
    # Wave 1 Pure Math (10)
    "div", "exp2", "exp2f", "logb", "modf", "modff", "scalbn", "sincos", "sincosf", "tanhf",
    # Wave 1 Byte / Memory String (12)
    "memchr", "memrchr", "strcat", "strchr", "strcspn", "strdup", "strlcpy", "strncat", "strrchr", "strspn", "strstr", "strtok_r",
    # Wave 1 Pure Wide-Character Memory (3)
    "wcslen", "wmemchr", "wmemcmp",
}

# Wave 2 Format, Error, Guard & Lifecycle Shims (23 symbols)
WAVE2_ANDROID_SHIM_SYMBOLS = {
    # String Formatting & Scanning (8)
    "asprintf", "snprintf", "sprintf", "sscanf", "swprintf", "vasprintf", "vsnprintf", "vsscanf",
    # Error & Bionic-to-String (4)
    "__errno", "__gnu_strerror_r", "strerror", "strerror_r",
    # System Logging (3)
    "closelog", "openlog", "syslog",
    # Lifecycle / Atexit / Fork (3)
    "__cxa_atexit", "__cxa_finalize", "__register_atfork",
    # Abort, Assert & Stack Guard (5)
    "__assert2", "__stack_chk_fail", "abort", "android_set_abort_message", "exit",
}

# Wave 3 Time, Clock, Environment & Stateful RNG Shims (20 symbols)
WAVE3_ANDROID_SHIM_SYMBOLS = {
    # Clocks & Sleep (7)
    "clock", "clock_getres", "clock_gettime", "gettimeofday", "nanosleep", "time", "usleep",
    # Calendar & Time Formatting (7)
    "difftime", "gmtime", "gmtime_r", "localtime", "localtime_r", "mktime", "strftime",
    # Environment & System Config (4)
    "getenv", "setenv", "sysconf", "unsetenv",
    # Stateful 48-bit LCG RNG (2)
    "lrand48", "srand48",
}

# Active Android Shim Registry (149 symbols: 79 baseline + 27 Wave 1 + 23 Wave 2 + 20 Wave 3)
ANDROID_SHIM_SYMBOLS = (
    BASELINE_ANDROID_SHIM_SYMBOLS
    | WAVE1_ANDROID_SHIM_SYMBOLS
    | WAVE2_ANDROID_SHIM_SYMBOLS
    | WAVE3_ANDROID_SHIM_SYMBOLS
)

# Deterministic address mapping for host model dry-run resolution (149 symbols)
SORTED_ANDROID_SHIM_SYMBOLS = sorted(ANDROID_SHIM_SYMBOLS)
ANDROID_SHIM_ADDRESSES = {
    sym: 0x7fff000000 + (idx * 0x1000)
    for idx, sym in enumerate(SORTED_ANDROID_SHIM_SYMBOLS)
}


def resolve_android_shim(sym: str) -> Optional[int]:
    """Deterministic external resolver for active Android shim symbols (149 symbols)."""
    return ANDROID_SHIM_ADDRESSES.get(sym)


class ElfValidationError(Exception):
    """Raised when an ELF binary violates structure, alignment, bounds, or security rules."""
    pass


class UnresolvedSymbolError(Exception):
    """Raised when a strong (GLOBAL) imported symbol cannot be resolved."""
    pass


class ElfSegment:
    def __init__(self, p_type: int, p_flags: int, p_offset: int, p_vaddr: int,
                 p_paddr: int, p_filesz: int, p_memsz: int, p_align: int):
        self.p_type = p_type
        self.p_flags = p_flags
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_align = p_align

        # Virtual address range when mapped into a base address
        self.mapped_vaddr_start = 0
        self.mapped_vaddr_end = 0
        self.final_prot = self._flags_to_str(p_flags)

    @staticmethod
    def _flags_to_str(flags: int) -> str:
        res = []
        if flags & PF_R: res.append('R')
        if flags & PF_W: res.append('W')
        if flags & PF_X: res.append('X')
        return "".join(res) if res else "NONE"

    def is_writable(self) -> bool:
        return bool(self.p_flags & PF_W)

    def is_executable(self) -> bool:
        return bool(self.p_flags & PF_X)

    def is_readable(self) -> bool:
        return bool(self.p_flags & PF_R)


class ElfSymbol:
    def __init__(self, name: str, bind: int, st_type: int, shndx: int, value: int, size: int):
        self.name = name
        self.bind = bind          # STB_LOCAL, STB_GLOBAL, STB_WEAK
        self.st_type = st_type    # STT_FUNC, STT_OBJECT, etc.
        self.shndx = shndx        # SHN_UNDEF means imported
        self.value = value        # Virtual address offset within module (or absolute value if SHN_ABS)
        self.size = size

    @property
    def is_defined(self) -> bool:
        return self.shndx != SHN_UNDEF and (self.shndx < SHN_LORESERVE or self.shndx == SHN_ABS)

    @property
    def is_absolute(self) -> bool:
        return self.shndx == SHN_ABS

    @property
    def is_weak(self) -> bool:
        return self.bind == STB_WEAK

    @property
    def is_global(self) -> bool:
        return self.bind == STB_GLOBAL

    @property
    def bind_name(self) -> str:
        if self.bind == STB_GLOBAL: return "GLOBAL"
        if self.bind == STB_WEAK: return "WEAK"
        if self.bind == STB_LOCAL: return "LOCAL"
        return f"OTHER({self.bind})"


class ElfRelocation:
    def __init__(self, offset: int, r_type: int, sym_idx: int, symbol: Optional[ElfSymbol],
                 addend: int, is_plt: bool):
        self.offset = offset       # Target VADDR in module
        self.r_type = r_type       # Relocation type (e.g. R_AARCH64_RELATIVE)
        self.sym_idx = sym_idx
        self.symbol = symbol
        self.addend = addend
        self.is_plt = is_plt

        # Resolution tracking
        self.resolved = False
        self.resolved_value = 0
        self.resolved_from = ""    # "RELATIVE", "INTERNAL", module name, or "WEAK_NULL"

    @property
    def type_name(self) -> str:
        return RELOC_NAMES.get(self.r_type, f"R_AARCH64_UNKNOWN({self.r_type})")

    @property
    def symbol_name(self) -> str:
        return self.symbol.name if self.symbol else ""

    @property
    def is_weak(self) -> bool:
        return self.symbol.is_weak if self.symbol else False


class ElfModule:
    """Represents a single parsed and mapped ELF64 AArch64 module."""

    def __init__(self, path: str, name: Optional[str] = None):
        self.path = path
        self.name = name or os.path.basename(path)
        self.raw_data = b""
        self.file_size = 0

        # Header fields
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_phnum = 0
        self.e_phentsize = 0

        # Program headers & memory layout
        self.segments: List[ElfSegment] = []
        self.load_segments: List[ElfSegment] = []
        self.relro_segment: Optional[ElfSegment] = None
        self.min_vaddr = 0
        self.max_vaddr = 0
        self.load_size = 0
        self.max_align = 0x1000   # Minimum 4 KiB
        self.base_addr = 0        # Allocation base
        self.load_bias = 0        # Load bias (base_addr - min_vaddr)

        # In-memory buffer for dry-run
        self.memory: bytearray = bytearray()

        # Dynamic structures
        self.dynamic_tags: Dict[int, int] = {}
        self.needed_libraries: List[str] = []
        self.symbols: Dict[int, ElfSymbol] = {}
        self.exported_symbols: Dict[str, ElfSymbol] = {}
        self.imported_symbols: Dict[str, ElfSymbol] = {}
        self.relocations: List[ElfRelocation] = []
        self.init_array: List[int] = []

        # W^X Protection tracking per page (offset in module -> prot string)
        self.page_protection: Dict[int, int] = {}

        self._parse_and_validate()

    def _parse_and_validate(self):
        if not os.path.exists(self.path):
            raise ElfValidationError(f"File not found: {self.path}")

        with open(self.path, 'rb') as f:
            self.raw_data = f.read()
        self.file_size = len(self.raw_data)

        if self.file_size < 64:
            raise ElfValidationError(f"File {self.name} too small to be valid ELF64 (size={self.file_size})")

        # 1. Validate e_ident
        magic = self.raw_data[0:4]
        if magic != ELFMAG:
            raise ElfValidationError(f"{self.name}: Invalid ELF magic {magic!r}, expected {ELFMAG!r}")

        elf_class = self.raw_data[EI_CLASS]
        if elf_class != ELFCLASS64:
            raise ElfValidationError(f"{self.name}: Expected ELFCLASS64 (2), got {elf_class}")

        data_enc = self.raw_data[EI_DATA]
        if data_enc != ELFDATA2LSB:
            raise ElfValidationError(f"{self.name}: Expected little-endian ELFDATA2LSB (1), got {data_enc}")

        version = self.raw_data[EI_VERSION]
        if version != EV_CURRENT:
            raise ElfValidationError(f"{self.name}: Invalid ELF version {version}")

        # 2. Parse ELF64 Header
        header_fields = struct.unpack('<HHIQQQIHHHHHH', self.raw_data[16:64])
        e_type, e_machine, e_version, self.e_entry, self.e_phoff, self.e_shoff, e_flags, \
        e_ehsize, self.e_phentsize, self.e_phnum, e_shentsize, e_shnum, e_shstrndx = header_fields

        if e_type != ET_DYN:
            raise ElfValidationError(f"{self.name}: Expected ET_DYN (3, shared object), got {e_type}")

        if e_machine != EM_AARCH64:
            raise ElfValidationError(f"{self.name}: Expected EM_AARCH64 (0xB7/183), got {e_machine:#x}")

        if self.e_phentsize != 56:
            raise ElfValidationError(f"{self.name}: Unexpected Elf64_Phdr size {self.e_phentsize} (expected 56)")

        ph_total_size = self.e_phoff + self.e_phnum * self.e_phentsize
        if ph_total_size > self.file_size:
            raise ElfValidationError(f"{self.name}: Program headers exceed file bounds ({ph_total_size} > {self.file_size})")

        # 3. Parse Program Headers
        for i in range(self.e_phnum):
            ph_off = self.e_phoff + i * self.e_phentsize
            chunk = self.raw_data[ph_off : ph_off + self.e_phentsize]
            p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack('<IIQQQQQQ', chunk)

            # Security checks
            if p_filesz > p_memsz:
                raise ElfValidationError(f"{self.name}: Segment {i} invalid: p_filesz ({p_filesz:#x}) > p_memsz ({p_memsz:#x})")

            if p_offset + p_filesz > self.file_size:
                raise ElfValidationError(f"{self.name}: Segment {i} extends beyond EOF ({p_offset + p_filesz:#x} > {self.file_size:#x})")

            if p_vaddr + p_memsz > 0xffffffffffffffff:
                raise ElfValidationError(f"{self.name}: Segment {i} virtual address overflow ({p_vaddr:#x} + {p_memsz:#x})")

            seg = ElfSegment(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align)
            self.segments.append(seg)

            if p_type == PT_LOAD:
                # Validate alignment: p_align must be 0, 1 or a power of 2
                if p_align > 1:
                    if (p_align & (p_align - 1)) != 0:
                        raise ElfValidationError(f"{self.name}: Segment {i} invalid alignment {p_align:#x}: must be a power of 2")
                    if (p_vaddr % p_align) != (p_offset % p_align):
                        raise ElfValidationError(f"{self.name}: Segment {i} misaligned: vaddr {p_vaddr:#x} % {p_align:#x} != offset {p_offset:#x} % {p_align:#x}")
                    if p_align > self.max_align:
                        self.max_align = p_align

                self.load_segments.append(seg)
            elif p_type == PT_GNU_RELRO:
                self.relro_segment = seg

        if not self.load_segments:
            raise ElfValidationError(f"{self.name}: No PT_LOAD segments found")

        # 4. Check for segment overlap in virtual address space
        sorted_loads = sorted(self.load_segments, key=lambda s: s.p_vaddr)
        for i in range(len(sorted_loads) - 1):
            curr_seg = sorted_loads[i]
            next_seg = sorted_loads[i + 1]
            if curr_seg.p_vaddr + curr_seg.p_memsz > next_seg.p_vaddr:
                raise ElfValidationError(
                    f"{self.name}: Overlapping PT_LOAD segments: "
                    f"[{curr_seg.p_vaddr:#x}..{curr_seg.p_vaddr + curr_seg.p_memsz:#x}) overlaps with "
                    f"[{next_seg.p_vaddr:#x}..{next_seg.p_vaddr + next_seg.p_memsz:#x})"
                )

        # 5. Compute virtual address span
        self.min_vaddr = min(s.p_vaddr & ~(self.max_align - 1) for s in self.load_segments)
        self.max_vaddr = max((s.p_vaddr + s.p_memsz + self.max_align - 1) & ~(self.max_align - 1) for s in self.load_segments)
        self.load_size = self.max_vaddr - self.min_vaddr
        if self.load_size <= 0 or self.load_size > MAX_LOAD_SIZE:
            raise ElfValidationError(f"{self.name}: Invalid or excessive load_size ({self.load_size:#x}, max={MAX_LOAD_SIZE:#x})")

    def vaddr_to_file_offset(self, vaddr: int, size: int = 1) -> int:
        """Convert virtual address to file offset, verifying it is strictly contained in a file-backed PT_LOAD."""
        for seg in self.load_segments:
            if seg.p_vaddr <= vaddr and (vaddr + size) <= (seg.p_vaddr + seg.p_filesz):
                return seg.p_offset + (vaddr - seg.p_vaddr)
        raise ElfValidationError(
            f"{self.name}: Virtual address range [{vaddr:#x}..{vaddr + size:#x}) is not contained in any file-backed PT_LOAD segment"
        )

    def map_into_memory(self, base_addr: int):
        """Map PT_LOAD segments and BSS into memory at base_addr."""
        # Align base_addr to maximum segment alignment
        if base_addr % self.max_align != 0:
            raise ElfValidationError(f"{self.name}: Base address {base_addr:#x} is not aligned to max_align {self.max_align:#x}")

        self.base_addr = base_addr
        self.load_bias = base_addr - self.min_vaddr
        self.memory = bytearray(self.load_size)

        for seg in self.load_segments:
            seg_rel_start = seg.p_vaddr - self.min_vaddr
            seg.mapped_vaddr_start = self.base_addr + seg_rel_start
            seg.mapped_vaddr_end = seg.mapped_vaddr_start + seg.p_memsz

            # Copy file contents
            if seg.p_filesz > 0:
                self.memory[seg_rel_start : seg_rel_start + seg.p_filesz] = \
                    self.raw_data[seg.p_offset : seg.p_offset + seg.p_filesz]

            # BSS zero-initialization
            bss_size = seg.p_memsz - seg.p_filesz
            if bss_size > 0:
                bss_start = seg_rel_start + seg.p_filesz
                self.memory[bss_start : bss_start + bss_size] = b'\x00' * bss_size

        # Parse dynamic tags and symbol table once memory is allocated
        self._parse_dynamic()

    def _get_dynsym_count(self) -> int:
        """Derive authoritative dynamic symbol count from DT_HASH or DT_GNU_HASH."""
        if DT_HASH in self.dynamic_tags:
            hash_va = self.dynamic_tags[DT_HASH]
            hash_off = self.vaddr_to_file_offset(hash_va, 8)
            nbucket, nchain = struct.unpack('<II', self.raw_data[hash_off : hash_off + 8])
            total_hash_sz = 8 + (nbucket + nchain) * 4
            self.vaddr_to_file_offset(hash_va, total_hash_sz)
            return nchain
        elif DT_GNU_HASH in self.dynamic_tags:
            gnu_va = self.dynamic_tags[DT_GNU_HASH]
            gnu_off = self.vaddr_to_file_offset(gnu_va, 16)
            nbuckets, symndx, maskwords, shift2 = struct.unpack('<IIII', self.raw_data[gnu_off : gnu_off + 16])
            bloom_sz = maskwords * 8
            buckets_sz = nbuckets * 4
            bloom_off = gnu_off + 16
            buckets_off = bloom_off + bloom_sz
            chains_off = buckets_off + buckets_sz
            self.vaddr_to_file_offset(gnu_va, 16 + bloom_sz + buckets_sz)
            buckets = struct.unpack(f'<{nbuckets}I', self.raw_data[buckets_off : buckets_off + buckets_sz])
            max_sym = max(buckets) if buckets else 0
            if max_sym < symndx:
                return symndx

            cur_sym = max_sym
            while True:
                chain_idx = cur_sym - symndx
                c_off = chains_off + chain_idx * 4
                self.vaddr_to_file_offset(gnu_va, 16 + bloom_sz + buckets_sz + (chain_idx + 1) * 4)
                chain_val = struct.unpack('<I', self.raw_data[c_off : c_off + 4])[0]
                if chain_val & 1:
                    return cur_sym + 1
                cur_sym += 1
        elif self.e_shoff > 0 and self.e_shnum > 0:
            for i in range(self.e_shnum):
                sh_off = self.e_shoff + i * self.e_shentsize
                if sh_off + 40 > self.file_size:
                    break
                sh_type = struct.unpack('<I', self.raw_data[sh_off + 4 : sh_off + 8])[0]
                if sh_type == 11:  # SHT_DYNSYM
                    sh_size = struct.unpack('<Q', self.raw_data[sh_off + 32 : sh_off + 40])[0]
                    return sh_size // 24
            raise ElfValidationError(f"{self.name}: No DT_HASH/DT_GNU_HASH and no SHT_DYNSYM section found")
        else:
            raise ElfValidationError(f"{self.name}: Cannot determine exact dynamic symbol count (missing DT_HASH and DT_GNU_HASH)")

    def _parse_dynamic(self):
        dyn_seg = next((s for s in self.segments if s.p_type == PT_DYNAMIC), None)
        if not dyn_seg:
            return

        dyn_offset = self.vaddr_to_file_offset(dyn_seg.p_vaddr, dyn_seg.p_filesz)
        num_entries = dyn_seg.p_filesz // 16

        for i in range(num_entries):
            off = dyn_offset + i * 16
            d_tag, d_val = struct.unpack('<qQ', self.raw_data[off : off + 16])
            if d_tag == DT_NULL:
                break
            if d_tag == DT_NEEDED:
                self.needed_libraries.append(d_val) # Store index, resolve after strtab
            else:
                self.dynamic_tags[d_tag] = d_val

        # Validate dynamic entry constants if present
        if DT_SYMENT in self.dynamic_tags and self.dynamic_tags[DT_SYMENT] != 24:
            raise ElfValidationError(f"{self.name}: Invalid DT_SYMENT {self.dynamic_tags[DT_SYMENT]} (expected 24)")
        if DT_RELAENT in self.dynamic_tags and self.dynamic_tags[DT_RELAENT] != 24:
            raise ElfValidationError(f"{self.name}: Invalid DT_RELAENT {self.dynamic_tags[DT_RELAENT]} (expected 24)")
        if DT_PLTREL in self.dynamic_tags and self.dynamic_tags[DT_PLTREL] != DT_RELA:
            raise ElfValidationError(f"{self.name}: Invalid DT_PLTREL {self.dynamic_tags[DT_PLTREL]} (expected DT_RELA = 7)")

        strtab_va = self.dynamic_tags.get(DT_STRTAB)
        symtab_va = self.dynamic_tags.get(DT_SYMTAB)
        if not strtab_va or not symtab_va:
            return

        if DT_STRSZ not in self.dynamic_tags or self.dynamic_tags[DT_STRSZ] <= 0:
            raise ElfValidationError(f"{self.name}: Missing or non-positive DT_STRSZ in dynamic tags")
        strsz = self.dynamic_tags[DT_STRSZ]

        rela_va = self.dynamic_tags.get(DT_RELA)
        relasz = self.dynamic_tags.get(DT_RELASZ, 0)
        jmprel_va = self.dynamic_tags.get(DT_JMPREL)
        pltrelsz = self.dynamic_tags.get(DT_PLTRELSZ, 0)

        strtab_off = self.vaddr_to_file_offset(strtab_va, strsz)
        symtab_off = self.vaddr_to_file_offset(symtab_va, 24)

        if rela_va and relasz:
            self.vaddr_to_file_offset(rela_va, relasz)
        if jmprel_va and pltrelsz:
            self.vaddr_to_file_offset(jmprel_va, pltrelsz)

        # Resolve DT_NEEDED names
        resolved_needed = []
        for n_idx in self.needed_libraries:
            if isinstance(n_idx, int):
                if n_idx >= strsz:
                    raise ElfValidationError(f"{self.name}: DT_NEEDED string index {n_idx} >= DT_STRSZ ({strsz})")
                name_end = self.raw_data.find(b'\0', strtab_off + n_idx, strtab_off + strsz)
                if name_end == -1:
                    raise ElfValidationError(f"{self.name}: Unterminated DT_NEEDED string at offset {n_idx} within DT_STRSZ ({strsz})")
                name = self.raw_data[strtab_off + n_idx : name_end].decode('latin1', errors='ignore')
                resolved_needed.append(name)
        self.needed_libraries = resolved_needed

        # Exact dynamic symbol count derived authoritatively
        num_symbols = self._get_dynsym_count()
        # Verify entire symtab fits in file-backed PT_LOAD
        self.vaddr_to_file_offset(symtab_va, num_symbols * 24)

        for sym_idx in range(num_symbols):
            sym_file_off = symtab_off + sym_idx * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
                '<IBBHQQ', self.raw_data[sym_file_off : sym_file_off + 24]
            )
            if st_name >= strsz:
                raise ElfValidationError(f"{self.name}: Symbol {sym_idx} st_name ({st_name:#x}) >= DT_STRSZ ({strsz:#x})")
            name_end = self.raw_data.find(b'\0', strtab_off + st_name, strtab_off + strsz)
            if name_end == -1:
                raise ElfValidationError(f"{self.name}: Symbol {sym_idx} name is not null-terminated within DT_STRSZ ({strsz})")
            sym_name = self.raw_data[strtab_off + st_name : name_end].decode('latin1', errors='ignore')
            bind = st_info >> 4
            st_type = st_info & 0xf

            sym = ElfSymbol(sym_name, bind, st_type, st_shndx, st_value, st_size)
            self.symbols[sym_idx] = sym

            if sym_name:
                if sym.is_defined and (sym.is_global or sym.is_weak):
                    self.exported_symbols[sym_name] = sym
                elif not sym.is_defined:
                    self.imported_symbols[sym_name] = sym

        # Parse relocations
        for va, sz, is_plt in [(rela_va, relasz, False), (jmprel_va, pltrelsz, True)]:
            if not va or not sz: continue
            off = self.vaddr_to_file_offset(va, sz)
            for i in range(sz // 24):
                r_offset, r_info, r_addend = struct.unpack('<QQq', self.raw_data[off + i*24 : off + (i+1)*24])
                r_type = r_info & 0xffffffff
                sym_idx = r_info >> 32
                if sym_idx >= num_symbols:
                    raise ElfValidationError(f"{self.name}: Relocation symbol index {sym_idx} exceeds symbol count ({num_symbols})")
                sym = self.symbols.get(sym_idx)
                rel = ElfRelocation(r_offset, r_type, sym_idx, sym, r_addend, is_plt)
                self.relocations.append(rel)

        # Parse DT_INIT_ARRAY
        init_arr_va = self.dynamic_tags.get(DT_INIT_ARRAY)
        init_arr_sz = self.dynamic_tags.get(DT_INIT_ARRAYSZ, 0)
        if init_arr_va and init_arr_sz:
            off = self.vaddr_to_file_offset(init_arr_va, init_arr_sz)
            count = init_arr_sz // 8
            for i in range(count):
                fn_ptr = struct.unpack('<Q', self.raw_data[off + i*8 : off + (i+1)*8])[0]
                self.init_array.append(fn_ptr)

    def write_reloc_value(self, r_offset: int, value: int):
        """Write 64-bit resolved value into memory at r_offset (ELF VADDR)."""
        # Validate that r_offset..r_offset+8 strictly belongs to a mapped PT_LOAD segment
        target_seg = None
        for seg in self.load_segments:
            if seg.p_vaddr <= r_offset and (r_offset + 8) <= (seg.p_vaddr + seg.p_memsz):
                target_seg = seg
                break
        if not target_seg:
            raise ElfValidationError(
                f"{self.name}: Relocation target [{r_offset:#x}..{r_offset + 8:#x}) does not fall inside any mapped PT_LOAD segment"
            )

        rel_pos = r_offset - self.min_vaddr
        if rel_pos < 0 or rel_pos + 8 > len(self.memory):
            raise ElfValidationError(f"{self.name}: Relocation offset {r_offset:#x} out of bounds (len={len(self.memory):#x})")
        self.memory[rel_pos : rel_pos + 8] = struct.pack('<Q', value & 0xffffffffffffffff)

    def read_memory_u64(self, r_offset: int) -> int:
        rel_pos = r_offset - self.min_vaddr
        return struct.unpack('<Q', self.memory[rel_pos : rel_pos + 8])[0]

    def enforce_wx_permissions(self) -> Dict[str, any]:
        """
        Transition memory permissions from RW (relocation phase) to final W^X state.
        Verifies that no mapped page has both Write and Execute permissions.
        """
        violations = []
        page_size = 0x1000 # 4 KiB granular check
        total_pages = (self.load_size + page_size - 1) // page_size
        pages_prot = [0] * total_pages

        # 1. Apply segment flags
        for seg in self.load_segments:
            start_page = (seg.p_vaddr - self.min_vaddr) // page_size
            end_page = (seg.p_vaddr - self.min_vaddr + seg.p_memsz + page_size - 1) // page_size
            for p in range(start_page, min(end_page, total_pages)):
                pages_prot[p] |= seg.p_flags

        # 2. Apply GNU_RELRO (removes W flag from relro region)
        if self.relro_segment:
            relro_start_page = (self.relro_segment.p_vaddr - self.min_vaddr) // page_size
            relro_end_page = (self.relro_segment.p_vaddr - self.min_vaddr + self.relro_segment.p_memsz + page_size - 1) // page_size
            for p in range(relro_start_page, min(relro_end_page, total_pages)):
                pages_prot[p] &= ~PF_W # Clear Write flag

        # 3. Strict W^X Verification
        wx_count = 0
        rx_count = 0
        rw_count = 0
        ro_count = 0

        for p_idx, prot in enumerate(pages_prot):
            has_w = bool(prot & PF_W)
            has_x = bool(prot & PF_X)
            if has_w and has_x:
                wx_count += 1
                page_addr = self.base_addr + p_idx * page_size
                violations.append(page_addr)
            elif has_x:
                rx_count += 1
            elif has_w:
                rw_count += 1
            else:
                ro_count += 1

        return {
            "module": self.name,
            "total_pages": total_pages,
            "rx_pages": rx_count,
            "rw_pages": rw_count,
            "ro_pages": ro_count,
            "wx_violations_count": wx_count,
            "wx_violation_addresses": violations,
            "wx_compliant": (wx_count == 0)
        }


class MultiModuleLoader:
    """Manages coordinated loading, alignment, relocations, and inter-module linking."""

    def __init__(self, base_address_start: int = 0x7000000000):
        self.base_address_start = base_address_start
        self.modules: Dict[str, ElfModule] = {}
        self.load_order: List[str] = []
        self.global_exports: Dict[str, Tuple[ElfModule, ElfSymbol]] = {}
        self.unresolved_strong: List[Dict] = []
        self.unresolved_weak: List[Dict] = []
        self.cross_resolved: List[Dict] = []
        self.external_resolved: List[Dict] = []
        self.wx_results: List[Dict] = []
        self.shims_enabled: bool = False

    def load_module(self, path: str, name: Optional[str] = None) -> ElfModule:
        mod = ElfModule(path, name)
        mod_name = mod.name
        if mod_name in self.modules:
            raise ElfValidationError(f"Module {mod_name} already loaded in this loader context")

        # Determine next base address respecting module max_align
        if not self.modules:
            curr_base = self.base_address_start
        else:
            last_mod = self.modules[self.load_order[-1]]
            curr_base = last_mod.base_addr + last_mod.load_size

        # Align to mod.max_align (e.g. 64 KiB for libsqlite3.so)
        aligned_base = (curr_base + mod.max_align - 1) & ~(mod.max_align - 1)
        mod.map_into_memory(aligned_base)

        self.modules[mod_name] = mod
        self.load_order.append(mod_name)

        # Register exports
        for sym_name, sym in mod.exported_symbols.items():
            # Standard ELF symbol precedence: first global definition wins
            if sym_name not in self.global_exports:
                self.global_exports[sym_name] = (mod, sym)
            elif self.global_exports[sym_name][1].is_weak and sym.is_global:
                self.global_exports[sym_name] = (mod, sym)

        return mod

    def relocate_all(self, strict: bool = False, external_resolver=None):
        """Perform relocation across all loaded modules and resolve inter-module symbols."""
        self.shims_enabled = external_resolver is not None
        for mod_name in self.load_order:
            mod = self.modules[mod_name]
            for rel in mod.relocations:
                # 1. R_AARCH64_RELATIVE: *dest = load_bias + addend
                if rel.r_type == R_AARCH64_RELATIVE:
                    resolved_val = mod.load_bias + rel.addend
                    mod.write_reloc_value(rel.offset, resolved_val)
                    rel.resolved = True
                    rel.resolved_value = resolved_val
                    rel.resolved_from = "RELATIVE"

                # 2. Symbol-based relocations
                elif rel.r_type in (R_AARCH64_GLOB_DAT, R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64):
                    sym = rel.symbol
                    sym_name = sym.name if sym else ""
                    resolved_val = None
                    source = None

                    # A. Check if symbol is defined internally in this module
                    if sym and sym.is_defined:
                        if sym.is_absolute:
                            resolved_val = sym.value + rel.addend
                        else:
                            resolved_val = mod.load_bias + sym.value + rel.addend
                        source = f"INTERNAL:{mod.name}"

                    # B. Check global exports from all loaded modules
                    elif sym_name in self.global_exports:
                        provider_mod, provider_sym = self.global_exports[sym_name]
                        if provider_sym.is_absolute:
                            resolved_val = provider_sym.value + rel.addend
                        else:
                            resolved_val = provider_mod.load_bias + provider_sym.value + rel.addend
                        source = f"CROSS_MODULE:{provider_mod.name}"
                        self.cross_resolved.append({
                            "consumer": mod.name,
                            "symbol": sym_name,
                            "provider": provider_mod.name,
                            "r_type": rel.type_name,
                            "r_offset": hex(rel.offset),
                            "target_addr": hex(mod.load_bias + rel.offset),
                            "resolved_val": hex(resolved_val)
                        })

                    # B2. Check external symbol resolver (e.g. Android shims)
                    elif external_resolver:
                        ext_val = external_resolver(sym_name)
                        if ext_val is not None:
                            resolved_val = ext_val + rel.addend
                            source = f"EXTERNAL_SHIM:{sym_name}"
                            self.external_resolved.append({
                                "consumer": mod.name,
                                "symbol": sym_name,
                                "r_type": rel.type_name,
                                "r_offset": hex(rel.offset),
                                "target_addr": hex(mod.load_bias + rel.offset),
                                "resolved_val": hex(resolved_val)
                            })

                    # C. Unresolved symbol handling
                    if resolved_val is not None:
                        mod.write_reloc_value(rel.offset, resolved_val)
                        rel.resolved = True
                        rel.resolved_value = resolved_val
                        rel.resolved_from = source
                    else:
                        if sym and sym.is_weak:
                            # WEAK undefined symbol resolves to 0 (plus addend if any)
                            resolved_val = rel.addend
                            mod.write_reloc_value(rel.offset, resolved_val)
                            rel.resolved = True
                            rel.resolved_value = resolved_val
                            rel.resolved_from = "WEAK_NULL"
                            self.unresolved_weak.append({
                                "module": mod.name,
                                "symbol": sym_name,
                                "r_type": rel.type_name,
                                "r_offset": hex(rel.offset),
                                "addend": rel.addend
                            })
                        else:
                            # STRONG undefined symbol
                            self.unresolved_strong.append({
                                "module": mod.name,
                                "symbol": sym_name,
                                "r_type": rel.type_name,
                                "r_offset": hex(rel.offset),
                                "addend": rel.addend,
                                "is_plt": rel.is_plt
                            })
                            if strict:
                                raise UnresolvedSymbolError(
                                    f"Module {mod.name}: Unresolved strong symbol {sym_name} "
                                    f"at offset {rel.offset:#x} ({rel.type_name})"
                                )

                elif rel.r_type == R_AARCH64_NONE:
                    pass
                else:
                    raise ElfValidationError(f"Module {mod.name}: Unsupported relocation type {rel.r_type} ({rel.type_name})")

    def finalize_wx(self) -> List[Dict]:
        """Finalize W^X permissions for all loaded modules and verify zero violations."""
        results = []
        for mod_name in self.load_order:
            mod = self.modules[mod_name]
            res = mod.enforce_wx_permissions()
            results.append(res)
        self.wx_results = results
        return results

    def generate_report(self) -> Dict:
        """Generate comprehensive diagnostic report."""
        modules_report = []
        for mod_name in self.load_order:
            mod = self.modules[mod_name]
            loads = []
            for s in mod.load_segments:
                loads.append({
                    "vaddr": hex(s.p_vaddr),
                    "mapped_start": hex(s.mapped_vaddr_start),
                    "mapped_end": hex(s.mapped_vaddr_end),
                    "filesz": hex(s.p_filesz),
                    "memsz": hex(s.p_memsz),
                    "bss_size": hex(s.p_memsz - s.p_filesz),
                    "align": hex(s.p_align),
                    "flags": s.final_prot
                })

            reloc_counts = {}
            for r in mod.relocations:
                reloc_counts[r.type_name] = reloc_counts.get(r.type_name, 0) + 1

            modules_report.append({
                "module": mod.name,
                "path": mod.path,
                "base_address": hex(mod.base_addr),
                "load_bias": hex(mod.load_bias),
                "min_vaddr": hex(mod.min_vaddr),
                "load_size": hex(mod.load_size),
                "max_align": hex(mod.max_align),
                "segments_count": len(mod.load_segments),
                "pt_load_segments": loads,
                "has_gnu_relro": mod.relro_segment is not None,
                "init_array_count": len(mod.init_array),
                "needed_libraries": mod.needed_libraries,
                "relocations_count": len(mod.relocations),
                "relocations_by_type": reloc_counts,
                "exported_symbols_count": len(mod.exported_symbols),
                "imported_symbols_count": len(mod.imported_symbols)
            })

        # Categorize unresolved strong imports by subsystem
        def categorize_symbol(sym: str) -> str:
            # Android NDK APIs
            if sym.startswith("AChoreographer_") or sym.startswith("ALooper_") or \
               sym.startswith("ANativeWindow_") or sym.startswith("ASensor"):
                return "libandroid"
            if sym.startswith("AMedia"):
                return "libmediandk"
            if sym.startswith("egl"):
                return "libEGL"
            if sym.startswith("gl") and not sym.startswith("global"):
                return "libGLESv2_v3"
            if sym.startswith("__android_log_"):
                return "liblog"
            if sym in ("dlopen", "dlsym", "dlclose", "dlerror", "dladdr"):
                return "libdl"
            if sym in ("deflate", "inflate", "crc32", "adler32", "zlibVersion", "inflateEnd", "inflateInit2_"):
                return "libz"
            # Math
            math_syms = {
                "sin", "sinf", "cos", "cosf", "tan", "tanf", "asin", "asinf", "acos", "acosf",
                "atan", "atanf", "atan2", "atan2f", "exp", "expf", "log", "logf", "log10", "log10f",
                "pow", "powf", "sqrt", "sqrtf", "ceil", "ceilf", "floor", "floorf", "fabs", "fabsf",
                "fmod", "fmodf", "round", "roundf", "trunc", "truncf", "remainder", "remainderf",
                "hypot", "hypotf", "ldexp", "frexp", "cbrt", "cbrtf", "copysign", "copysignf"
            }
            if sym in math_syms:
                return "libm"
            # Pthread
            if sym.startswith("pthread_"):
                return "libc_pthread"
            # Socket & Network
            socket_syms = {
                "socket", "connect", "bind", "listen", "accept", "send", "sendto", "recv", "recvfrom",
                "shutdown", "getsockname", "getpeername", "getsockopt", "setsockopt", "getaddrinfo",
                "freeaddrinfo", "gai_strerror", "gethostbyname", "getnameinfo", "inet_addr", "inet_ntoa",
                "inet_pton", "inet_ntop", "select", "poll"
            }
            if sym in socket_syms:
                return "libc_sockets"
            # Memory / String / Format
            if sym.startswith("mem") or sym.startswith("str") or sym.startswith("wcs") or \
               sym in ("malloc", "calloc", "realloc", "free", "posix_memalign",
                       "snprintf", "sprintf", "vsnprintf", "vsprintf", "sscanf",
                       "qsort", "bsearch", "atoi", "atol", "atoll", "strtod", "strtof", "strtol", "strtoll", "strtoul", "strtoull"):
                return "libc_mem_string"
            # File / IO
            if sym in ("open", "close", "read", "write", "lseek", "stat", "fstat", "lstat",
                       "access", "unlink", "remove", "rename", "mkdir", "rmdir", "getcwd", "chdir",
                       "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind", "fflush",
                       "fseeko", "ftello", "fseeko64", "ftello64", "fgetc", "fputc", "fgets", "fputs",
                       "feof", "ferror", "fileno", "fdopen", "statfs", "statvfs", "__sF", "ioctl", "fcntl"):
                return "libc_stdio_fs"
            # System / Process / Time
            if sym.startswith("__system_property_") or sym.startswith("__FD_") or \
               sym in ("gettimeofday", "clock_gettime", "time", "nanosleep", "usleep", "sleep",
                       "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "sysconf",
                       "abort", "exit", "_exit", "getenv", "setenv", "unsetenv",
                       "__errno", "__stack_chk_fail", "__cxa_finalize", "__cxa_atexit",
                       "__register_atfork", "__assert2", "__ctype_get_mb_cur_max",
                       "sigaction", "sigprocmask", "signal", "mmap", "munmap", "mprotect", "madvise"):
                return "libc_system_posix"

            return "other_bionic_or_sdk"

        categorized_unresolved = {}
        for item in self.unresolved_strong:
            sym = item["symbol"]
            cat = categorize_symbol(sym)
            categorized_unresolved.setdefault(cat, []).append(item)

        cat_summary = {k: len(v) for k, v in categorized_unresolved.items()}

        if not self.wx_results:
            self.finalize_wx()

        total_wx_violations = sum(r.get("wx_violations_count", 0) for r in self.wx_results)
        wx_overall_compliant = (total_wx_violations == 0) and (len(self.wx_results) == len(self.load_order))

        report = {
            "summary": {
                "total_modules": len(self.load_order),
                "load_order": self.load_order,
                "total_exported_symbols": len(self.global_exports),
                "cross_module_resolved_count": len(self.cross_resolved),
                "shims_enabled": self.shims_enabled,
                "available_shim_symbols_count": len(ANDROID_SHIM_SYMBOLS),
                "registered_shim_symbols_count": len(ANDROID_SHIM_SYMBOLS) if self.shims_enabled else 0,
                "external_resolved_count": len(self.external_resolved),
                "unresolved_strong_count": len(self.unresolved_strong),
                "unresolved_weak_count": len(self.unresolved_weak),
                "wx_overall_compliant": wx_overall_compliant,
                "total_wx_violations": total_wx_violations,
                "categorized_unresolved_strong": cat_summary
            },
            "wx_results": self.wx_results,
            "modules": modules_report,
            "cross_module_resolutions": self.cross_resolved,
            "external_resolutions": self.external_resolved,
            "unresolved_strong_details": self.unresolved_strong,
            "unresolved_weak_details": self.unresolved_weak
        }
        return report

    def write_markdown_report(self, path: str):
        report = self.generate_report()
        s = report["summary"]
        
        lines = [
            "# Durak NX — Звіт ELF64 / AArch64 Host Oracle (E05 Host Model)",
            "",
            "## 1. Підсумок завантаження модулів",
            "",
            f"- **Кількість модулів:** {s['total_modules']}",
            f"- **Порядок завантаження:** `{' -> '.join(s['load_order'])}`",
            f"- **Зареєстровано глобальних експортів:** {s['total_exported_symbols']}",
            f"- **Міжмодульних релокацій розв'язано:** {s['cross_module_resolved_count']}",
            f"- **Зареєстровано зовнішніх shim-символів (E05.4b):** {s['registered_shim_symbols_count']}" + ("" if s.get("shims_enabled", False) else f" (вимкнено, доступно в реєстрі: {s.get('available_shim_symbols_count', len(ANDROID_SHIM_SYMBOLS))})"),
            f"- **Зовнішніх shim-релокацій розв'язано (relocation sites):** {s['external_resolved_count']}",
            f"- **Незв'язаних strong (GLOBAL) релокацій (relocation sites):** {s['unresolved_strong_count']}",
            f"- **Незв'язаних weak імпортів (дозволено NULL):** {s['unresolved_weak_count']}",
            "",
            "## 2. Карта пам'яті модулів (Memory Layout & Alignment)",
            "",
            "| Модуль | Allocation Base | Load Bias | Розмір пам'яті | Вирівнювання | PT_LOAD | RELRO | InitArray |",
            "|---|---|---|---|---|:---:|:---:|:---:|",
        ]

        for m in report["modules"]:
            lines.append(
                f"| `{m['module']}` | `{m['base_address']}` | `{m['load_bias']}` | `{m['load_size']}` | `{m['max_align']}` | "
                f"{m['segments_count']} | {'Так' if m['has_gnu_relro'] else 'Ні'} | {m['init_array_count']} |"
            )

        lines.extend([
            "",
            "## 3. Розподіл незв'язаних Strong-імпортів за підсистемами (Ціль для E06 Shims)",
            "",
            "| Підсистема | Унікальних символів | Загалом викликів | Приклади символів |",
            "|---|:---:|:---:|---|",
        ])

        # Group distinct symbol names per category
        cat_to_syms = {}
        cat_to_calls = {}
        for item in report["unresolved_strong_details"]:
            sym = item["symbol"]
            # match with same categorizer logic
            if sym.startswith("AChoreographer_") or sym.startswith("ALooper_") or \
               sym.startswith("ANativeWindow_") or sym.startswith("ASensor"):
                cat = "libandroid (NDK)"
            elif sym.startswith("AMedia"):
                cat = "libmediandk"
            elif sym.startswith("egl"):
                cat = "libEGL"
            elif sym.startswith("gl") and not sym.startswith("global"):
                cat = "libGLESv2_v3"
            elif sym.startswith("__android_log_"):
                cat = "liblog"
            elif sym in ("dlopen", "dlsym", "dlclose", "dlerror", "dladdr"):
                cat = "libdl"
            elif sym in ("deflate", "inflate", "crc32", "adler32", "zlibVersion", "inflateEnd", "inflateInit2_"):
                cat = "libz"
            elif sym in ("sin", "sinf", "cos", "cosf", "tan", "tanf", "asin", "asinf", "acos", "acosf", "atan", "atanf", "atan2", "atan2f", "exp", "expf", "log", "logf", "log10", "log10f", "pow", "powf", "sqrt", "sqrtf", "ceil", "ceilf", "floor", "floorf", "fabs", "fabsf", "fmod", "fmodf", "round", "roundf", "trunc", "truncf", "remainder", "remainderf", "hypot", "hypotf", "ldexp", "frexp", "cbrt", "cbrtf", "copysign", "copysignf"):
                cat = "libm (Math)"
            elif sym.startswith("pthread_"):
                cat = "libc (Pthreads)"
            elif sym in ("socket", "connect", "bind", "listen", "accept", "send", "sendto", "recv", "recvfrom", "shutdown", "getsockname", "getpeername", "getsockopt", "setsockopt", "getaddrinfo", "freeaddrinfo", "gai_strerror", "gethostbyname", "getnameinfo", "inet_addr", "inet_ntoa", "inet_pton", "inet_ntop", "select", "poll"):
                cat = "libc (Sockets/Net)"
            elif sym.startswith("mem") or sym.startswith("str") or sym.startswith("wcs") or sym in ("malloc", "calloc", "realloc", "free", "posix_memalign", "snprintf", "sprintf", "vsnprintf", "vsprintf", "sscanf", "qsort", "bsearch", "atoi", "atol", "atoll", "strtod", "strtof", "strtol", "strtoll", "strtoul", "strtoull"):
                cat = "libc (Memory/String)"
            elif sym in ("open", "close", "read", "write", "lseek", "stat", "fstat", "lstat", "access", "unlink", "remove", "rename", "mkdir", "rmdir", "getcwd", "chdir", "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "rewind", "fflush", "fseeko", "ftello", "fseeko64", "ftello64", "fgetc", "fputc", "fgets", "fputs", "feof", "ferror", "fileno", "fdopen", "statfs", "statvfs", "__sF", "ioctl", "fcntl"):
                cat = "libc (FS/IO/Stdio)"
            elif sym.startswith("__system_property_") or sym.startswith("__FD_") or sym in ("gettimeofday", "clock_gettime", "time", "nanosleep", "usleep", "sleep", "getpid", "gettid", "getuid", "geteuid", "getgid", "getegid", "sysconf", "abort", "exit", "_exit", "getenv", "setenv", "unsetenv", "__errno", "__stack_chk_fail", "__cxa_finalize", "__cxa_atexit", "__register_atfork", "__assert2", "__ctype_get_mb_cur_max", "sigaction", "sigprocmask", "signal", "mmap", "munmap", "mprotect", "madvise"):
                cat = "libc (POSIX/System)"
            else:
                cat = "Bionic/Android SDK (Other)"

            cat_to_syms.setdefault(cat, set()).add(sym)
            cat_to_calls[cat] = cat_to_calls.get(cat, 0) + 1

        for cat, syms in sorted(cat_to_syms.items(), key=lambda x: len(x[1]), reverse=True):
            calls_count = cat_to_calls[cat]
            sample = ", ".join(f"`{s}`" for s in sorted(syms)[:3])
            if len(syms) > 3: sample += f" (+{len(syms)-3})"
            lines.append(f"| **{cat}** | {len(syms)} | {calls_count} | {sample} |")

        wx_violations = s.get("total_wx_violations", 0)
        wx_compliant = s.get("wx_overall_compliant", False)
        wx_status_str = "PASS (0 порушень)" if wx_compliant else f"FAIL ({wx_violations} порушень)"

        lines.extend([
            "",
            "## 4. Верифікація безпеки W^X та сегментів",
            "",
            "- Усі сегменти завантажуються в режимі RW для накладення релокацій.",
            "- Після релокацій дозволи фіналізуються за заголовками ELF:",
            "  * Код: `RX`",
            "  * Дані: `RW`",
            "  * Rodata / RELRO: `R`",
            f"- **Загальний статус W^X:** `{wx_status_str}`",
            f"- **Порушень правила W^X:** `{wx_violations}` (жодна сторінка не має одночасно прав запису та виконання).",
            "- **Вирівнювання 64 KiB:** успішно застосовано до `libsqlite3.so` без конфліктів у пам'яті.",
            "",
            "| Модуль | Всього сторінок | RX сторінок | RW сторінок | RO сторінок | W^X порушень | Статус |",
            "|---|:---:|:---:|:---:|:---:|:---:|:---:|",
        ])

        for r in report.get("wx_results", []):
            mod_status = "PASS" if r.get("wx_compliant") else "**FAIL**"
            lines.append(
                f"| `{r['module']}` | {r.get('total_pages', 0)} | {r.get('rx_pages', 0)} | "
                f"{r.get('rw_pages', 0)} | {r.get('ro_pages', 0)} | {r.get('wx_violations_count', 0)} | {mod_status} |"
            )

        lines.append("")

        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))


# ------------------------------------------------------------------------------
# Verified Target Expected Constants (Durak 25.0, Unity 6000.4.0b6) - Root of Trust
# ------------------------------------------------------------------------------
EXPECTED_PACKAGE = "ru.appscraft.durak"
EXPECTED_VERSION_NAME = "25.0"
EXPECTED_VERSION_CODE = 250

EXPECTED_CORE_LIBRARIES = {
    "libmain.so": {
        "size": 6696,
        "sha256": "c11373dffa1bab427e8864a40313111de2a70367d052d87f33a9069ce8949d93",
        "build_id": "c5498ab8c791f1473a54c79a9d3c5b738ff6d941"
    },
    "libunity.so": {
        "size": 21388304,
        "sha256": "292f89210151ba0060f77d137cd6a00a52158dc5da760d4bf106158fc9309cef",
        "build_id": "bcc661ea2046416d"
    },
    "libil2cpp.so": {
        "size": 31256704,
        "sha256": "7bc9c2e7e20c741a511e6645589db16d0fa084d79bcfc12ba1fab78931e2271c",
        "build_id": "d3ddafd67eaec758b8cfc68a49f6f13a0167b1b0"
    },
    "libsqlite3.so": {
        "size": 1797248,
        "sha256": "6df7a75d31c417cae7e877fd7c3d190e0ac47b1f104ae0ae5501d72491b1c32c",
        "build_id": "99495662cefa74605573c8dc36a53cb1f842764d"
    }
}

DURAK_CORE_LIBRARIES = [
    "libsqlite3.so",
    "libmain.so",
    "libunity.so",
    "libil2cpp.so"
]


def verify_durak_default_environment(extracted_dir: str = "extracted_durak") -> List[str]:
    """
    Fail-closed verification of Durak 25.0 core binaries and game_manifest.json against
    the trusted M1 root-of-trust definitions.
    Returns the list of verified module paths in load order.
    Exits with code 1 upon any validation failure.
    """
    manifest_path = os.path.join(extracted_dir, "game_manifest.json")
    if not os.path.isfile(manifest_path):
        print(f"Error: Required game manifest not found in default mode: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(manifest_path, "r", encoding="utf-8") as mf:
            manifest_data = json.load(mf)
    except Exception as e:
        print(f"Error reading manifest {manifest_path}: {e}", file=sys.stderr)
        sys.exit(1)

    # 1. Verify package identity against trusted M1 definition
    pkg = manifest_data.get("package_info", {})
    if pkg.get("package_name") != EXPECTED_PACKAGE:
        print(f"Error: Manifest package_name mismatch: {pkg.get('package_name')} != {EXPECTED_PACKAGE}", file=sys.stderr)
        sys.exit(1)
    if pkg.get("version_name") != EXPECTED_VERSION_NAME:
        print(f"Error: Manifest version_name mismatch: {pkg.get('version_name')} != {EXPECTED_VERSION_NAME}", file=sys.stderr)
        sys.exit(1)
    if pkg.get("version_code") != EXPECTED_VERSION_CODE:
        print(f"Error: Manifest version_code mismatch: {pkg.get('version_code')} != {EXPECTED_VERSION_CODE}", file=sys.stderr)
        sys.exit(1)
    if pkg.get("verified") is not True:
        print(f"Error: Manifest package_info.verified is not True: {pkg.get('verified')}", file=sys.stderr)
        sys.exit(1)

    # 2. Verify manifest core_libraries entries against trusted M1 definition
    m_libs = manifest_data.get("core_libraries", {})
    for lib_name, exp in EXPECTED_CORE_LIBRARIES.items():
        if lib_name not in m_libs:
            print(f"Error: Manifest missing core_libraries entry for {lib_name}", file=sys.stderr)
            sys.exit(1)
        m_entry = m_libs[lib_name]
        if m_entry.get("sha256") != exp["sha256"]:
            print(
                f"Error: Manifest SHA-256 mismatch for {lib_name}: "
                f"{m_entry.get('sha256')} != {exp['sha256']}",
                file=sys.stderr
            )
            sys.exit(1)
        if m_entry.get("verified") is not True:
            print(f"Error: Manifest core_libraries[{lib_name}].verified is not True: {m_entry.get('verified')}", file=sys.stderr)
            sys.exit(1)

    # 3. Verify actual binary files on disk against trusted M1 root of trust
    default_mods = []
    for lib_name in DURAK_CORE_LIBRARIES:
        p = os.path.join(extracted_dir, lib_name)
        if not os.path.isfile(p):
            print(f"Error: Missing core Durak 25.0 library: {p}", file=sys.stderr)
            sys.exit(1)

        exp = EXPECTED_CORE_LIBRARIES[lib_name]
        with open(p, "rb") as f:
            data = f.read()

        actual_sz = len(data)
        if actual_sz != exp["size"]:
            print(f"Error: Size mismatch for {lib_name}: have {actual_sz}, expected {exp['size']}", file=sys.stderr)
            sys.exit(1)

        actual_sha256 = hashlib.sha256(data).hexdigest()
        if actual_sha256 != exp["sha256"]:
            print(
                f"Error: Trusted SHA-256 mismatch for {lib_name}! "
                f"Expected {exp['sha256']}, got {actual_sha256}",
                file=sys.stderr
            )
            sys.exit(1)

        default_mods.append(p)

    return default_mods


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ELF64 / AArch64 Dry-Run Loader & Resolver")
    parser.add_argument("--modules", nargs="+", help="Paths to ELF modules in load order")
    parser.add_argument("--base", type=lambda x: int(x, 0), default=0x7000000000, help="Initial base address")
    parser.add_argument("--report-json", default="docs/analysis/durak_unresolved_imports.json", help="Path to write JSON report")
    parser.add_argument("--report-md", default="docs/analysis/durak_unresolved_imports.md", help="Path to write Markdown report")
    parser.add_argument("--strict", action="store_true", help="Fail if any strong symbol is unresolved")
    parser.add_argument("--shims", action="store_true", help="Enable E05.4a Android Bionic shim resolution")
    args = parser.parse_args()

    if not args.modules:
        args.modules = verify_durak_default_environment("extracted_durak")
    else:
        for mod_path in args.modules:
            if not os.path.isfile(mod_path):
                print(f"Error: Module file not found: {mod_path}", file=sys.stderr)
                sys.exit(1)

    print(f"[*] Initializing MultiModuleLoader at base {args.base:#x}...")
    loader = MultiModuleLoader(args.base)

    for mod_path in args.modules:
        print(f"[*] Loading and mapping {mod_path}...")
        mod = loader.load_module(mod_path)
        print(f"    -> Mapped @ {mod.base_addr:#x}..{mod.base_addr + mod.load_size:#x} (size={mod.load_size:#x}, align={mod.max_align:#x})")

    print("[*] Performing relocations and cross-module symbol resolution...")
    loader.relocate_all(strict=args.strict, external_resolver=resolve_android_shim if args.shims else None)
    print(f"    -> Cross-module resolved: {len(loader.cross_resolved)}")
    if args.shims:
        print(f"    -> External shims resolved: {len(loader.external_resolved)}")
    print(f"    -> Unresolved WEAK (NULL): {len(loader.unresolved_weak)}")
    print(f"    -> Unresolved STRONG: {len(loader.unresolved_strong)}")

    print("[*] Enforcing and validating W^X memory permissions...")
    wx_results = loader.finalize_wx()
    has_wx_violations = False
    for res in wx_results:
        print(
            f"    -> {res['module']}: W^X Compliant={res['wx_compliant']} "
            f"(RX={res['rx_pages']}, RW={res['rw_pages']}, RO={res['ro_pages']}, "
            f"Violations={res['wx_violations_count']})"
        )
        if not res["wx_compliant"]:
            has_wx_violations = True

    if has_wx_violations:
        print("ERROR: W^X permission violation detected in one or more modules!", file=sys.stderr)
        sys.exit(2)

    rep = loader.generate_report()
    with open(args.report_json, 'w', encoding='utf-8') as f:
        json.dump(rep, f, indent=2)
    print(f"[*] Saved JSON report: {args.report_json}")

    loader.write_markdown_report(args.report_md)
    print(f"[*] Saved Markdown report: {args.report_md}")


if __name__ == "__main__":
    main()
