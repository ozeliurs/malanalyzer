"""Address-aware helpers available to agent-authored Python inside the sandbox."""

import io
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP


class BinaryImage:
    """PE/ELF mapping: all public addresses are VAs, not RVAs or file offsets."""

    def __init__(self, path="/input/sample.bin"):
        self.data = Path(path).read_bytes()
        self.sections = []
        self.image_base = 0
        if self.data.startswith(b"MZ"):
            import pefile

            pe = pefile.PE(data=self.data, fast_load=True)
            self.format = "PE"
            self.bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
            self.arch = {0x14C: "x86", 0x8664: "x86", 0xAA64: "arm64"}.get(pe.FILE_HEADER.Machine)
            self.image_base = pe.OPTIONAL_HEADER.ImageBase
            self.entry = self.image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                self.sections.append({
                    "name": section.Name.rstrip(b"\0").decode("utf-8", "replace"),
                    "va": self.image_base + section.VirtualAddress,
                    "offset": section.PointerToRawData, "size": section.SizeOfRawData,
                    "virtual_size": section.Misc_VirtualSize,
                    "executable": bool(section.Characteristics & 0x20000000),
                })
            self.header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
            pe.close()
        elif self.data.startswith(b"\x7fELF"):
            from elftools.elf.elffile import ELFFile

            elf = ELFFile(io.BytesIO(self.data))
            self.format, self.bits, self.entry = "ELF", elf.elfclass, elf.header["e_entry"]
            self.arch = {"EM_X86_64": "x86", "EM_386": "x86", "EM_AARCH64": "arm64"}.get(elf.header["e_machine"])
            for section in elf.iter_sections():
                if section["sh_type"] != "SHT_NOBITS" and section["sh_flags"] & 2:
                    self.sections.append({
                        "name": section.name, "va": section["sh_addr"],
                        "offset": section["sh_offset"], "size": section["sh_size"],
                        "virtual_size": section["sh_size"], "executable": bool(section["sh_flags"] & 4),
                    })
            self.header_size = 0
        else:
            raise ValueError("BinaryImage supports PE and ELF; use Python/file/objdump for other formats.")

    def va_to_offset(self, va: int) -> int:
        for section in self.sections:
            delta = va - section["va"]
            if 0 <= delta < section["size"]:
                offset = section["offset"] + delta
                if offset < len(self.data):
                    return offset
        if self.format == "PE" and self.image_base <= va < self.image_base + self.header_size:
            return va - self.image_base
        raise ValueError(f"VA {va:#x} is not backed by file data (possibly virtual/BSS).")

    def read(self, va: int, size: int) -> bytes:
        offset = self.va_to_offset(va)
        for section in self.sections:
            if section["va"] <= va < section["va"] + section["size"]:
                size = min(size, section["size"] - (va - section["va"]))
                break
        return self.data[offset:offset + min(size, 1_048_576)]

    def engine(self, *, skipdata=False):
        if self.arch == "x86":
            engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.bits == 64 else capstone.CS_MODE_32)
        elif self.arch == "arm64":
            engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            raise ValueError("Unsupported architecture for helper disassembly.")
        engine.detail = True
        engine.skipdata = skipdata
        return engine

    def disassemble(self, va=None, size=1024, count=200):
        va = self.entry if va is None else va
        for instruction in self.engine().disasm(self.read(va, min(size, 65536)), va, count=min(count, 1000)):
            row = {"va": hex(instruction.address), "bytes": instruction.bytes.hex(),
                   "instruction": f"{instruction.mnemonic} {instruction.op_str}".strip()}
            if self.arch == "x86":
                targets = self._targets(instruction)
                if targets:
                    row["targets"] = [hex(target) for target in targets]
            yield row

    @staticmethod
    def _targets(instruction):
        targets = []
        for operand in instruction.operands:
            if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                targets.append(instruction.address + instruction.size + operand.mem.disp)
            elif operand.type == X86_OP_IMM:
                targets.append(operand.imm)
            elif operand.type == X86_OP_MEM and not operand.mem.base and not operand.mem.index:
                targets.append(operand.mem.disp)
        return targets

    def xrefs(self, start: int, end: int | None = None, limit=200):
        if self.arch != "x86":
            raise ValueError("The xref helper supports x86/x64; use Capstone scripts for other architectures.")
        end = start + 1 if end is None else end
        found = 0
        for section in self.sections:
            if not section["executable"]:
                continue
            code = self.data[section["offset"]:section["offset"] + section["size"]]
            for instruction in self.engine(skipdata=True).disasm(code, section["va"]):
                if instruction.id == 0:  # Skip embedded bytes instead of stopping the whole scan.
                    continue
                targets = [target for target in self._targets(instruction) if start <= target < end]
                if targets:
                    yield {"va": hex(instruction.address), "instruction": f"{instruction.mnemonic} {instruction.op_str}",
                           "targets": [hex(target) for target in targets]}
                    found += 1
                    if found >= min(limit, 1000):
                        return
