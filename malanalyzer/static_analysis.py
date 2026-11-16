"""Bounded, static-only evidence collection. Never imports or executes a sample."""

import hashlib
import io
import ipaddress
import json
import math
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from malanalyzer.models import IOC, IOCType

ASCII = re.compile(rb"[\x20-\x7e]{4,}")
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL = re.compile(r"\b(?:https?|hxxps?|ftp)://[^\s<>\"'`\x00]+", re.I)
DOMAIN = re.compile(
    r"(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|info|biz|xyz|top|site|online|cloud|live|shop|club|icu|"
    r"onion|local|test|invalid|[a-z]{2})(?![\w.-])", re.I,
)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6 = re.compile(r"(?<![\w:])(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4}(?![\w:])", re.I)
EMAIL = re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b", re.I)
REGISTRY = re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[^\s\"'<>]+", re.I)
WINPATH = re.compile(r"\b[A-Z]:\\[^\r\n\"'<>|]{2,240}", re.I)
SUSPICIOUS = re.compile(
    r"https?://|hxxp|socket|powershell|cmd\.exe|VirtualAlloc|WriteProcessMemory|"
    r"CreateRemoteThread|Crypt|RegSet|autorun|schtasks|base64|ransom|mutex|beacon", re.I,
)


def entropy(data: bytes) -> float:
    length = len(data)
    return round(-sum((n / length) * math.log2(n / length) for n in Counter(data).values()), 3) if length else 0


def disassemble(code: bytes, address: int, arch: str, bits: int) -> list[dict]:
    import capstone

    if arch == "x86":
        engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
    elif arch == "arm64":
        engine = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    else:
        return []
    return [
        {"address": hex(ins.address), "instruction": f"{ins.mnemonic} {ins.op_str}".strip()}
        for ins in engine.disasm(code[:2048], address, count=128)
    ]


def pe_metadata(data: bytes) -> dict:
    import pefile

    pe = pefile.PE(data=data, fast_load=True)
    try:
        pe.parse_data_directories(directories=[0, 1])
        bits = 64 if pe.OPTIONAL_HEADER.Magic == 0x20B else 32
        arch = {0x14C: "x86", 0x8664: "x86", 0xAA64: "arm64"}.get(pe.FILE_HEADER.Machine, "unknown")
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        imports = []
        for module in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:128]:
            for symbol in module.imports[:128]:
                imports.append({
                    "library": module.dll.decode("utf-8", "replace"),
                    "name": symbol.name.decode("utf-8", "replace") if symbol.name else f"ordinal:{symbol.ordinal}",
                })
                if len(imports) >= 1024:
                    break
            if len(imports) >= 1024:
                break
        return {
            "format": "PE", "architecture": arch, "bits": bits,
            "machine": hex(pe.FILE_HEADER.Machine), "entry_point_rva": hex(entry),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "compile_timestamp_untrusted": pe.FILE_HEADER.TimeDateStamp,
            "sections": [
                {"name": section.Name.rstrip(b"\0").decode("utf-8", "replace"),
                 "virtual_address": hex(section.VirtualAddress),
                 "raw_size": section.SizeOfRawData,
                 "entropy": round(section.get_entropy(), 3),
                 "characteristics": hex(section.Characteristics)}
                for section in pe.sections[:96]
            ],
            "imports": imports,
            "exports": [
                symbol.name.decode("utf-8", "replace") for symbol in
                getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", [])[:256] if symbol.name
            ],
            "entry_disassembly": disassemble(pe.get_data(entry, 2048), pe.OPTIONAL_HEADER.ImageBase + entry, arch, bits),
            "parser_warnings": pe.get_warnings()[:20],
        }
    finally:
        pe.close()


def elf_metadata(data: bytes) -> dict:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    elf = ELFFile(io.BytesIO(data))
    entry = elf.header["e_entry"]
    sections, symbols, code = [], [], b""
    for section in elf.iter_sections():
        if len(sections) < 128:
            sections.append({"name": section.name, "size": section["sh_size"], "type": section["sh_type"]})
        if isinstance(section, SymbolTableSection) and len(symbols) < 512:
            for symbol in section.iter_symbols():
                if symbol.name:
                    symbols.append({"name": symbol.name[:300], "imported": symbol["st_shndx"] == "SHN_UNDEF"})
                if len(symbols) >= 512:
                    break
        if section["sh_type"] != "SHT_NOBITS" and section["sh_addr"] <= entry < section["sh_addr"] + section["sh_size"]:
            offset = section["sh_offset"] + entry - section["sh_addr"]
            code = data[offset:offset + min(2048, section["sh_size"] - (entry - section["sh_addr"]))]
    arch = {"EM_X86_64": "x86", "EM_386": "x86", "EM_AARCH64": "arm64"}.get(elf.header["e_machine"], "unknown")
    return {
        "format": "ELF", "architecture": arch, "bits": elf.elfclass,
        "machine": elf.header["e_machine"], "entry_point": hex(entry),
        "sections": sections, "symbols": symbols,
        "entry_disassembly": disassemble(code, entry, arch, elf.elfclass),
    }


def candidates(text: str, offset: int) -> list[IOC]:
    found: dict[tuple[str, str], IOC] = {}

    def add(value: str, kind: IOCType) -> None:
        if len(value) > 4096:
            return
        found[(kind.value, value)] = IOC(
            ioc=value, type=kind,
            description=f"Literal static indicator near file offset {offset:#x}; its operational role is unconfirmed.",
        )

    for match in URL.finditer(text):
        value = match.group().rstrip(".,;)]}")
        value = re.sub(r"^hxxp", "http", value, flags=re.I).replace("[.]", ".")
        try:
            host = urlsplit(value).hostname
            if host:
                add(value, IOCType.URL)
                try:
                    address = ipaddress.ip_address(host)
                    add(str(address), IOCType.IPV4 if address.version == 4 else IOCType.IPV6)
                except ValueError:
                    add(host.lower(), IOCType.DOMAIN)
        except ValueError:
            pass
    for match in DOMAIN.finditer(text):
        add(match.group().lower(), IOCType.DOMAIN)
    for pattern, version in ((IPV4, 4), (IPV6, 6)):
        for match in pattern.finditer(text):
            try:
                address = ipaddress.ip_address(match.group())
                if address.version == version:
                    add(str(address), IOCType.IPV4 if version == 4 else IOCType.IPV6)
            except ValueError:
                pass
    for pattern, kind in ((EMAIL, IOCType.EMAIL), (REGISTRY, IOCType.REGISTRY_KEY), (WINPATH, IOCType.FILE_PATH)):
        for match in pattern.finditer(text):
            add(match.group().rstrip(" ;,)"), kind)
    return list(found.values())


def collect(path: Path) -> dict:
    data = path.read_bytes()
    hashes = {
        name: hashlib.new(name, data, usedforsecurity=False).hexdigest()
        for name in ("md5", "sha1", "sha256")
    }
    warnings = [
        "Static analysis only: no sample execution, network contact, unpacking, or emulation.",
        "Strings and regex indicators are candidates, not proof of malicious behavior or C2 use.",
        "Executable metadata, symbols, and entry-point disassembly are bounded previews, not a full decompilation.",
    ]
    metadata = {"format": "unknown"}
    try:
        if data.startswith(b"MZ"):
            metadata = pe_metadata(data)
        elif data.startswith(b"\x7fELF"):
            metadata = elf_metadata(data)
        elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"):
            metadata = {"format": "Mach-O / universal (header detection only)"}
        elif data.startswith(b"PK\x03\x04"):
            metadata = {"format": "ZIP container (not extracted)"}
    except Exception as exc:
        warnings.append(f"Executable metadata parser failed ({type(exc).__name__}); string analysis remains available.")

    indicators: dict[tuple[str, str], IOC] = {}
    for kind, digest in hashes.items():
        indicators[(kind, digest)] = IOC(ioc=digest, type=IOCType(kind), description=f"{kind.upper()} hash of the uploaded sample.")
    strings, string_count, budget = [], 0, 60_000
    # Keep interesting strings even if a large benign preamble fills the ordinary preview.
    ordinary, interesting = [], []
    for pattern, encoding, stride in ((ASCII, "ascii", 1), (UTF16, "utf-16-le", 2)):
        for match in pattern.finditer(data):
            raw = match.group()
            for start in range(0, len(raw), 3968 * stride):
                text = raw[start:start + 4096 * stride].decode(encoding, "replace")
                offset = match.start() + start
                string_count += 1
                extracted = candidates(text, offset)
                for indicator in extracted:
                    key = (indicator.type.value, indicator.ioc)
                    if len(indicators) < 2000 or key in indicators:
                        indicators.setdefault(key, indicator)
                item = {"offset": offset, "encoding": encoding, "text": text[:1000]}
                if (extracted or SUSPICIOUS.search(text)) and len(interesting) < 700:
                    interesting.append(item)
                elif len(ordinary) < 200:
                    ordinary.append(item)
    for item in interesting + ordinary:
        cost = len(item["text"]) + 100
        if cost <= budget:
            strings.append(item)
            budget -= cost
    if string_count > len(strings):
        warnings.append(f"String evidence is truncated: {len(strings)} previews retained from {string_count} chunks; indicators were scanned across all chunks.")
    if len(indicators) >= 2000:
        warnings.append("Indicator count reached the 2000-item cap; additional candidates may be omitted.")

    source = None
    preview = data[:40_000]
    if preview.startswith((b"\xff\xfe", b"\xfe\xff")):
        source = preview.decode("utf-16", "replace")
    elif preview and b"\0" not in preview and sum(b in (9, 10, 13) or 32 <= b <= 126 or b >= 128 for b in preview) / len(preview) > 0.95:
        source = preview.decode("utf-8", "replace")
    if source is not None:
        if metadata["format"] == "unknown":
            metadata["format"] = "text / script"
        if len(data) > len(preview):
            warnings.append("Source preview is truncated to the first 40000 bytes.")
    return {
        "schema_version": 1, "size": len(data), "hashes": hashes,
        "entropy": entropy(data), "magic_hex": data[:32].hex(),
        "executable": metadata, "strings": strings, "source_preview": source,
        "candidate_iocs": [item.model_dump() for item in indicators.values()],
        "limitations": warnings,
    }


def main() -> None:
    # Parsers run in a disposable subprocess with CPU/memory bounds on Unix.
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    if sys.platform != "darwin":
        resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    print(json.dumps(collect(Path(sys.argv[1])), ensure_ascii=True))


if __name__ == "__main__":
    main()
