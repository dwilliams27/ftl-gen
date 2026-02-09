# Phase 1: Binary Reconnaissance Module

**Goal**: Programmatic inspection of the FTL Mach-O binary.

## New files
- `src/ftl_gen/binary/__init__.py` — package init
- `src/ftl_gen/binary/recon.py` — `BinaryRecon` class using `lief`

## `BinaryRecon` capabilities
- Parse Mach-O header (arch, segments, sections, PIE flag)
- Find all augment name strings in `__cstring` section with virtual addresses + file offsets
- Check code signing status via `codesign -dvv` subprocess
- Find code caves (contiguous NUL regions in executable segments)
- Report linked libraries via `otool -L`

## Data classes

```python
@dataclass
class BinaryInfo:
    path: Path
    architecture: str           # "x86_64"
    code_signed: bool
    hardened_runtime: bool
    segments: list[SegmentInfo]
    augment_strings: list[StringRef]  # name, vaddr, file_offset, section
    code_caves: list[tuple[int, int, int]]  # offset, size, segment

@dataclass
class StringRef:
    value: str
    virtual_address: int
    file_offset: int
    section: str
```

## CLI command: `ftl-gen binary-info`
- Rich table output showing binary metadata, augment strings found, code cave space, signing status

## Dependency: add `[binary]` optional group to `pyproject.toml`

```toml
binary = ["lief>=0.15.0", "capstone>=5.0.0"]
```
