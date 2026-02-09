# Deep Modding Research: Beyond XML Patching

Research playbook for breaking past the limits of Slipstream XML patching. See [xml-modding-limits.md](xml-modding-limits.md) for what those limits are.

Every technical claim is tagged:
- **VERIFIED** — confirmed by direct testing or tool output
- **LIKELY** — strong indirect evidence or consistent with known FTL/macOS behavior
- **NEEDS_INVESTIGATION** — plausible but unconfirmed, requires hands-on work

---

## Prerequisites: Binary Reconnaissance

Concrete steps that must happen before either approach is viable. These are cheap (minutes each) and gate all further work.

### 1. Check code signing — `codesign -dvv`
Run `codesign -dvv /path/to/FTL` on the game binary. Look for:
- `runtime` flag in `CodeDirectory` — if present, FTL uses **hardened runtime**, which blocks `DYLD_INSERT_LIBRARIES` unless the binary also has the `com.apple.security.cs.allow-dyld-environment-variables` entitlement.
- Check entitlements with `codesign -d --entitlements - /path/to/FTL`.
- **LIKELY**: Steam games on macOS are generally ad-hoc signed without hardened runtime, since they need to work on older macOS versions. But this must be verified.

### 2. Check dynamic dependencies — `otool -L`
Run `otool -L /path/to/FTL` to see linked libraries. Expected: SDL2, OpenGL/OpenAL, libc++, system frameworks. This tells us what function families are available for interception.
- **LIKELY**: FTL links SDL2 dynamically (common for indie games on macOS).

### 3. Confirm architecture — `file`
Run `file /path/to/FTL`. **VERIFIED**: FTL macOS binary is Mach-O x86_64. Runs under Rosetta 2 on Apple Silicon.
- Rosetta 2 implications for DYLD injection: the injected dylib must also be x86_64. Build with `arch -x86_64` or set target in Xcode.

### 4. Trivial DYLD injection test
Write a minimal C dylib:
```c
#include <stdio.h>
__attribute__((constructor))
static void on_load(void) {
    fprintf(stderr, "[INJECT] dylib loaded into FTL\n");
}
```
Compile: `arch -x86_64 cc -shared -o test_inject.dylib test_inject.c`
Launch: `DYLD_INSERT_LIBRARIES=./test_inject.dylib /path/to/FTL`

If `[INJECT] dylib loaded into FTL` appears in stderr, DYLD injection works. If not (silent failure or crash), check SIP status (`csrutil status`) and code signing results from step 1.
- **NEEDS_INVESTIGATION**: This is the single most important gate. If this fails, Approach A is dead.

### 5. Ghidra import + auto-analysis
Import the FTL binary into Ghidra, run auto-analysis. This produces a navigable database of functions, strings, and cross-references.
- **VERIFIED**: Ghidra handles Mach-O x86_64 binaries well.
- Export the project for future sessions. The initial analysis takes ~10-30 min depending on binary size.

### 6. Augment string search in Ghidra
Search for ASCII strings like `SCRAP_COLLECTOR`, `EXPLOSIVE_REPLICATOR`, `LONG_RANGED_SCANNERS` in the Ghidra string table. Follow cross-references from these strings to the code that uses them — this should lead directly to the augment dispatch function.
- **LIKELY**: The strings are stored as constants in the binary's data segment (standard C++ pattern for string comparisons).
- Finding this function is the prerequisite for both patching approaches.

---

## Approach A: DYLD Interception

### Concept
Intercept FTL's file I/O via macOS `DYLD_INSERT_LIBRARIES` to serve modified data at runtime. Instead of patching `ftl.dat` on disk, a dylib intercepts `open()`/`fopen()`/`read()` calls and returns different XML content.

### What it could enable
- **Conditional events** — serve different event XML based on game state (NEEDS_INVESTIGATION)
- **Dynamic difficulty** — modify blueprint stats at load time based on profile data (NEEDS_INVESTIGATION)
- **Hot-reload modding** — change XML without restarting FTL (NEEDS_INVESTIGATION)
- **Event sector hooks** — intercept sector data loading to inject event references, potentially fixing the events freeze (LIKELY — if the freeze is caused by missing sector hooks, serving complete sector XML could fix it)

### What it probably can't fix
- **Augment dispatch** — the dispatch table is compiled C++ logic, not file I/O. Intercepting file reads doesn't change how the binary processes augment names after loading them. (LIKELY)
- **Crew spawn pools** — likely hardcoded logic similar to augments, not file-driven. (NEEDS_INVESTIGATION)

### Integration point
`FTLLauncher` in `core/launcher.py` already launches FTL via `subprocess.Popen`. Adding DYLD injection is a one-line change:
```python
env = os.environ.copy()
env["DYLD_INSERT_LIBRARIES"] = str(dylib_path)
subprocess.Popen([ftl_executable], env=env)
```
**VERIFIED**: `FTLLauncher` uses `subprocess.Popen` and can pass custom environment variables.

### Key risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Hardened runtime | Blocks DYLD injection entirely | Check with `codesign -dvv` (step 1) |
| SIP restrictions | Blocks DYLD on system-protected processes | FTL is not a system binary, so SIP shouldn't apply (LIKELY) |
| Rosetta 2 compat | x86_64 dylib injection under Rosetta may behave differently | Build dylib as x86_64, test empirically (NEEDS_INVESTIGATION) |
| Steam integrity checks | Steam may re-verify/re-download files | DYLD injection doesn't modify files on disk, so this should be fine (LIKELY) |
| FTL's file I/O patterns | FTL may use custom archive reading (not standard `fopen`) | Check with `otool -L` and Ghidra (NEEDS_INVESTIGATION) |

### Scope note
Claims about OpenGL overlays, SDL event interception, and custom rendering are plausible future directions but entirely speculative at this stage. They depend on basic file I/O interception working first. Don't invest there until the trivial DYLD test (step 4) passes and file interception is proven.

---

## Approach B: Static Binary Patching

### Concept
Modify the FTL executable on disk to change hardcoded behavior. Identified targets include the augment dispatch table, weapon slot limits, combat formulas, and crew spawn tables.

### What it could fix
- **Augment dispatch** — add new name→effect entries or redirect unknown names to a generic handler (LIKELY — depends on dispatch table structure found in step 6)
- **Weapon slot limits** — change hardcoded constants (e.g., max 4 weapon slots → 6) (NEEDS_INVESTIGATION)
- **Combat formulas** — modify damage calculations, evasion caps, etc. (NEEDS_INVESTIGATION)
- **Crew spawn tables** — add custom races to enemy crew pools (NEEDS_INVESTIGATION)

### Agent-assisted reverse engineering workflow
The key insight: an LLM can analyze decompiled pseudocode much faster than a human can read raw assembly. The workflow:

1. **Human**: Load FTL binary into Ghidra, run auto-analysis
2. **Human**: Search for known strings (augment names), follow cross-references to functions
3. **Human**: Export decompiled pseudocode for the target function(s)
4. **LLM**: Analyze the pseudocode — identify dispatch table structure, function boundaries, constants, and safe patch points
5. **Human**: Verify LLM's analysis against actual binary behavior
6. **LLM**: Generate patch bytes (offset + old bytes + new bytes) for the desired modification
7. **Human**: Apply patch, test in-game

The LLM doesn't run Ghidra — the human exports relevant functions and the LLM analyzes them. This is a collaboration, not automation.

### Cross-reference with Hyperspace
**Hyperspace** (the FTL modding framework for Windows/Linux) already maps function addresses and patches the binary. Since FTL is compiled from the same C++ source across platforms, the logic is identical — only the addresses differ.

- Hyperspace's source code documents which functions to target and what they do
- This serves as a **roadmap**: we know *what* to patch, we just need to find *where* in the macOS binary
- **NEEDS_INVESTIGATION**: How much of Hyperspace's function mapping is publicly documented vs. requires source access

### Patch types
| Type | Description | Example |
|------|-------------|---------|
| Constant replacement | Change a hardcoded numeric value | Weapon slot limit 4→6 |
| Instruction replacement | Replace a comparison or jump | Remove augment count cap |
| NOP sled | Disable a check by replacing with no-ops | Skip integrity check |
| Code cave | Inject new logic into unused binary space | New augment dispatch entry |

### Distribution model
Patches would be distributed as JSON specs, not modified binaries:
```json
{
  "version": "1.6.14-macos",
  "patches": [
    {
      "description": "Add CUSTOM_AUG to dispatch table",
      "offset": "0x????",
      "old_bytes": "...",
      "new_bytes": "..."
    }
  ]
}
```
Users apply patches to their own FTL copy. `old_bytes` enables verification before patching (won't apply if binary doesn't match).

### Key risks
| Risk | Impact | Mitigation |
|------|--------|------------|
| Code signing invalidation | macOS refuses to run modified binary | `codesign --remove-signature` then `codesign -s - FTL` (ad-hoc re-sign). NEEDS_INVESTIGATION |
| Steam re-download | Steam detects modified binary and re-downloads | Disable auto-updates, work on a copy. Steam doesn't verify on every launch (LIKELY) |
| Version-specific patches | Patches break on FTL updates | Pin to specific version, include version check in patch spec |
| ASLR/PIE | Binary loaded at random base address | Patches target file offsets (fixed), not runtime addresses. Ghidra normalizes this |
| Limited code cave space | Not enough room for new logic | Use jump-to-allocated-memory trampolines (standard technique) |

---

## Mapping Approaches to ftl-gen Limitations

| Limitation | DYLD Interception | Static Patching | XML-Only Workaround |
|---|---|---|---|
| Augments cosmetic | Unlikely (logic, not I/O) | Yes (dispatch table) | Reskin vanilla augments |
| Events don't trigger | Likely (intercept sector data) | Possible (patch sector loading) | Manual sector hooks (needs freeze fix) |
| Crew won't spawn | Maybe (intercept spawn tables) | Yes (modify spawn logic) | Hiring events (needs events working) |
| Ships need layouts | No (data problem, not binary) | No (data problem, not binary) | Generate layout files |
| Weapon slot limits | No (binary constant) | Yes (constant replacement) | N/A |

---

## Ordered Research Steps

A sequential plan. Each step gates the next — don't skip ahead.

| Step | Task | Time Est. | Gates |
|------|------|-----------|-------|
| 1 | Binary reconnaissance: `codesign`, `otool`, `file` | 30 min | Everything |
| 2 | DYLD injection feasibility: trivial dylib test | 1 hour | Approach A |
| 3 | Ghidra import + auto-analysis | 1 hour | Steps 4-5 |
| 4 | Augment string search: find dispatch function | 30 min | Targeted patching |
| 5 | Hyperspace cross-reference: correlate known function mappings | 2 hours | Efficient patching |
| 6 | Code signing removal test: strip + ad-hoc re-sign + test launch | 30 min | Approach B |
| 7 | **Decision point** | — | Choose approach(es) |

### Decision point criteria
After steps 1-6, we'll know:
- Whether DYLD injection works on this binary (go/no-go for Approach A)
- Whether we can re-sign the binary and have it still run (go/no-go for Approach B)
- What the augment dispatch function looks like (complexity estimate for patching)
- How much Hyperspace documentation we can leverage (effort multiplier)

The answer might be "both" — DYLD for event injection, static patching for augments. Or it might be "neither works on macOS, use Hyperspace on Windows via Wine." The research steps are designed to get to that answer cheaply.

---

## What this document is NOT

- Not a product roadmap — no feature tiers, no timelines, no cost estimates
- Not a definitive architecture — every claim tagged with confidence level
- Not implementation-ready — no hex offsets, no assembly, no C code templates
- Not a substitute for Hyperspace — if Windows/Wine is acceptable, Hyperspace is the proven path

This is a research plan. The goal is to determine what's feasible on macOS with the minimum investment of time before committing to an approach.
