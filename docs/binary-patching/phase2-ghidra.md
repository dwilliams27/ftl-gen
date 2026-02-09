# Phase 2: Agentic Ghidra Analysis

**Goal**: Use Ghidra + AI to find the augment dispatch mechanism and determine patch strategy.

## Ghidra Installation

```bash
brew install --cask ghidra
# Or download from https://ghidra-sre.org/
# Requires JDK 17+ (brew install openjdk@17)
```

Set `GHIDRA_HOME` env var (add to `.env`):
```
GHIDRA_HOME=/Applications/ghidra  # or wherever installed
```

## Approach: Codex API + Ghidra Headless Scripts (Agentic Loop)

Fully automated pipeline: Ghidra headless exports -> Codex API analysis -> iterate.

## New files
- `src/ftl_gen/binary/ghidra/__init__.py`
- `src/ftl_gen/binary/ghidra/headless.py` — `GhidraHeadless` class wrapping `analyzeHeadless` CLI
- `src/ftl_gen/binary/ghidra/scripts/find_strings.py` — Jython: find augment name strings + xrefs -> JSON
- `src/ftl_gen/binary/ghidra/scripts/decompile_function.py` — Jython: decompile function at address -> pseudocode
- `src/ftl_gen/binary/ghidra/scripts/get_xrefs.py` — Jython: given address, get all code xrefs -> JSON
- `src/ftl_gen/binary/ghidra/scripts/get_bytes.py` — Jython: dump N bytes at address -> hex
- `src/ftl_gen/binary/ghidra/agent.py` — agentic orchestration loop using Codex API

## `GhidraHeadless` class (`headless.py`)

Wraps Ghidra's `analyzeHeadless` CLI for non-interactive analysis:

```python
class GhidraHeadless:
    def __init__(self, ghidra_home: Path, project_dir: Path):
        self.analyze_headless = ghidra_home / "support" / "analyzeHeadless"
        self.project_dir = project_dir
        self.project_name = "FTL_Analysis"

    def import_binary(self, binary_path: Path) -> None:
        """Import binary and run auto-analysis (one-time, ~2-5 min)."""
        # analyzeHeadless <project_dir> <project_name> -import <binary_path>

    def run_script(self, script_path: Path, args: list[str] = []) -> str:
        """Run a Jython script against the analyzed binary. Returns stdout."""
        # analyzeHeadless <project_dir> <project_name> -process FTL
        #   -postScript <script_path> <args...> -noanalysis

    def find_strings(self, patterns: list[str]) -> list[dict]:
        """Find strings matching patterns, return addresses + xrefs."""

    def decompile_at(self, address: int) -> str:
        """Decompile the function containing the given address."""

    def get_xrefs_to(self, address: int) -> list[dict]:
        """Get all code cross-references to an address."""

    def get_bytes(self, address: int, length: int) -> bytes:
        """Read raw bytes from the binary at the given address."""
```

## Jython Scripts (run inside Ghidra JVM)

Each script reads args from `getScriptArgs()`, does one focused operation, prints JSON to stdout.

**`find_strings.py`**: Search defined strings for augment names, for each found string output:
```json
{"value": "SCRAP_COLLECTOR", "address": "0x1a3f40", "xrefs": ["0x8b420", "0xc1a30"]}
```

**`decompile_function.py`**: Given hex address arg, find containing function, decompile with Ghidra's decompiler:
```json
{"function": "FUN_0008b400", "address": "0x8b400", "pseudocode": "bool HasAug(string *name) {...}"}
```

**`get_xrefs.py`**: Given hex address, list all references to it with calling function names.

**`get_bytes.py`**: Given hex address + length, dump raw bytes as hex string.

## Agentic Orchestration (`agent.py`)

The core of Phase 2 — an autonomous analysis loop powered by Codex:

```python
class GhidraAgent:
    def __init__(self, ghidra: GhidraHeadless, model: str = "gpt-5.2-codex"):
        self.ghidra = ghidra
        self.client = openai.OpenAI()  # Already a project dependency
        self.model = model
        self.findings: list[dict] = []
        self.messages: list[dict] = []  # Conversation history

    def analyze_augment_dispatch(self) -> DispatchAnalysis:
        """Main entry point. Runs the full agentic analysis loop."""
        # Step 1: Find all augment strings
        strings = self.ghidra.find_strings(VANILLA_AUGMENT_NAMES)
        self.findings.append({"step": "strings", "data": strings})

        # Step 2: Seed the conversation with findings
        self._add_system_prompt()
        self._add_findings("augment_strings", strings)

        # Step 3: Agentic loop — ask Codex what to analyze next
        for iteration in range(MAX_ITERATIONS):
            response = self._ask_codex()
            action = self._parse_action(response)

            if action.type == "decompile":
                result = self.ghidra.decompile_at(action.address)
                self._add_findings("decompile", result)
            elif action.type == "xrefs":
                result = self.ghidra.get_xrefs_to(action.address)
                self._add_findings("xrefs", result)
            elif action.type == "get_bytes":
                result = self.ghidra.get_bytes(action.address, action.length)
                self._add_findings("bytes", result)
            elif action.type == "conclude":
                return self._parse_conclusion(response)

        raise AnalysisTimeout("Max iterations reached")
```

## Codex Tool Definitions (Function Calling API)

Instead of asking the model to emit JSON in text, define Ghidra actions as **OpenAI tools**. This gives typed schemas, reliable structured output, and multi-tool call support.

```python
GHIDRA_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "decompile_function",
            "description": "Decompile the function containing the given address. Returns C pseudocode.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Hex address (e.g. '0x8b420')"},
                    "reason": {"type": "string", "description": "Why you want to decompile this"},
                },
                "required": ["address", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_xrefs_to",
            "description": "Get all code cross-references TO a given address (who calls/references this).",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Hex address to find references to"},
                    "reason": {"type": "string", "description": "Why you want these xrefs"},
                },
                "required": ["address", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_xrefs_from",
            "description": "Get all code cross-references FROM a function (what does it call/reference).",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Hex address of function to analyze"},
                    "reason": {"type": "string", "description": "Why you want outgoing xrefs"},
                },
                "required": ["address", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_bytes",
            "description": "Read raw bytes from the binary at a given address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Hex address"},
                    "length": {"type": "integer", "description": "Number of bytes to read"},
                    "reason": {"type": "string", "description": "Why you need these bytes"},
                },
                "required": ["address", "length", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_strings",
            "description": "Search for strings in the binary matching a pattern.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "String or regex pattern to search for"},
                    "reason": {"type": "string", "description": "Why you're searching for this"},
                },
                "required": ["pattern", "reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "conclude_analysis",
            "description": "Call when you have enough information to describe the dispatch mechanism.",
            "parameters": {
                "type": "object",
                "properties": {
                    "dispatch_pattern": {
                        "type": "string",
                        "enum": ["scattered_checks", "central_dispatch", "hybrid", "other"],
                    },
                    "has_augmentation_addr": {"type": "string"},
                    "get_augmentation_value_addr": {"type": "string"},
                    "string_comparison_method": {"type": "string"},
                    "calling_convention": {"type": "string"},
                    "function_prologue_bytes": {"type": "string"},
                    "recommended_patch_strategy": {"type": "string"},
                    "key_functions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name": {"type": "string"},
                                "address": {"type": "string"},
                                "role": {"type": "string"},
                                "pseudocode_summary": {"type": "string"},
                            },
                        },
                    },
                },
                "required": [
                    "dispatch_pattern", "has_augmentation_addr",
                    "recommended_patch_strategy", "key_functions",
                ],
            },
        },
    },
]
```

## Agent Loop (standard OpenAI tool_calls flow)

```python
def _run_loop(self) -> DispatchAnalysis:
    while self.iteration < MAX_ITERATIONS:
        response = self.client.chat.completions.create(
            model=self.model,
            messages=self.messages,
            tools=GHIDRA_TOOLS,
        )
        msg = response.choices[0].message
        self.messages.append(msg)

        if not msg.tool_calls:
            # Model responded with text (thinking out loud) — continue
            continue

        for tool_call in msg.tool_calls:
            result = self._execute_tool(tool_call.function.name, tool_call.function.arguments)
            self.messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": json.dumps(result),
            })
            if tool_call.function.name == "conclude_analysis":
                return self._parse_conclusion(tool_call.function.arguments)

        self.iteration += 1
```

## System Prompt

```
You are a reverse engineer analyzing the FTL: Faster Than Light game binary (macOS, x86_64).

Your goal: Find how the game maps augment name strings (like "SCRAP_COLLECTOR") to gameplay effects.

Context from Hyperspace (an existing Windows FTL modding framework):
- HasAugmentation(std::string) — checks if ship has a named augment
- GetAugmentationValue(std::string) — returns the float value
- These are C++ methods, likely on a ShipObject class
- The checks may be scattered (each game system checks specific names)
  or centralized (one function maps name -> effect ID)

You have been provided with initial string search results. Use the tools to explore
the binary — decompile functions, follow cross-references, read bytes — until you
understand the dispatch mechanism well enough to call conclude_analysis.

Focus on finding: (1) the function entry points, (2) how string arguments are passed,
(3) the first 8+ bytes of the function prologue (needed for trampoline patching).
```

## Validator Agent: Verifying Analyzer Findings

The analyzer (Codex) produces findings. A separate **validator agent** runs concrete checks to confirm or reject each finding before we build patches on top of them.

### New file: `src/ftl_gen/binary/ghidra/validator.py`

```python
@dataclass
class ValidationResult:
    finding: str           # What was claimed
    check_type: str        # "byte_match", "disasm_verify", "xref_verify", "behavioral_probe"
    passed: bool
    evidence: str          # What we actually found
    confidence: float      # 0.0-1.0

class FindingValidator:
    def __init__(self, binary_path: Path):
        self.binary_data = binary_path.read_bytes()
        # capstone disassembler for x86_64
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

    def validate_string_at(self, address: int, expected: str) -> ValidationResult:
        """Read bytes at file offset, verify they match the expected string."""

    def validate_function_prologue(self, address: int) -> ValidationResult:
        """Disassemble bytes at address, check for valid function prologue pattern."""

    def validate_xref(self, caller_addr: int, target_addr: int) -> ValidationResult:
        """Disassemble caller function, verify it contains a CALL/JMP to target."""
```

### Behavioral Probes (strongest signal)

The gold standard — apply a minimal test patch, run FTL, observe behavior.

```python
class BehavioralProbe:
    """Apply minimal test patches to verify function identification."""

    def probe_has_augmentation(self, function_addr: int) -> ValidationResult:
        """NOP out HasAugmentation -> if augments stop working, we found the right function."""
        # 1. Save original bytes at function_addr (first 5 bytes)
        # 2. Write RET (0xC3) at function_addr (function returns immediately -> always false)
        # 3. Launch FTL with a test mod that has SCRAP_COLLECTOR augment
        # 4. If scrap bonus disappears -> CONFIRMED: this is HasAugmentation
        # 5. Restore original bytes

    def probe_get_augmentation_value(self, function_addr: int) -> ValidationResult:
        """Patch GetAugmentationValue to always return 0.0 -> augment values become zero."""
```

### Two-agent pipeline

```
+-------------------+     findings      +--------------------+
|  Analyzer Agent   | ---------------> |  Validator Agent    |
|  (Codex + tools)  |                  |  (byte checks +    |
|  Explores binary  | <--------------- |   disasm + probes)  |
|  via Ghidra       |  pass/fail       |                     |
+-------------------+                  +--------------------+
```

1. **Analyzer** (Codex) explores via Ghidra tools, produces findings with addresses
2. **Validator** runs concrete checks on each finding (no LLM — pure deterministic code)
3. Failed validations feed back to the Analyzer as corrections
4. Behavioral probes run only for final high-confidence findings (expensive — requires game launch)

## Key Insight from Hyperspace Cross-reference

Hyperspace hooks `HasAugmentation` / `GetAugmentationValue` at the method level. The FTL binary likely does NOT have a single dispatch table — instead, there are **scattered call sites** throughout game logic that each call `HasAugmentation("SPECIFIC_NAME")`. The dispatch is implicit in the caller, not a central switch.

This means the **best patch strategy is a trampoline on `HasAugmentation`** itself — intercept at one function entry point and remap custom names to vanilla names before the original comparison logic runs.

## CLI command: `ftl-gen ghidra-analyze`
- Runs the full agentic analysis pipeline
- Requires `GHIDRA_HOME` and FTL binary
- Outputs `DispatchAnalysis` as JSON to `src/ftl_gen/binary/specs/dispatch_analysis.json`
- Progress logged via Rich console

## Config addition
```python
# In config.py Settings
ghidra_home: Path | None = Field(default=None, alias="GHIDRA_HOME")
```
