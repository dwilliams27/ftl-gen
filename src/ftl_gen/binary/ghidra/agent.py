"""Agentic Ghidra analysis using OpenAI function calling.

Orchestrates an LLM-driven reverse engineering loop:
1. Seed with initial data from Ghidra (strings, functions, etc.)
2. LLM decides what to explore next (decompile, follow xrefs, read bytes)
3. Execute via Ghidra headless scripts
4. Feed results back to LLM
5. Repeat until LLM calls conclude_analysis

The agent is parameterized by an AnalysisGoal, which defines the system prompt,
seed data, and conclusion schema. Preset goals are provided for common tasks
(augment dispatch, event dispatch, etc.), but custom goals can be created.

The validator independently checks findings using capstone disassembly.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import openai

logger = logging.getLogger(__name__)

MAX_ITERATIONS = 25


# --- Analysis goal definition ---


@dataclass
class AnalysisGoal:
    """Defines what the agent should analyze and how to conclude.

    Attributes:
        name: Short identifier (e.g. "augment_dispatch").
        system_prompt: Full system prompt for the LLM.
        seed_fn: Callable(ghidra) -> (seed_data, seed_message). Runs Ghidra
            commands to gather initial data, returns (raw_data_for_findings,
            user_message_string) to seed the conversation.
        conclusion_schema: JSON Schema properties dict for the conclude_analysis
            tool. These fields are what the LLM fills in when it's done.
        conclusion_required: List of required field names in the conclusion.
    """

    name: str
    system_prompt: str
    seed_fn: Callable[[Any], tuple[Any, str]]
    conclusion_schema: dict[str, Any]
    conclusion_required: list[str] = field(default_factory=lambda: ["key_functions"])


# --- Result types ---


@dataclass
class KeyFunction:
    """A key function identified during analysis."""

    name: str
    address: str
    role: str
    pseudocode_summary: str = ""


@dataclass
class AnalysisResult:
    """Generic result from an agentic Ghidra analysis run."""

    goal_name: str
    conclusion: dict[str, Any]  # Raw fields from conclude_analysis
    key_functions: list[KeyFunction] = field(default_factory=list)
    iterations_used: int = 0
    raw_findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Serialize to dict for JSON output."""
        return {
            "goal_name": self.goal_name,
            "conclusion": self.conclusion,
            "key_functions": [
                {
                    "name": f.name,
                    "address": f.address,
                    "role": f.role,
                    "pseudocode_summary": f.pseudocode_summary,
                }
                for f in self.key_functions
            ],
            "iterations_used": self.iterations_used,
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get a conclusion field by name."""
        return self.conclusion.get(key, default)

    def save(self, path: Path) -> None:
        """Save analysis results to JSON file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2))
        logger.info("Analysis saved to %s", path)

    @classmethod
    def load(cls, path: Path) -> AnalysisResult:
        """Load analysis results from JSON file."""
        data = json.loads(path.read_text())
        return cls(
            goal_name=data.get("goal_name", "unknown"),
            conclusion=data.get("conclusion", {}),
            key_functions=[
                KeyFunction(**f) for f in data.get("key_functions", [])
            ],
            iterations_used=data.get("iterations_used", 0),
        )


# --- Transcript logging ---


@dataclass
class TranscriptEntry:
    """One step in the agent's transcript."""

    iteration: int
    timestamp: float  # time.time()
    entry_type: str  # "llm_call", "tool_exec", "seed", "conclude"
    data: dict[str, Any]
    duration_s: float = 0.0


@dataclass
class Transcript:
    """Full transcript of an agent run for post-hoc review."""

    goal_name: str
    model: str
    max_iterations: int
    start_time: float = 0.0
    end_time: float = 0.0
    entries: list[TranscriptEntry] = field(default_factory=list)
    messages_snapshot: list[dict] = field(default_factory=list)

    @property
    def total_duration_s(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    def add(
        self,
        iteration: int,
        entry_type: str,
        data: dict[str, Any],
        duration_s: float = 0.0,
    ) -> None:
        self.entries.append(TranscriptEntry(
            iteration=iteration,
            timestamp=time.time(),
            entry_type=entry_type,
            data=data,
            duration_s=duration_s,
        ))

    def save(self, path: Path) -> None:
        """Save transcript to JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        out = {
            "goal_name": self.goal_name,
            "model": self.model,
            "max_iterations": self.max_iterations,
            "total_duration_s": round(self.total_duration_s, 2),
            "num_iterations": len([
                e for e in self.entries if e.entry_type == "llm_call"
            ]),
            "num_tool_calls": len([
                e for e in self.entries if e.entry_type == "tool_exec"
            ]),
            "entries": [
                {
                    "iteration": e.iteration,
                    "time": round(e.timestamp - self.start_time, 2) if self.start_time else 0,
                    "type": e.entry_type,
                    "duration_s": round(e.duration_s, 2),
                    "data": e.data,
                }
                for e in self.entries
            ],
            "final_messages": self.messages_snapshot,
        }
        path.write_text(json.dumps(out, indent=2, default=str))
        logger.info("Transcript saved to %s (%d entries)", path, len(self.entries))


# --- Preset goals ---


def _augment_dispatch_seed(ghidra: Any) -> tuple[Any, str]:
    """Seed function for augment dispatch analysis."""
    # First try to find functions directly — much more useful than strings
    functions = ghidra.list_functions("Augment", 20)
    functions += ghidra.list_functions("HasAug", 10)

    if functions:
        # Deduplicate by address
        seen = set()
        unique = []
        for f in functions:
            if f["address"] not in seen:
                seen.add(f["address"])
                unique.append(f)
        functions = unique

        message = (
            "Here are augment-related functions found in the FTL binary:\n\n"
            + json.dumps(functions, indent=2)
            + "\n\nThese are actual CODE entry points. Start by decompiling "
            "the most relevant ones — look for HasAugmentation, GetAugmentationValue, "
            "or any ShipManager methods that deal with augments."
        )
    else:
        # Fallback to string search
        from ftl_gen.binary.recon import VANILLA_AUGMENT_NAMES
        strings = ghidra.find_strings(VANILLA_AUGMENT_NAMES)
        functions = strings
        message = (
            "No augment functions found directly. Here are augment name strings:\n\n"
            + json.dumps(strings, indent=2)
            + "\n\nUse list_functions with patterns like 'Augment', 'HasAug', "
            "'ShipManager' to find actual code addresses."
        )
    return functions, message


AUGMENT_DISPATCH_GOAL = AnalysisGoal(
    name="augment_dispatch",
    system_prompt="""\
You are a reverse engineer analyzing the FTL: Faster Than Light game binary (macOS, x86_64).

Your goal: Find how the game maps augment name strings (like "SCRAP_COLLECTOR") to gameplay effects.

Context from Hyperspace (an existing Windows FTL modding framework):
- HasAugmentation(std::string) — checks if ship has a named augment, returns bool
- GetAugmentationValue(std::string) — returns the float value for a named augment
- These are C++ methods, likely on a ShipManager or ShipObject class
- The checks are likely SCATTERED: each game system calls HasAugmentation("SPECIFIC_NAME")
  for the augments it cares about. There is probably no single dispatch table.

IMPORTANT TIPS:
- Use list_functions to find CODE addresses (e.g. list_functions("HasAug"), list_functions("Augment")).
  This is much more reliable than following string xrefs which often lead to RTTI data.
- If decompile returns an error about "non-executable section", the address is data, not code.

Strategy:
1. Use list_functions to find augment-related functions (HasAugmentation, GetAugmentationValue, ShipManager)
2. Decompile them and understand how string arguments are compared
3. Verify by checking that multiple different augment strings flow through the same function
4. Get the function prologue bytes (first 16+ bytes) — needed for trampoline patching
5. Identify the calling convention (how the std::string argument is passed)

Call conclude_analysis when you are confident in your findings.\
""",
    seed_fn=_augment_dispatch_seed,
    conclusion_schema={
        "dispatch_pattern": {
            "type": "string",
            "enum": ["scattered_checks", "central_dispatch", "hybrid", "other"],
            "description": "How augment names are dispatched to effects",
        },
        "primary_function_addr": {
            "type": "string",
            "description": "Address of the main augment-checking function (e.g. HasAugmentation)",
        },
        "secondary_function_addr": {
            "type": "string",
            "description": "Address of secondary function if any (e.g. GetAugmentationValue)",
        },
        "string_comparison_method": {
            "type": "string",
            "description": "How strings are compared (e.g. std::string::operator==, strcmp)",
        },
        "calling_convention": {
            "type": "string",
            "description": "How string args are passed to these functions",
        },
        "function_prologue_bytes": {
            "type": "string",
            "description": "Hex bytes at the function entry point (first 16+ bytes)",
        },
        "recommended_patch_strategy": {
            "type": "string",
            "description": "Recommended approach for patching (e.g. trampoline, detour, vtable)",
        },
        "key_functions": {
            "type": "array",
            "description": "Key functions found during analysis",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "address": {"type": "string"},
                    "role": {"type": "string"},
                    "pseudocode_summary": {"type": "string"},
                },
                "required": ["name", "address", "role"],
            },
        },
    },
    conclusion_required=["dispatch_pattern", "recommended_patch_strategy", "key_functions"],
)


def _event_dispatch_seed(ghidra: Any) -> tuple[Any, str]:
    """Seed function for event dispatch analysis."""
    event_strings = [
        "START_BEACON", "FINISH_BEACON", "NEBULA", "PIRATE",
        "REBEL", "STORE", "QUEST", "BOSS", "FLEET",
        "eventFile", "loadEvent", "EventManager",
    ]
    strings = ghidra.find_strings(event_strings)
    message = (
        "Here are event-related strings found in the FTL binary:\n\n"
        + json.dumps(strings, indent=2)
        + "\n\nPlease analyze how FTL loads and dispatches events from XML. "
        "Find the EventManager class and how event names map to event logic."
    )
    return strings, message


EVENT_DISPATCH_GOAL = AnalysisGoal(
    name="event_dispatch",
    system_prompt="""\
You are a reverse engineer analyzing the FTL: Faster Than Light game binary (macOS, x86_64).

Your goal: Find how the game loads and dispatches events from XML data.

Context:
- FTL events are defined in XML files (events.xml) with named event blocks
- Events are loaded by name (e.g. <event load="PIRATE_ATTACK"/>)
- Custom events added via .xml.append cause a freeze at "Blueprints Loaded!"
- We need to understand WHY custom events freeze and how to fix it

Things to look for:
- EventManager or similar class that loads/stores events
- How event names are resolved to event data at runtime
- Whether events need to be registered in a sector list or pool
- The loading sequence during startup (what happens at "Blueprints Loaded!")

Use the tools to explore. Call conclude_analysis when you understand the event system.\
""",
    seed_fn=_event_dispatch_seed,
    conclusion_schema={
        "event_loading_mechanism": {
            "type": "string",
            "description": "How events are loaded from XML (e.g. parsed at startup, lazy loaded)",
        },
        "event_manager_addr": {
            "type": "string",
            "description": "Address of EventManager or equivalent class/function",
        },
        "event_registration_required": {
            "type": "boolean",
            "description": "Whether events must be registered in a pool/list to work",
        },
        "freeze_cause_hypothesis": {
            "type": "string",
            "description": "Best hypothesis for why custom events cause a freeze at load",
        },
        "recommended_fix": {
            "type": "string",
            "description": "Recommended approach to make custom events work",
        },
        "key_functions": {
            "type": "array",
            "description": "Key functions found during analysis",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "address": {"type": "string"},
                    "role": {"type": "string"},
                    "pseudocode_summary": {"type": "string"},
                },
                "required": ["name", "address", "role"],
            },
        },
    },
    conclusion_required=["freeze_cause_hypothesis", "recommended_fix", "key_functions"],
)


def _get_event_seed(ghidra: Any) -> tuple[Any, str]:
    """Seed function for GetEvent smoke test."""
    # Use list_functions to find actual code addresses (not just strings)
    functions = ghidra.list_functions("GetEvent", 20)
    if functions:
        message = (
            "Here are functions matching 'GetEvent' found in the FTL binary:\n\n"
            + json.dumps(functions, indent=2)
            + "\n\nThese are actual CODE entry points (from Ghidra's function manager). "
            "Start by decompiling the most interesting ones — especially any on "
            "EventGenerator or BossShip. The addresses are decompilable directly."
        )
    else:
        # Fallback to string search
        strings = ghidra.find_strings(["GetEvent", "BossShip", "SaveBoss", "LoadBoss"])
        functions = strings  # Use strings as seed data
        message = (
            "No functions matching 'GetEvent' found directly. "
            "Here are related string matches:\n\n"
            + json.dumps(strings, indent=2)
            + "\n\nUse list_functions with broader patterns (e.g. 'Event', 'Boss') "
            "to find actual function code addresses."
        )
    return functions, message


GET_EVENT_GOAL = AnalysisGoal(
    name="get_event",
    system_prompt="""\
You are a reverse engineer analyzing the FTL: Faster Than Light game binary (macOS, x86_64).

Your goal: Find and characterize the GetEvent function and related event-handling code.

IMPORTANT TIPS:
- Use list_functions to find CODE addresses. String xrefs often point to RTTI data, not code.
- The seed data already contains function matches from list_functions — decompile those directly.
- If decompile returns an error about "non-executable section", the address is data, not code.
  Use list_functions with a different pattern to find the actual code.

Strategy:
1. Start from the seed function list — decompile the most relevant functions directly
2. Focus on EventGenerator::GetEvent if present (it takes a string event name + params)
3. Also look at BossShip::GetEvent, TutorialManager::GetEvent for comparison
4. Follow xrefs UP (get_xrefs_to) to find callers
5. Get prologue bytes (get_bytes) for key functions

Call conclude_analysis when you can describe:
- What GetEvent does (its signature, return type, purpose)
- Who calls it and in what context
- The function addresses and prologue bytes\
""",
    seed_fn=_get_event_seed,
    conclusion_schema={
        "get_event_addr": {
            "type": "string",
            "description": "Address of the GetEvent function",
        },
        "get_event_signature": {
            "type": "string",
            "description": "Inferred function signature (return type, params)",
        },
        "get_event_purpose": {
            "type": "string",
            "description": "What does GetEvent do? (1-2 sentences)",
        },
        "callers": {
            "type": "array",
            "description": "Functions that call GetEvent",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "address": {"type": "string"},
                    "context": {"type": "string", "description": "Why/when this caller invokes GetEvent"},
                },
                "required": ["name", "address"],
            },
        },
        "function_prologue_bytes": {
            "type": "string",
            "description": "Hex bytes at GetEvent entry point (first 16+ bytes)",
        },
        "related_functions": {
            "type": "string",
            "description": "Other related functions discovered (BossShip, SaveBoss, etc.)",
        },
        "key_functions": {
            "type": "array",
            "description": "All key functions found during analysis",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "address": {"type": "string"},
                    "role": {"type": "string"},
                    "pseudocode_summary": {"type": "string"},
                },
                "required": ["name", "address", "role"],
            },
        },
    },
    conclusion_required=["get_event_addr", "get_event_purpose", "key_functions"],
)


def _general_exploration_seed(ghidra: Any) -> tuple[Any, str]:
    """Seed function for general binary exploration."""
    # List first few functions to give the agent something to start with
    script = ghidra.SCRIPTS_DIR / "list_functions.py"
    # This script may not exist — fall back to a prompt-only seed
    try:
        raw = ghidra.run_script(script)
        functions = [json.loads(line) for line in raw.splitlines() if line.strip()]
    except Exception:
        functions = []

    if functions:
        message = (
            "Here are the first functions found in the FTL binary:\n\n"
            + json.dumps(functions, indent=2)
            + "\n\nExplore the binary to complete the analysis goal."
        )
    else:
        message = (
            "The binary has been loaded. Use search_strings and decompile_function "
            "to explore. Start by searching for relevant string patterns."
        )
    return functions, message


def custom_goal(
    name: str,
    objective: str,
    context: str = "",
    strategy: str = "",
    conclusion_fields: dict[str, Any] | None = None,
    conclusion_required: list[str] | None = None,
    seed_strings: list[str] | None = None,
) -> AnalysisGoal:
    """Create a custom analysis goal.

    Args:
        name: Short identifier.
        objective: What the agent should find (1-2 sentences).
        context: Background knowledge to help the agent.
        strategy: Suggested exploration strategy.
        conclusion_fields: Custom JSON schema properties for conclude_analysis.
            If None, uses a generic schema with summary + key_functions.
        conclusion_required: Required fields in the conclusion.
        seed_strings: Strings to search for as initial seed data. If None,
            uses general exploration seed.
    """
    parts = [
        "You are a reverse engineer analyzing the FTL: Faster Than Light game binary (macOS, x86_64).",
        "",
        f"Your goal: {objective}",
    ]
    if context:
        parts += ["", "Context:", context]
    if strategy:
        parts += ["", "Strategy:", strategy]
    parts += ["", "Call conclude_analysis when you are confident in your findings."]

    system_prompt = "\n".join(parts)

    if conclusion_fields is None:
        conclusion_fields = {
            "summary": {
                "type": "string",
                "description": "Summary of findings",
            },
            "recommended_approach": {
                "type": "string",
                "description": "Recommended approach based on findings",
            },
            "key_functions": {
                "type": "array",
                "description": "Key functions found during analysis",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "address": {"type": "string"},
                        "role": {"type": "string"},
                        "pseudocode_summary": {"type": "string"},
                    },
                    "required": ["name", "address", "role"],
                },
            },
        }

    if seed_strings:
        def seed_fn(ghidra: Any) -> tuple[Any, str]:
            strings = ghidra.find_strings(seed_strings)
            if strings:
                msg = (
                    "Here are relevant strings found in the binary:\n\n"
                    + json.dumps(strings, indent=2)
                    + "\n\nExplore the binary to complete the analysis goal."
                )
            else:
                msg = (
                    "No matching strings found via direct search. Try searching "
                    "for related function names or decompiling known entry points."
                )
            return strings, msg
    else:
        seed_fn = _general_exploration_seed

    return AnalysisGoal(
        name=name,
        system_prompt=system_prompt,
        seed_fn=seed_fn,
        conclusion_schema=conclusion_fields,
        conclusion_required=conclusion_required or ["key_functions"],
    )


# --- Preset goal registry ---

PRESET_GOALS: dict[str, AnalysisGoal] = {
    "augment_dispatch": AUGMENT_DISPATCH_GOAL,
    "event_dispatch": EVENT_DISPATCH_GOAL,
    "get_event": GET_EVENT_GOAL,
}


# --- OpenAI tool definitions ---


def _build_exploration_tools() -> list[dict[str, Any]]:
    """Build the fixed Ghidra exploration tools (always available)."""
    return [
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
                "description": "Search for strings in the binary's data sections matching a pattern. "
                "NOTE: This finds STRING DATA (in __cstring), not code. Xrefs from strings often "
                "point to RTTI/typeinfo data, not executable code. To find actual function code "
                "addresses, use list_functions instead.",
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
                "name": "list_functions",
                "description": "Search Ghidra's function manager for functions matching a name pattern. "
                "Returns actual CODE entry-point addresses that can be decompiled. This is the "
                "best way to find function addresses — much more reliable than following string xrefs "
                "which often lead to RTTI data. Supports partial matches (case-insensitive).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string", "description": "Function name pattern to search (e.g. 'GetEvent', 'BossShip')"},
                        "max_results": {"type": "integer", "description": "Max results to return (default 20)"},
                        "reason": {"type": "string", "description": "Why you're searching for this function"},
                    },
                    "required": ["pattern", "reason"],
                },
            },
        },
    ]


def _build_conclude_tool(goal: AnalysisGoal) -> dict[str, Any]:
    """Build the conclude_analysis tool from a goal's conclusion schema."""
    return {
        "type": "function",
        "function": {
            "name": "conclude_analysis",
            "description": "Call when you have enough information to report your findings.",
            "parameters": {
                "type": "object",
                "properties": goal.conclusion_schema,
                "required": goal.conclusion_required,
            },
        },
    }


def build_tools(goal: AnalysisGoal) -> list[dict[str, Any]]:
    """Build the full tool list for a given goal."""
    return _build_exploration_tools() + [_build_conclude_tool(goal)]


# Keep a module-level reference for backwards compatibility with tests
GHIDRA_TOOLS = _build_exploration_tools() + [_build_conclude_tool(AUGMENT_DISPATCH_GOAL)]


# --- Agent ---


class AnalysisTimeout(Exception):
    """Raised when the agentic analysis exceeds max iterations."""


class GhidraAgent:
    """Agentic reverse engineering loop using OpenAI + Ghidra headless.

    Uses OpenAI's function calling API to let the LLM drive exploration
    of the FTL binary through Ghidra. The LLM decides what to decompile,
    what xrefs to follow, and what bytes to read.

    The agent is parameterized by an AnalysisGoal which defines the prompt,
    seed data, and conclusion schema.
    """

    def __init__(
        self,
        ghidra: Any,  # GhidraHeadless
        model: str = "gpt-5.2",
        max_iterations: int = MAX_ITERATIONS,
    ):
        self.ghidra = ghidra
        self.client = openai.OpenAI()  # reads OPENAI_API_KEY from env
        self.model = model
        self.max_iterations = max_iterations
        self.messages: list[dict] = []
        self.findings: list[dict] = []
        self.iteration = 0
        self.transcript: Transcript | None = None

    def run(
        self,
        goal: AnalysisGoal,
        progress_callback: Any | None = None,
    ) -> AnalysisResult:
        """Run the agentic analysis for a given goal.

        Args:
            goal: Defines what to analyze and how to conclude.
            progress_callback: Optional callable(iteration, max_iterations, message).

        Returns:
            AnalysisResult with the findings.
        """
        self.iteration = 0
        self.findings = []
        self.transcript = Transcript(
            goal_name=goal.name,
            model=self.model,
            max_iterations=self.max_iterations,
        )
        self.transcript.start_time = time.time()

        # Step 1: Seed with initial data
        if progress_callback:
            progress_callback(0, self.max_iterations, f"Seeding: {goal.name}...")

        t0 = time.time()
        seed_data, seed_message = goal.seed_fn(self.ghidra)
        seed_dur = time.time() - t0
        self.findings.append({"step": "seed", "data": seed_data})
        self.transcript.add(0, "seed", {
            "seed_strings_found": len(seed_data) if isinstance(seed_data, list) else 0,
            "seed_message_len": len(seed_message),
        }, duration_s=seed_dur)

        # Step 2: Build conversation
        self.messages = [
            {"role": "system", "content": goal.system_prompt},
            {"role": "user", "content": seed_message},
        ]

        # Step 3: Build tools with goal-specific conclusion schema
        tools = build_tools(goal)

        # Step 4: Agentic loop
        try:
            result = self._run_loop(goal, tools, progress_callback)
        except AnalysisTimeout:
            self.transcript.end_time = time.time()
            self.transcript.messages_snapshot = self.messages
            raise

        self.transcript.end_time = time.time()
        self.transcript.messages_snapshot = self.messages
        return result

    # Backwards-compatible convenience method
    def analyze_augment_dispatch(
        self,
        progress_callback: Any | None = None,
    ) -> AnalysisResult:
        """Run augment dispatch analysis. Convenience wrapper around run()."""
        return self.run(AUGMENT_DISPATCH_GOAL, progress_callback)

    def save_transcript(self, path: Path) -> None:
        """Save the transcript from the last run."""
        if self.transcript:
            self.transcript.save(path)
        else:
            logger.warning("No transcript to save (run the agent first)")

    def _run_loop(
        self,
        goal: AnalysisGoal,
        tools: list[dict[str, Any]],
        progress_callback: Any | None = None,
    ) -> AnalysisResult:
        """Run the tool-calling loop until conclude_analysis or timeout."""
        while self.iteration < self.max_iterations:
            self.iteration += 1

            if progress_callback:
                progress_callback(
                    self.iteration,
                    self.max_iterations,
                    f"Analysis iteration {self.iteration}/{self.max_iterations}",
                )

            logger.info("Analysis iteration %d/%d", self.iteration, self.max_iterations)

            # Convergence pressure: nudge before the LLM call when close to limit
            remaining = self.max_iterations - self.iteration
            if remaining <= 1:
                self.messages.append({
                    "role": "user",
                    "content": (
                        f"WARNING: This is your LAST iteration. "
                        "You MUST call conclude_analysis NOW "
                        "with your best findings so far. Do not request more data — "
                        "summarize what you've learned and conclude."
                    ),
                })
            elif remaining <= 2:
                self.messages.append({
                    "role": "user",
                    "content": (
                        f"Note: Only {remaining} iterations remaining. "
                        "Please wrap up your analysis and call conclude_analysis soon."
                    ),
                })

            t0 = time.time()
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                tools=tools,
                temperature=0.1,
            )
            llm_dur = time.time() - t0

            msg = response.choices[0].message

            # Log the LLM call
            llm_log: dict[str, Any] = {
                "model": self.model,
                "has_content": bool(msg.content),
                "content_preview": (msg.content or "")[:500],
                "num_tool_calls": len(msg.tool_calls) if msg.tool_calls else 0,
                "tool_calls": [],
            }
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    tc_args = json.loads(tc.function.arguments)
                    llm_log["tool_calls"].append({
                        "id": tc.id,
                        "name": tc.function.name,
                        "args": tc_args,
                    })
            self.transcript.add(self.iteration, "llm_call", llm_log, duration_s=llm_dur)

            # Append assistant message (must serialize tool_calls properly)
            self.messages.append(_serialize_assistant_message(msg))

            if not msg.tool_calls:
                # Model is thinking out loud — continue the loop
                logger.info("Model thinking: %s", (msg.content or "")[:200])
                continue

            for tool_call in msg.tool_calls:
                fn_name = tool_call.function.name
                fn_args = json.loads(tool_call.function.arguments)

                logger.info(
                    "Tool call: %s(%s)",
                    fn_name,
                    fn_args.get("reason", fn_args.get("address", ""))[:100],
                )

                if fn_name == "conclude_analysis":
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps({"status": "analysis_complete"}),
                    })
                    self.transcript.add(self.iteration, "conclude", {
                        "conclusion_args": fn_args,
                    })
                    return self._parse_conclusion(goal, fn_args)

                # Execute tool and feed result back
                t0 = time.time()
                result = self._execute_tool(fn_name, fn_args)
                tool_dur = time.time() - t0

                self.findings.append({
                    "iteration": self.iteration,
                    "tool": fn_name,
                    "args": fn_args,
                    "result": result,
                })

                # Log tool execution
                result_preview = json.dumps(result, default=str)
                if len(result_preview) > 2000:
                    result_preview = result_preview[:2000] + "...(truncated)"
                self.transcript.add(self.iteration, "tool_exec", {
                    "tool": fn_name,
                    "args": fn_args,
                    "result_preview": result_preview,
                    "result_is_error": isinstance(result, dict) and "error" in result,
                }, duration_s=tool_dur)

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result),
                })

        raise AnalysisTimeout(
            f"Analysis did not converge after {self.max_iterations} iterations. "
            f"Collected {len(self.findings)} findings."
        )

    def _execute_tool(self, name: str, args: dict) -> Any:
        """Execute a Ghidra tool call and return the result."""
        try:
            if name == "decompile_function":
                addr = int(args["address"], 16)
                return self.ghidra.decompile_at(addr)

            elif name == "get_xrefs_to":
                addr = int(args["address"], 16)
                return self.ghidra.get_xrefs_to(addr)

            elif name == "get_xrefs_from":
                addr = int(args["address"], 16)
                return self.ghidra.get_xrefs_from(addr)

            elif name == "get_bytes":
                addr = int(args["address"], 16)
                length = args.get("length", 32)
                hex_str = self.ghidra.get_bytes(addr, length)
                return {"address": args["address"], "length": length, "hex": hex_str}

            elif name == "search_strings":
                pattern = args["pattern"]
                return self.ghidra.search_strings(pattern)

            elif name == "list_functions":
                pattern = args["pattern"]
                max_results = args.get("max_results", 20)
                return self.ghidra.list_functions(pattern, max_results)

            else:
                return {"error": f"Unknown tool: {name}"}

        except Exception as e:
            logger.warning("Tool %s failed: %s", name, e)
            return {"error": str(e)}

    def _parse_conclusion(self, goal: AnalysisGoal, args: dict) -> AnalysisResult:
        """Parse the conclude_analysis tool call into an AnalysisResult."""
        key_functions = []
        for f in args.get("key_functions", []):
            key_functions.append(KeyFunction(
                name=f.get("name", "unknown"),
                address=f.get("address", "0x0"),
                role=f.get("role", "unknown"),
                pseudocode_summary=f.get("pseudocode_summary", ""),
            ))

        return AnalysisResult(
            goal_name=goal.name,
            conclusion=args,
            key_functions=key_functions,
            iterations_used=self.iteration,
            raw_findings=self.findings,
        )


def _serialize_assistant_message(msg) -> dict:
    """Serialize an OpenAI assistant message for the messages list.

    Handles the tool_calls attribute which isn't a plain dict.
    """
    serialized: dict[str, Any] = {"role": "assistant"}

    if msg.content:
        serialized["content"] = msg.content

    if msg.tool_calls:
        serialized["tool_calls"] = [
            {
                "id": tc.id,
                "type": "function",
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in msg.tool_calls
        ]

    return serialized
