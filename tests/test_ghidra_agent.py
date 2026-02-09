"""Tests for Ghidra headless wrapper, agent, and validator."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Skip if lief/capstone not installed
pytest.importorskip("lief")
capstone = pytest.importorskip("capstone")


# --- GhidraHeadless tests ---


class TestGhidraHeadless:
    """Test the GhidraHeadless wrapper class."""

    def test_init_missing_ghidra(self, tmp_path):
        from ftl_gen.binary.ghidra.headless import GhidraError, GhidraHeadless

        with pytest.raises(GhidraError, match="analyzeHeadless not found"):
            GhidraHeadless(ghidra_home=tmp_path)

    def test_init_valid_ghidra(self, tmp_path):
        from ftl_gen.binary.ghidra.headless import GhidraHeadless

        # Create fake analyzeHeadless
        support_dir = tmp_path / "support"
        support_dir.mkdir()
        (support_dir / "analyzeHeadless").touch()

        ghidra = GhidraHeadless(ghidra_home=tmp_path)
        assert ghidra.analyze_headless == support_dir / "analyzeHeadless"

    def test_import_binary_missing(self, tmp_path):
        from ftl_gen.binary.ghidra.headless import GhidraError, GhidraHeadless

        support_dir = tmp_path / "support"
        support_dir.mkdir()
        (support_dir / "analyzeHeadless").touch()

        ghidra = GhidraHeadless(ghidra_home=tmp_path)
        with pytest.raises(GhidraError, match="Binary not found"):
            ghidra.import_binary(tmp_path / "nonexistent")

    def test_run_script_no_import(self, tmp_path):
        from ftl_gen.binary.ghidra.headless import GhidraError, GhidraHeadless

        support_dir = tmp_path / "support"
        support_dir.mkdir()
        (support_dir / "analyzeHeadless").touch()

        ghidra = GhidraHeadless(ghidra_home=tmp_path)
        script = tmp_path / "test.py"
        script.touch()

        with pytest.raises(GhidraError, match="No binary imported"):
            ghidra.run_script(script)

    def test_extract_results(self, tmp_path):
        from ftl_gen.binary.ghidra.headless import GhidraHeadless

        support_dir = tmp_path / "support"
        support_dir.mkdir()
        (support_dir / "analyzeHeadless").touch()

        ghidra = GhidraHeadless(ghidra_home=tmp_path)

        # Test direct RESULT: prefix
        stdout = (
            "INFO  (GhidraScript)  some log line\n"
            'RESULT:{"value": "SCRAP_COLLECTOR", "address": "0x1234"}\n'
            "INFO  (GhidraScript)  another log line\n"
            'RESULT:{"value": "REPAIR_ARM", "address": "0x5678"}\n'
        )

        extracted = ghidra._extract_results(stdout)
        lines = extracted.strip().splitlines()
        assert len(lines) == 2

        d1 = json.loads(lines[0])
        assert d1["value"] == "SCRAP_COLLECTOR"
        d2 = json.loads(lines[1])
        assert d2["value"] == "REPAIR_ARM"

        # Test Ghidra 12 log-wrapped format:
        # INFO  script.py> RESULT:{...} (GhidraScript)
        stdout_wrapped = (
            'INFO  find_strings.py> RESULT:{"value": "AUTO_COOLDOWN", "address": "0xabc"} (GhidraScript)  \n'
            "INFO  find_strings.py> some other log (GhidraScript)  \n"
            'INFO  find_strings.py> RESULT:{"value": "REPAIR_ARM", "address": "0xdef"} (GhidraScript)  \n'
        )

        extracted2 = ghidra._extract_results(stdout_wrapped)
        lines2 = extracted2.strip().splitlines()
        assert len(lines2) == 2

        d3 = json.loads(lines2[0])
        assert d3["value"] == "AUTO_COOLDOWN"
        d4 = json.loads(lines2[1])
        assert d4["value"] == "REPAIR_ARM"

    def test_scripts_dir_exists(self):
        from ftl_gen.binary.ghidra.headless import GhidraHeadless

        scripts_dir = GhidraHeadless.SCRIPTS_DIR
        assert scripts_dir.exists()
        assert (scripts_dir / "find_strings.py").exists()
        assert (scripts_dir / "decompile_function.py").exists()
        assert (scripts_dir / "get_xrefs.py").exists()
        assert (scripts_dir / "get_bytes.py").exists()


# --- AnalysisResult tests ---


class TestAnalysisResult:
    """Test AnalysisResult dataclass serialization."""

    def test_to_dict(self):
        from ftl_gen.binary.ghidra.agent import AnalysisResult, KeyFunction

        analysis = AnalysisResult(
            goal_name="augment_dispatch",
            conclusion={
                "dispatch_pattern": "scattered_checks",
                "primary_function_addr": "0x8b420",
                "recommended_patch_strategy": "trampoline on HasAugmentation entry",
            },
            key_functions=[
                KeyFunction(
                    name="HasAugmentation",
                    address="0x8b420",
                    role="Main augment check function",
                ),
            ],
            iterations_used=5,
        )

        d = analysis.to_dict()
        assert d["goal_name"] == "augment_dispatch"
        assert d["conclusion"]["dispatch_pattern"] == "scattered_checks"
        assert len(d["key_functions"]) == 1
        assert d["key_functions"][0]["name"] == "HasAugmentation"

    def test_get_conclusion_field(self):
        from ftl_gen.binary.ghidra.agent import AnalysisResult

        analysis = AnalysisResult(
            goal_name="test",
            conclusion={"dispatch_pattern": "scattered_checks", "some_field": "value"},
        )

        assert analysis.get("dispatch_pattern") == "scattered_checks"
        assert analysis.get("some_field") == "value"
        assert analysis.get("missing") is None
        assert analysis.get("missing", "default") == "default"

    def test_save_and_load(self, tmp_path):
        from ftl_gen.binary.ghidra.agent import AnalysisResult, KeyFunction

        analysis = AnalysisResult(
            goal_name="augment_dispatch",
            conclusion={
                "dispatch_pattern": "hybrid",
                "primary_function_addr": "0xabc",
                "recommended_patch_strategy": "detour",
            },
            key_functions=[
                KeyFunction(name="fn1", address="0x100", role="checker"),
            ],
            iterations_used=3,
        )

        path = tmp_path / "analysis.json"
        analysis.save(path)
        assert path.exists()

        loaded = AnalysisResult.load(path)
        assert loaded.goal_name == "augment_dispatch"
        assert loaded.get("dispatch_pattern") == "hybrid"
        assert loaded.get("primary_function_addr") == "0xabc"
        assert loaded.iterations_used == 3
        assert len(loaded.key_functions) == 1
        assert loaded.key_functions[0].name == "fn1"


# --- GhidraAgent tests ---


@patch("ftl_gen.binary.ghidra.agent.openai.OpenAI")
class TestGhidraAgent:
    """Test the agentic analysis loop (mocked OpenAI + Ghidra)."""

    def _make_agent(self, mock_openai_cls):
        from ftl_gen.binary.ghidra.agent import GhidraAgent

        mock_ghidra = MagicMock()
        mock_ghidra.find_strings.return_value = [
            {"value": "SCRAP_COLLECTOR", "address": "0x2d1d75", "xrefs": ["0x8b420"]},
            {"value": "REPAIR_ARM", "address": "0x2d1d85", "xrefs": ["0x8b430"]},
        ]
        mock_ghidra.decompile_at.return_value = {
            "function": "HasAugmentation",
            "address": "0x8b400",
            "pseudocode": "bool HasAugmentation(string *name) { ... }",
        }
        mock_ghidra.get_xrefs_to.return_value = [
            {"from_address": "0x9a000", "from_function": "FUN_9a000", "ref_type": "CALL"},
        ]
        mock_ghidra.get_bytes.return_value = "554889e54883ec20"

        agent = GhidraAgent(ghidra=mock_ghidra)
        return agent, mock_ghidra

    def test_execute_tool_decompile(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        result = agent._execute_tool("decompile_function", {"address": "0x8b420", "reason": "test"})
        mock_ghidra.decompile_at.assert_called_once_with(0x8b420)
        assert result["function"] == "HasAugmentation"

    def test_execute_tool_xrefs_to(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        result = agent._execute_tool("get_xrefs_to", {"address": "0x8b420", "reason": "test"})
        mock_ghidra.get_xrefs_to.assert_called_once_with(0x8b420)
        assert len(result) == 1

    def test_execute_tool_xrefs_from(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        mock_ghidra.get_xrefs_from.return_value = [{"to_address": "0x1234"}]
        result = agent._execute_tool("get_xrefs_from", {"address": "0x8b420", "reason": "test"})
        mock_ghidra.get_xrefs_from.assert_called_once_with(0x8b420)

    def test_execute_tool_get_bytes(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        result = agent._execute_tool("get_bytes", {"address": "0x8b420", "length": 16, "reason": "test"})
        mock_ghidra.get_bytes.assert_called_once_with(0x8b420, 16)
        assert result["hex"] == "554889e54883ec20"

    def test_execute_tool_search_strings(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        mock_ghidra.search_strings.return_value = [{"value": "Augmentation"}]
        result = agent._execute_tool("search_strings", {"pattern": "Augmentation", "reason": "test"})
        mock_ghidra.search_strings.assert_called_once_with("Augmentation")

    def test_execute_tool_list_functions(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        mock_ghidra.list_functions.return_value = [
            {"name": "GetEvent", "address": "0x1002a3f40", "size": 256}
        ]
        result = agent._execute_tool(
            "list_functions", {"pattern": "GetEvent", "reason": "test"}
        )
        mock_ghidra.list_functions.assert_called_once_with("GetEvent", 20)

    def test_execute_tool_list_functions_max_results(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        mock_ghidra.list_functions.return_value = []
        result = agent._execute_tool(
            "list_functions", {"pattern": "Boss", "max_results": 5, "reason": "test"}
        )
        mock_ghidra.list_functions.assert_called_once_with("Boss", 5)

    def test_execute_tool_unknown(self, mock_openai_cls):
        agent, _ = self._make_agent(mock_openai_cls)
        result = agent._execute_tool("unknown_tool", {})
        assert "error" in result

    def test_execute_tool_error_handling(self, mock_openai_cls):
        agent, mock_ghidra = self._make_agent(mock_openai_cls)
        mock_ghidra.decompile_at.side_effect = RuntimeError("Ghidra crashed")
        result = agent._execute_tool("decompile_function", {"address": "0x8b420", "reason": "test"})
        assert "error" in result

    def test_parse_conclusion(self, mock_openai_cls):
        from ftl_gen.binary.ghidra.agent import AUGMENT_DISPATCH_GOAL

        agent, _ = self._make_agent(mock_openai_cls)
        args = {
            "dispatch_pattern": "scattered_checks",
            "primary_function_addr": "0x8b400",
            "secondary_function_addr": "0x8b500",
            "string_comparison_method": "operator==",
            "calling_convention": "rdi=this",
            "function_prologue_bytes": "554889e5",
            "recommended_patch_strategy": "trampoline",
            "key_functions": [
                {"name": "HasAugmentation", "address": "0x8b400", "role": "checker"},
            ],
        }

        result = agent._parse_conclusion(AUGMENT_DISPATCH_GOAL, args)
        assert result.get("dispatch_pattern") == "scattered_checks"
        assert result.get("primary_function_addr") == "0x8b400"
        assert result.goal_name == "augment_dispatch"
        assert len(result.key_functions) == 1

    def test_full_loop_conclude_immediately(self, mock_openai_cls):
        """Test that the agent loop terminates when conclude_analysis is called."""
        from ftl_gen.binary.ghidra.agent import AUGMENT_DISPATCH_GOAL, GhidraAgent

        mock_ghidra = MagicMock()
        mock_ghidra.find_strings.return_value = [
            {"value": "SCRAP_COLLECTOR", "address": "0x2d1d75", "xrefs": ["0x8b420"]},
        ]

        # Create a mock response that calls conclude_analysis
        mock_tool_call = MagicMock()
        mock_tool_call.id = "call_123"
        mock_tool_call.function.name = "conclude_analysis"
        mock_tool_call.function.arguments = json.dumps({
            "dispatch_pattern": "scattered_checks",
            "primary_function_addr": "0x8b400",
            "recommended_patch_strategy": "trampoline",
            "key_functions": [],
        })

        mock_msg = MagicMock()
        mock_msg.content = None
        mock_msg.tool_calls = [mock_tool_call]

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=mock_msg)]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_cls.return_value = mock_client

        agent = GhidraAgent(ghidra=mock_ghidra)
        result = agent.run(AUGMENT_DISPATCH_GOAL)

        assert result.goal_name == "augment_dispatch"
        assert result.get("dispatch_pattern") == "scattered_checks"
        assert result.get("primary_function_addr") == "0x8b400"
        assert result.iterations_used == 1

        # Transcript should be populated
        assert agent.transcript is not None
        assert agent.transcript.goal_name == "augment_dispatch"
        assert len(agent.transcript.entries) >= 2  # seed + llm_call + conclude
        assert agent.transcript.total_duration_s >= 0

    def test_transcript_save(self, mock_openai_cls, tmp_path):
        """Test that transcript saves correctly to JSON."""
        from ftl_gen.binary.ghidra.agent import AUGMENT_DISPATCH_GOAL, GhidraAgent

        mock_ghidra = MagicMock()
        mock_ghidra.find_strings.return_value = [
            {"value": "SCRAP_COLLECTOR", "address": "0x2d1d75", "xrefs": []},
        ]

        mock_tool_call = MagicMock()
        mock_tool_call.id = "call_456"
        mock_tool_call.function.name = "conclude_analysis"
        mock_tool_call.function.arguments = json.dumps({
            "dispatch_pattern": "scattered_checks",
            "primary_function_addr": "0x8b400",
            "recommended_patch_strategy": "trampoline",
            "key_functions": [],
        })

        mock_msg = MagicMock()
        mock_msg.content = None
        mock_msg.tool_calls = [mock_tool_call]

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=mock_msg)]

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = mock_response
        mock_openai_cls.return_value = mock_client

        agent = GhidraAgent(ghidra=mock_ghidra)
        agent.run(AUGMENT_DISPATCH_GOAL)

        transcript_path = tmp_path / "transcript.json"
        agent.save_transcript(transcript_path)
        assert transcript_path.exists()

        data = json.loads(transcript_path.read_text())
        assert data["goal_name"] == "augment_dispatch"
        assert data["num_iterations"] >= 1
        assert data["total_duration_s"] >= 0
        assert len(data["entries"]) >= 2
        assert data["final_messages"]  # should have the full message history


# --- Preset goals tests ---


class TestPresetGoals:
    """Test that all preset goals are properly registered."""

    def test_all_presets_registered(self):
        from ftl_gen.binary.ghidra.agent import PRESET_GOALS

        assert "augment_dispatch" in PRESET_GOALS
        assert "event_dispatch" in PRESET_GOALS
        assert "get_event" in PRESET_GOALS

    def test_get_event_goal_fields(self):
        from ftl_gen.binary.ghidra.agent import GET_EVENT_GOAL

        assert GET_EVENT_GOAL.name == "get_event"
        assert "GetEvent" in GET_EVENT_GOAL.system_prompt
        assert "get_event_addr" in GET_EVENT_GOAL.conclusion_required
        assert "get_event_purpose" in GET_EVENT_GOAL.conclusion_required
        assert "key_functions" in GET_EVENT_GOAL.conclusion_required

    def test_custom_goal_factory(self):
        from ftl_gen.binary.ghidra.agent import custom_goal

        goal = custom_goal(
            name="test_goal",
            objective="Find the main loop",
            seed_strings=["main", "loop"],
        )
        assert goal.name == "test_goal"
        assert "main loop" in goal.system_prompt
        assert "key_functions" in goal.conclusion_required


# --- FindingValidator tests ---


class TestFindingValidator:
    """Test the deterministic validator using real binary or synthetic data."""

    def _make_validator(self, tmp_path, data: bytes):
        from ftl_gen.binary.ghidra.validator import FindingValidator

        binary = tmp_path / "test_binary"
        binary.write_bytes(data)
        return FindingValidator(binary)

    def test_validate_string_at_match(self, tmp_path):
        data = b"\x00SCRAP_COLLECTOR\x00more stuff"
        validator = self._make_validator(tmp_path, data)
        result = validator.validate_string_at(1, "SCRAP_COLLECTOR")
        assert result.passed is True
        assert result.confidence == 1.0

    def test_validate_string_at_mismatch(self, tmp_path):
        data = b"\x00REPAIR_ARM\x00more stuff"
        validator = self._make_validator(tmp_path, data)
        result = validator.validate_string_at(1, "SCRAP_COLLECTOR")
        assert result.passed is False
        assert result.confidence == 0.0

    def test_validate_function_prologue_classic(self, tmp_path):
        # push rbp; mov rbp, rsp
        data = b"\x55\x48\x89\xe5\x48\x83\xec\x20" + b"\x90" * 24
        validator = self._make_validator(tmp_path, data)
        result = validator.validate_function_prologue(0, 0x100000)
        assert result.passed is True
        assert "push rbp" in result.evidence

    def test_validate_function_prologue_push_rbx(self, tmp_path):
        # push rbx; sub rsp, 0x20
        data = b"\x53\x48\x83\xec\x20" + b"\x90" * 27
        validator = self._make_validator(tmp_path, data)
        result = validator.validate_function_prologue(0, 0x100000)
        assert result.passed is True

    def test_validate_function_prologue_not_prologue(self, tmp_path):
        # nop; nop; nop...
        data = b"\x90" * 32
        validator = self._make_validator(tmp_path, data)
        result = validator.validate_function_prologue(0, 0x100000)
        assert result.passed is False

    def test_validate_bytes_at_match(self, tmp_path):
        data = b"\x55\x48\x89\xe5\x00" * 10
        validator = self._make_validator(tmp_path, data)
        result = validator.validate_bytes_at(0, "554889e5")
        assert result.passed is True

    def test_validate_bytes_at_mismatch(self, tmp_path):
        data = b"\x90\x90\x90\x90\x00" * 10
        validator = self._make_validator(tmp_path, data)
        result = validator.validate_bytes_at(0, "554889e5")
        assert result.passed is False

    def test_get_disassembly(self, tmp_path):
        # push rbp; mov rbp, rsp; sub rsp, 0x20; ret
        data = b"\x55\x48\x89\xe5\x48\x83\xec\x20\xc3" + b"\x00" * 23
        validator = self._make_validator(tmp_path, data)
        disasm = validator.get_disassembly(0, 0x100000, num_instructions=5)
        assert len(disasm) >= 3
        assert disasm[0]["mnemonic"] == "push"


class TestFindingValidatorRealBinary:
    """Integration tests using the real FTL binary."""

    @pytest.fixture
    def ftl_binary(self):
        from ftl_gen.config import get_settings

        settings = get_settings()
        binary_path = settings.find_ftl_executable()
        if binary_path is None or not binary_path.exists():
            pytest.skip("FTL binary not found")
        return binary_path

    def test_validate_known_augment_strings(self, ftl_binary):
        from ftl_gen.binary.ghidra.validator import FindingValidator
        from ftl_gen.binary.recon import BinaryRecon

        recon = BinaryRecon(ftl_binary)
        info = recon.analyze()
        validator = FindingValidator(ftl_binary)

        # Validate each augment string found by recon
        for string_ref in info.augment_strings[:5]:
            result = validator.validate_string_at(
                string_ref.file_offset,
                string_ref.value,
            )
            assert result.passed, f"Failed to validate {string_ref.value} at 0x{string_ref.file_offset:x}"

    def test_disassemble_text_section(self, ftl_binary):
        from ftl_gen.binary.ghidra.validator import FindingValidator
        from ftl_gen.binary.recon import BinaryRecon

        recon = BinaryRecon(ftl_binary)
        info = recon.analyze()
        validator = FindingValidator(ftl_binary)

        text_seg = next((s for s in info.segments if s.name == "__TEXT"), None)
        assert text_seg is not None

        # Find __text section offset (code, not strings)
        # Use a small offset into __text for disassembly test
        # The __text section starts after the Mach-O header
        disasm = validator.get_disassembly(
            text_seg.file_offset + 0x2000,
            text_seg.virtual_address + 0x2000,
            num_instructions=10,
        )
        assert len(disasm) > 0
        # Should have valid x86_64 instructions
        assert all("address" in insn for insn in disasm)
