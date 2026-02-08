"""Tests for event loop detection and diagnostic checks."""

import pytest

from ftl_gen.xml.validators import (
    DiagnosticCheck,
    DiagnosticResult,
    check_common_crash_patterns,
    check_dangling_references,
    detect_event_loops,
)


# --- detect_event_loops ---


def _wrap_events(inner: str) -> str:
    return f"<FTL>{inner}</FTL>"


class TestDetectEventLoops:
    def test_no_cycle(self):
        xml = _wrap_events("""
            <event name="A">
                <text>Hello</text>
                <choice><text>Go</text><event load="B"/></choice>
            </event>
            <event name="B">
                <text>World</text>
            </event>
        """)
        assert detect_event_loops(xml) == []

    def test_simple_cycle(self):
        xml = _wrap_events("""
            <event name="A">
                <text>Hello</text>
                <choice><text>Go</text><event load="B"/></choice>
            </event>
            <event name="B">
                <text>World</text>
                <choice><text>Back</text><event load="A"/></choice>
            </event>
        """)
        cycles = detect_event_loops(xml)
        assert len(cycles) >= 1
        # The cycle should contain both A and B
        flat = [name for cycle in cycles for name in cycle]
        assert "A" in flat
        assert "B" in flat

    def test_self_reference(self):
        xml = _wrap_events("""
            <event name="LOOP">
                <text>Stuck</text>
                <choice><text>Again</text><event load="LOOP"/></choice>
            </event>
        """)
        cycles = detect_event_loops(xml)
        assert len(cycles) >= 1
        flat = [name for cycle in cycles for name in cycle]
        assert "LOOP" in flat

    def test_longer_cycle(self):
        xml = _wrap_events("""
            <event name="A">
                <text>A</text>
                <choice><text>Go</text><event load="B"/></choice>
            </event>
            <event name="B">
                <text>B</text>
                <choice><text>Go</text><event load="C"/></choice>
            </event>
            <event name="C">
                <text>C</text>
                <choice><text>Go</text><event load="A"/></choice>
            </event>
        """)
        cycles = detect_event_loops(xml)
        assert len(cycles) >= 1
        flat = [name for cycle in cycles for name in cycle]
        assert "A" in flat
        assert "B" in flat
        assert "C" in flat

    def test_invalid_xml_returns_empty(self):
        assert detect_event_loops("not xml at all") == []

    def test_no_events_returns_empty(self):
        xml = _wrap_events("<weaponBlueprint name='X'><type>LASER</type></weaponBlueprint>")
        assert detect_event_loops(xml) == []


# --- check_dangling_references ---


class TestCheckDanglingReferences:
    def test_no_dangling(self):
        xml = _wrap_events("""
            <event name="A">
                <text>Hello</text>
                <choice><text>Go</text><event load="B"/></choice>
            </event>
            <event name="B">
                <text>World</text>
            </event>
        """)
        assert check_dangling_references(xml) == []

    def test_dangling_reference(self):
        xml = _wrap_events("""
            <event name="A">
                <text>Hello</text>
                <choice><text>Go</text><event load="MISSING"/></choice>
            </event>
        """)
        refs = check_dangling_references(xml)
        assert len(refs) == 1
        assert "A" in refs[0]
        assert "MISSING" in refs[0]

    def test_invalid_xml_returns_empty(self):
        assert check_dangling_references("not xml") == []


# --- check_common_crash_patterns ---


class TestCheckCommonCrashPatterns:
    def test_choice_missing_outcome(self):
        events_xml = _wrap_events("""
            <event name="BAD">
                <text>An event</text>
                <choice><text>Do something</text></choice>
            </event>
        """)
        issues = check_common_crash_patterns(None, events_xml)
        assert len(issues) == 1
        assert "no <event> outcome" in issues[0]

    def test_choice_with_empty_outcome(self):
        events_xml = _wrap_events("""
            <event name="BAD">
                <text>An event</text>
                <choice><text>Do something</text><event/></choice>
            </event>
        """)
        issues = check_common_crash_patterns(None, events_xml)
        assert len(issues) == 1
        assert "empty outcome" in issues[0]

    def test_valid_choice_with_load(self):
        events_xml = _wrap_events("""
            <event name="OK">
                <text>An event</text>
                <choice><text>Go</text><event load="OTHER"/></choice>
            </event>
        """)
        issues = check_common_crash_patterns(None, events_xml)
        assert len(issues) == 0

    def test_valid_choice_with_text(self):
        events_xml = _wrap_events("""
            <event name="OK">
                <text>An event</text>
                <choice><text>Go</text><event><text>Result</text></event></choice>
            </event>
        """)
        issues = check_common_crash_patterns(None, events_xml)
        assert len(issues) == 0

    def test_beam_missing_length(self):
        bp_xml = _wrap_events("""
            <weaponBlueprint name="BAD_BEAM">
                <type>BEAM</type>
                <damage>2</damage>
            </weaponBlueprint>
        """)
        issues = check_common_crash_patterns(bp_xml, None)
        assert len(issues) == 2
        assert any("length" in i for i in issues)
        assert any("iconImage" in i for i in issues)

    def test_missiles_missing_ammo(self):
        bp_xml = _wrap_events("""
            <weaponBlueprint name="BAD_MISSILE">
                <type>MISSILES</type>
                <damage>3</damage>
            </weaponBlueprint>
        """)
        issues = check_common_crash_patterns(bp_xml, None)
        assert len(issues) == 2
        assert any("missiles" in i for i in issues)
        assert any("iconImage" in i for i in issues)

    def test_missing_icon_image(self):
        bp_xml = _wrap_events("""
            <weaponBlueprint name="NO_ICON">
                <type>LASER</type>
                <damage>1</damage>
            </weaponBlueprint>
        """)
        issues = check_common_crash_patterns(bp_xml, None)
        assert len(issues) == 1
        assert "iconImage" in issues[0]
        assert "NO_ICON" in issues[0]

    def test_icon_image_present(self):
        bp_xml = _wrap_events("""
            <weaponBlueprint name="GOOD_WEAPON">
                <type>LASER</type>
                <damage>1</damage>
                <iconImage>laser</iconImage>
            </weaponBlueprint>
        """)
        issues = check_common_crash_patterns(bp_xml, None)
        assert len(issues) == 0

    def test_no_issues_when_both_none(self):
        assert check_common_crash_patterns(None, None) == []


# --- DiagnosticResult ---


class TestDiagnosticResult:
    def test_ok_when_all_pass(self):
        result = DiagnosticResult(
            checks=[
                DiagnosticCheck(name="test1", status="pass"),
                DiagnosticCheck(name="test2", status="warn", message="minor"),
            ]
        )
        assert result.ok is True

    def test_not_ok_when_fail(self):
        result = DiagnosticResult(
            checks=[
                DiagnosticCheck(name="test1", status="pass"),
                DiagnosticCheck(name="test2", status="fail", message="bad"),
            ]
        )
        assert result.ok is False
