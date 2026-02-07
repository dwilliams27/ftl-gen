"""Tests for LLM client and parsers."""

import json

import pytest

from ftl_gen.llm.client import LLMClient
from ftl_gen.llm.parsers import (
    extract_json,
    extract_json_list,
    parse_events_response,
    parse_weapons_response,
)


class TestExtractJson:
    """Tests for JSON extraction from LLM responses."""

    def test_plain_json(self):
        text = '{"name": "test", "value": 123}'
        result = extract_json(text)
        assert result == {"name": "test", "value": 123}

    def test_json_in_markdown(self):
        text = """Here is the response:
```json
{"name": "test", "value": 123}
```
That's the data."""
        result = extract_json(text)
        assert result == {"name": "test", "value": 123}

    def test_json_in_plain_code_block(self):
        text = """```
{"name": "test"}
```"""
        result = extract_json(text)
        assert result == {"name": "test"}

    def test_json_with_surrounding_text(self):
        text = """Let me generate that for you:
{"name": "weapon", "type": "LASER"}
I hope that helps!"""
        result = extract_json(text)
        assert result == {"name": "weapon", "type": "LASER"}

    def test_nested_json(self):
        text = '{"items": [{"name": "a"}, {"name": "b"}]}'
        result = extract_json(text)
        assert len(result["items"]) == 2

    def test_invalid_json_raises(self):
        from ftl_gen.llm.parsers import LLMResponseError

        with pytest.raises(LLMResponseError):
            extract_json("not json at all")


class TestExtractJsonList:
    """Tests for list extraction from JSON responses."""

    def test_items_key(self):
        text = '{"items": [{"name": "a"}, {"name": "b"}]}'
        result = extract_json_list(text, "items")
        assert len(result) == 2

    def test_weapons_key(self):
        text = '{"weapons": [{"name": "w1"}]}'
        result = extract_json_list(text, "items")  # Will find weapons as fallback
        assert len(result) == 1

    def test_single_object(self):
        text = '{"name": "single"}'
        result = extract_json_list(text)
        assert len(result) == 1
        assert result[0]["name"] == "single"


class TestParseWeaponsResponse:
    """Tests for weapon response parsing."""

    def test_parse_valid_weapons(self):
        response = json.dumps({
            "items": [
                {
                    "name": "PLASMA_LASER",
                    "type": "LASER",
                    "title": "Plasma Laser",
                    "desc": "A powerful laser",
                    "damage": 2,
                    "shots": 2,
                    "cooldown": 12,
                    "power": 2,
                    "cost": 60,
                }
            ]
        })

        weapons = parse_weapons_response(response)
        assert len(weapons) == 1
        assert weapons[0].name == "PLASMA_LASER"
        assert weapons[0].type == "LASER"

    def test_parse_fixes_name_format(self):
        response = json.dumps({
            "items": [
                {
                    "name": "plasma laser",
                    "type": "LASER",
                    "title": "Plasma Laser",
                    "desc": "A laser",
                    "cooldown": 10,
                    "power": 2,
                    "cost": 50,
                }
            ]
        })

        weapons = parse_weapons_response(response)
        assert weapons[0].name == "PLASMA_LASER"

    def test_parse_handles_missing_defaults(self):
        response = json.dumps({
            "items": [
                {
                    "name": "SIMPLE",
                    "type": "LASER",
                    "title": "Simple",
                    "desc": "Simple weapon",
                    "cooldown": 10,
                    "power": 2,
                    "cost": 50,
                }
            ]
        })

        weapons = parse_weapons_response(response)
        assert weapons[0].damage == 1  # Default
        assert weapons[0].shots == 1  # Default

    def test_parse_multiple_weapons(self):
        response = json.dumps({
            "items": [
                {
                    "name": "W1",
                    "type": "LASER",
                    "title": "W1",
                    "desc": "W1",
                    "cooldown": 10,
                    "power": 2,
                    "cost": 50,
                },
                {
                    "name": "W2",
                    "type": "BEAM",
                    "title": "W2",
                    "desc": "W2",
                    "cooldown": 15,
                    "power": 3,
                    "cost": 65,
                    "length": 40,
                },
            ]
        })

        weapons = parse_weapons_response(response)
        assert len(weapons) == 2


class TestParseEventsResponse:
    """Tests for event response parsing."""

    def test_parse_valid_event(self):
        response = json.dumps({
            "items": [
                {
                    "name": "TEST_EVENT",
                    "text": "You encounter a situation.",
                    "choices": [
                        {
                            "text": "Accept",
                            "event": {"text": "You accepted.", "scrap": 50}
                        },
                        {
                            "text": "Decline",
                            "event": {"text": "You declined."}
                        }
                    ]
                }
            ]
        })

        events = parse_events_response(response)
        assert len(events) == 1
        assert events[0].name == "TEST_EVENT"
        assert len(events[0].choices) == 2

    def test_parse_event_with_requirements(self):
        response = json.dumps({
            "items": [
                {
                    "name": "CREW_EVENT",
                    "text": "An event",
                    "choices": [
                        {
                            "text": "Send Engi",
                            "req": "engi",
                            "hidden": True,
                            "event": {"text": "Success"}
                        }
                    ]
                }
            ]
        })

        events = parse_events_response(response)
        assert events[0].choices[0].req == "engi"
        assert events[0].choices[0].hidden is True


class TestLLMClientParsing:
    """Tests for LLMClient JSON parsing."""

    def test_parse_json_response_plain(self):
        client = LLMClient()
        result = client._parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_response_markdown(self):
        client = LLMClient()
        result = client._parse_json_response("""```json
{"key": "value"}
```""")
        assert result == {"key": "value"}

    def test_parse_json_response_with_text(self):
        client = LLMClient()
        result = client._parse_json_response("""Here's the data:
{"key": "value"}
That's all.""")
        assert result == {"key": "value"}
