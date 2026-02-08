"""XML validation for FTL mod files."""

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

from ftl_gen.constants import DRONE_TYPES as _DRONE_TYPES
from ftl_gen.constants import WEAPON_TYPES as _WEAPON_TYPES


@dataclass
class ValidationResult:
    """Result of XML validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]

    @property
    def ok(self) -> bool:
        return self.valid and not self.errors


@dataclass
class DiagnosticCheck:
    """A single diagnostic check result."""

    name: str
    status: str  # "pass" | "fail" | "warn"
    message: str = ""


@dataclass
class DiagnosticResult:
    """Result of running all diagnostic checks on a mod."""

    checks: list[DiagnosticCheck] = field(default_factory=list)
    event_cycles: list[list[str]] = field(default_factory=list)
    dangling_refs: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.status != "fail" for c in self.checks)


def detect_event_loops(events_xml: str) -> list[list[str]]:
    """Detect circular references in event chains.

    Parses events XML, builds a directed graph of event references,
    and finds all cycles using DFS with white/gray/black coloring.

    Returns list of cycles, each cycle is a list of event names.
    """
    try:
        root = etree.fromstring(events_xml.encode())
    except etree.XMLSyntaxError:
        return []

    # Build adjacency graph: event name -> set of referenced event names
    graph: dict[str, set[str]] = defaultdict(set)
    defined_events: set[str] = set()

    for event_elem in root.findall(".//event[@name]"):
        event_name = event_elem.get("name")
        if not event_name:
            continue
        defined_events.add(event_name)

        # Find all <event load="X"> descendants (references to other events)
        for load_elem in event_elem.findall(".//event[@load]"):
            target = load_elem.get("load")
            if target:
                graph[event_name].add(target)

    # DFS cycle detection (white=unvisited, gray=in-progress, black=done)
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {name: WHITE for name in defined_events}
    cycles: list[list[str]] = []
    path: list[str] = []

    def dfs(node: str) -> None:
        if node not in color:
            return
        color[node] = GRAY
        path.append(node)

        for neighbor in graph.get(node, set()):
            if neighbor not in color:
                continue
            if color[neighbor] == GRAY:
                # Found a cycle - extract it from path
                cycle_start = path.index(neighbor)
                cycle = path[cycle_start:] + [neighbor]
                cycles.append(cycle)
            elif color[neighbor] == WHITE:
                dfs(neighbor)

        path.pop()
        color[node] = BLACK

    for event_name in defined_events:
        if color[event_name] == WHITE:
            dfs(event_name)

    return cycles


def check_dangling_references(events_xml: str) -> list[str]:
    """Find event references that point to undefined events.

    Returns list of strings like "EVENT_A -> undefined EVENT_B".
    """
    try:
        root = etree.fromstring(events_xml.encode())
    except etree.XMLSyntaxError:
        return []

    # Collect all defined top-level event names
    defined: set[str] = set()
    for event_elem in root.findall(".//event[@name]"):
        name = event_elem.get("name")
        if name:
            defined.add(name)

    # Find all references
    dangling: list[str] = []
    for event_elem in root.findall(".//event[@name]"):
        source = event_elem.get("name")
        for load_elem in event_elem.findall(".//event[@load]"):
            target = load_elem.get("load")
            if target and target not in defined:
                dangling.append(f"{source} -> undefined {target}")

    return dangling


def check_common_crash_patterns(
    blueprints_xml: str | None, events_xml: str | None
) -> list[str]:
    """Check for patterns known to cause FTL crashes.

    Returns list of warning/error strings.
    """
    issues: list[str] = []

    # Check events for choices without outcomes
    if events_xml:
        try:
            root = etree.fromstring(events_xml.encode())
            for event_elem in root.findall(".//event[@name]"):
                event_name = event_elem.get("name")
                for i, choice in enumerate(event_elem.findall("choice"), 1):
                    # A choice must have an <event> child (the outcome)
                    outcome = choice.find("event")
                    if outcome is None:
                        issues.append(
                            f"Event '{event_name}' choice {i} has no <event> outcome "
                            f"(crashes: 'Choice does not have an event')"
                        )
                    elif outcome.get("load") is None and outcome.find("text") is None:
                        issues.append(
                            f"Event '{event_name}' choice {i} has empty outcome "
                            f"(no text and no load reference)"
                        )
        except etree.XMLSyntaxError:
            issues.append("Events XML has syntax errors")

    # Check weapon blueprints for type-specific required fields
    if blueprints_xml:
        try:
            root = etree.fromstring(blueprints_xml.encode())
            for weapon in root.findall(".//weaponBlueprint"):
                name = weapon.get("name", "(unnamed)")
                type_elem = weapon.find("type")
                if type_elem is None:
                    continue
                wtype = type_elem.text

                if wtype == "BEAM":
                    if weapon.find("length") is None:
                        issues.append(
                            f"BEAM weapon '{name}' missing <length> (required for beams)"
                        )
                if wtype == "MISSILES" or wtype == "BOMB":
                    if weapon.find("missiles") is None:
                        issues.append(
                            f"{wtype} weapon '{name}' missing <missiles> (ammo cost)"
                        )

                # iconImage is required on ALL weapons — missing it freezes at load
                if weapon.find("iconImage") is None:
                    issues.append(
                        f"Weapon '{name}' missing <iconImage> (freezes game at 'Blueprints Loaded!')"
                    )
        except etree.XMLSyntaxError:
            issues.append("Blueprints XML has syntax errors")

    return issues


class XMLValidator:
    """Validates FTL XML files."""

    # Required elements for each blueprint type
    WEAPON_REQUIRED = {"type", "title", "desc", "damage", "cooldown", "power", "cost"}
    DRONE_REQUIRED = {"type", "title", "desc", "power", "cost"}
    EVENT_REQUIRED = {"text"}

    WEAPON_TYPES = _WEAPON_TYPES
    DRONE_TYPES = _DRONE_TYPES

    def validate_xml_string(self, xml_str: str) -> ValidationResult:
        """Validate an XML string for basic syntax."""
        errors = []
        warnings = []

        try:
            root = etree.fromstring(xml_str.encode())
        except etree.XMLSyntaxError as e:
            return ValidationResult(valid=False, errors=[f"XML syntax error: {e}"], warnings=[])

        # Check for FTL root element
        if root.tag != "FTL" and root.tag != "metadata":
            warnings.append(f"Root element is '{root.tag}', expected 'FTL' for append files")

        return ValidationResult(valid=True, errors=errors, warnings=warnings)

    def validate_weapon_blueprint(self, elem: etree._Element) -> ValidationResult:
        """Validate a weaponBlueprint element for structural correctness.

        Range checking is handled by Pydantic schemas (WeaponBlueprint).
        This validates XML structure: required elements, valid types, parseable numbers.
        """
        errors = []
        warnings = []

        name = elem.get("name")
        if not name:
            errors.append("weaponBlueprint missing 'name' attribute")
            return ValidationResult(valid=False, errors=errors, warnings=warnings)

        # Check required elements
        found_elements = {child.tag for child in elem}
        missing = self.WEAPON_REQUIRED - found_elements

        if missing:
            errors.append(f"Weapon '{name}' missing required elements: {missing}")

        # Check weapon type
        type_elem = elem.find("type")
        if type_elem is not None and type_elem.text not in self.WEAPON_TYPES:
            errors.append(f"Weapon '{name}' has invalid type: {type_elem.text}")

        # Check numeric fields are parseable (range validation is in Pydantic)
        for field, parser in [("damage", int), ("cooldown", float), ("power", int)]:
            elem_val = elem.find(field)
            if elem_val is not None:
                try:
                    parser(elem_val.text)
                except (ValueError, TypeError):
                    errors.append(f"Weapon '{name}' has non-numeric {field} value")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def validate_event(self, elem: etree._Element) -> ValidationResult:
        """Validate an event element."""
        errors = []
        warnings = []

        name = elem.get("name")
        if not name:
            warnings.append("Event missing 'name' attribute")
            name = "(unnamed)"

        # Check for text
        text_elem = elem.find("text")
        if text_elem is None:
            errors.append(f"Event '{name}' missing required 'text' element")

        # Check choices
        choices = elem.findall("choice")
        if choices:
            for i, choice in enumerate(choices):
                choice_text = choice.find("text")
                if choice_text is None:
                    errors.append(f"Event '{name}' choice {i + 1} missing 'text' element")

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def validate_file(self, file_path: Path) -> ValidationResult:
        """Validate an XML file."""
        errors = []
        warnings = []

        if not file_path.exists():
            return ValidationResult(valid=False, errors=[f"File not found: {file_path}"], warnings=[])

        try:
            tree = etree.parse(str(file_path))
            root = tree.getroot()
        except etree.XMLSyntaxError as e:
            return ValidationResult(valid=False, errors=[f"XML syntax error in {file_path}: {e}"], warnings=[])

        # Validate weapon blueprints
        for weapon in root.findall(".//weaponBlueprint"):
            result = self.validate_weapon_blueprint(weapon)
            errors.extend(result.errors)
            warnings.extend(result.warnings)

        # Validate events
        for event in root.findall(".//event[@name]"):
            result = self.validate_event(event)
            errors.extend(result.errors)
            warnings.extend(result.warnings)

        return ValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings)

    def validate_mod_directory(self, mod_dir: Path) -> ValidationResult:
        """Validate all XML files in a mod directory."""
        all_errors = []
        all_warnings = []

        data_dir = mod_dir / "data"
        if not data_dir.exists():
            return ValidationResult(
                valid=False,
                errors=[f"No data directory found in {mod_dir}"],
                warnings=[]
            )

        for xml_file in data_dir.glob("*.xml*"):
            result = self.validate_file(xml_file)
            all_errors.extend(result.errors)
            all_warnings.extend(result.warnings)

        return ValidationResult(
            valid=len(all_errors) == 0,
            errors=all_errors,
            warnings=all_warnings
        )
