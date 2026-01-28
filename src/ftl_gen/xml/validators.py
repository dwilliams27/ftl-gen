"""XML validation for FTL mod files."""

from dataclasses import dataclass
from pathlib import Path

from lxml import etree


@dataclass
class ValidationResult:
    """Result of XML validation."""

    valid: bool
    errors: list[str]
    warnings: list[str]

    @property
    def ok(self) -> bool:
        return self.valid and not self.errors


class XMLValidator:
    """Validates FTL XML files."""

    # Required elements for each blueprint type
    WEAPON_REQUIRED = {"type", "title", "desc", "damage", "cooldown", "power", "cost"}
    DRONE_REQUIRED = {"type", "title", "desc", "power", "cost"}
    EVENT_REQUIRED = {"text"}

    # Valid weapon types
    WEAPON_TYPES = {"LASER", "MISSILES", "BEAM", "BOMB", "BURST", "ION"}
    DRONE_TYPES = {"COMBAT", "DEFENSE", "SHIP_REPAIR", "BOARDER", "REPAIR", "BATTLE", "HACKING"}

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
        """Validate a weaponBlueprint element."""
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

        # Check numeric ranges
        damage_elem = elem.find("damage")
        if damage_elem is not None:
            try:
                damage = int(damage_elem.text)
                if damage < 0 or damage > 10:
                    warnings.append(f"Weapon '{name}' damage {damage} outside typical range 0-10")
            except (ValueError, TypeError):
                errors.append(f"Weapon '{name}' has non-numeric damage value")

        cooldown_elem = elem.find("cooldown")
        if cooldown_elem is not None:
            try:
                cooldown = float(cooldown_elem.text)
                if cooldown < 1 or cooldown > 30:
                    warnings.append(f"Weapon '{name}' cooldown {cooldown} outside typical range 1-30")
            except (ValueError, TypeError):
                errors.append(f"Weapon '{name}' has non-numeric cooldown value")

        power_elem = elem.find("power")
        if power_elem is not None:
            try:
                power = int(power_elem.text)
                if power < 0 or power > 5:
                    warnings.append(f"Weapon '{name}' power {power} outside typical range 0-5")
            except (ValueError, TypeError):
                errors.append(f"Weapon '{name}' has non-numeric power value")

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
