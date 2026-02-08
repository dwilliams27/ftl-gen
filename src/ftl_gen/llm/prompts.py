"""Prompt templates for FTL mod generation."""

import json

from ftl_gen.constants import get_balance_ranges
from ftl_gen.data.loader import load_vanilla_reference


def _ranges():
    """Get balance ranges lazily to avoid import-time loading issues."""
    return get_balance_ranges()


VANILLA_REFERENCE = load_vanilla_reference()

SYSTEM_PROMPT = """You are an expert FTL: Faster Than Light mod creator. You have deep knowledge of:
- FTL game mechanics, balance, and XML modding structure
- Creating engaging events with meaningful choices
- Designing weapons that are balanced yet interesting
- Crafting cohesive themed content that fits FTL's universe

When creating mod content:
1. Maintain FTL's tone - serious sci-fi with dark humor
2. Balance content to be fun but not overpowered
3. Create meaningful choices in events with real consequences
4. Use UPPERCASE_WITH_UNDERSCORES for all blueprint names
5. Keep descriptions concise but evocative

Reference vanilla balance:
- Weapons: 1-4 power, 0-120 scrap cost, 4-40 second cooldown
- Most weapons deal 1-3 damage per shot
- Higher damage weapons have longer cooldowns and higher power costs
- Rare/powerful weapons have rarity 4-5, common ones have rarity 0-2"""


def mod_concept_prompt(theme: str) -> str:
    """Prompt to expand a mod concept."""
    return f"""Expand this FTL mod concept into a detailed design:

Theme/Concept: {theme}

Create a cohesive mod design that includes:
1. A faction/theme name and brief lore (2-3 sentences)
2. 3 unique weapon concepts that fit the theme
3. 2 drone concepts that fit the theme
4. 1-2 augment concepts
5. 3-5 event encounters that could happen with this faction
6. Any special crew abilities that would enhance the theme

Focus on creating content that:
- Fits FTL's serious sci-fi tone
- Offers interesting gameplay decisions
- Is balanced relative to vanilla content
- Has internal consistency within the theme

Return your response as a JSON object with this structure:
{{
    "name": "Mod Name",
    "description": "Brief mod description",
    "lore": "2-3 sentences of faction background",
    "weapon_concepts": [
        {{"name": "WEAPON_NAME", "type": "LASER|BEAM|MISSILES|BOMB|ION (ion weapons are LASER subtype)", "concept": "Brief description", "visual": "Visual description for sprite"}}
    ],
    "drone_concepts": [
        {{"name": "DRONE_NAME", "type": "COMBAT|DEFENSE|REPAIR|BOARDER", "concept": "Brief description"}}
    ],
    "augment_concepts": [
        {{"name": "AUGMENT_NAME", "concept": "Brief description of effect"}}
    ],
    "event_concepts": [
        {{"name": "EVENT_NAME", "summary": "Brief event summary", "choices": ["choice 1 summary", "choice 2 summary"]}}
    ],
    "crew_concepts": [
        {{"name": "race_name", "concept": "Brief description of abilities and traits"}}
    ],
    "special_mechanics": ["mechanic 1", "mechanic 2"]
}}"""


def weapons_prompt(theme: str, concepts: list[dict], count: int = 3) -> str:
    """Prompt to generate weapon blueprints."""
    _wr = _ranges()["weapon"]
    # Show a few LASER weapons as examples from the flat dict
    weapons = VANILLA_REFERENCE.get("weapons", {})
    laser_examples = {k: v for k, v in weapons.items()
                      if v.get("type") == "LASER" and not v.get("noloc")}
    # Limit to 5 examples
    laser_examples = dict(list(laser_examples.items())[:5])
    vanilla_examples = json.dumps(laser_examples, indent=2)

    concepts_text = "\n".join(
        f"- {c['name']}: {c.get('concept', c.get('description', 'No description'))}"
        for c in concepts[:count]
    )

    return f"""Generate {count} detailed weapon blueprints for an FTL mod with this theme:

Theme: {theme}

Weapon concepts to develop:
{concepts_text}

Reference - vanilla laser weapons for balance:
{vanilla_examples}

For each weapon, generate a complete blueprint with:
- name: UPPERCASE_WITH_UNDERSCORES (e.g., PLASMA_BURST_LASER)
- type: One of LASER, BEAM, MISSILES, BOMB, ION
- title: Display name (e.g., "Plasma Burst Laser")
- desc: 1-2 sentence description for the player (SEE DESCRIPTION RULES BELOW)
- damage: {_wr["damage"][0]}-{_wr["damage"][1]} (most weapons: 1-3)
- shots: {_wr["shots"][0]}-{_wr["shots"][1]} (for LASER/BURST/ION)
- fireChance: {_wr["fireChance"][0]}-{_wr["fireChance"][1]} (10 = 100% fire chance)
- breachChance: {_wr["breachChance"][0]}-{_wr["breachChance"][1]} (10 = 100% breach chance)
- cooldown: 8-25 seconds (higher damage = longer cooldown)
- power: {_wr["power"][0]}-{_wr["power"][1]} (most weapons: 1-3)
- cost: {_wr["cost"][0]}-{_wr["cost"][1]} scrap (scale with power/usefulness)
- rarity: {_wr["rarity"][0]}-{_wr["rarity"][1]} (0=common, 5=very rare)

Special fields (include only if relevant):
- ion: {_wr["ion"][0]}-{_wr["ion"][1]} (for ION weapons)
- missiles: {_wr["missiles"][0]}-{_wr["missiles"][1]} (for MISSILES/BOMB)
- length: {_wr["length"][0]}-{_wr["length"][1]} (for BEAM weapons, in pixels)
- sp: {_wr["sp"][0]}-{_wr["sp"][1]} (shield piercing)
- persDamage: {_wr["persDamage"][0]}-{_wr["persDamage"][1]} (crew damage)
- sysDamage: {_wr["sysDamage"][0]}-{_wr["sysDamage"][1]} (bonus system damage)
- hullBust: true (bonus hull damage)
- stun: {_wr["stun"][0]}-{_wr["stun"][1]} (stun duration)
- lockdown: true (crystal lockdown)

CRITICAL - DESCRIPTION RULES:
The "desc" field MUST only describe effects that are mechanically implemented by the stats above.
- DO NOT invent mechanics that don't exist (healing, repair, probability-based special effects, damage over time, chain reactions, etc.)
- DO NOT describe percentage chances for effects not in the stats (only fireChance and breachChance exist)
- The description should accurately reflect what the weapon ACTUALLY DOES based on its stats
- Good: "Fires 3 laser shots. High fire chance." (matches stats: shots=3, fireChance=7)
- Bad: "30% chance to spawn repair nanobots" (this mechanic doesn't exist)
- Flavor text is fine, but mechanical claims must match the actual stats

Return a JSON object:
{{"items": [weapon1, weapon2, weapon3]}}"""


def events_prompt(theme: str, concepts: list[dict], count: int = 5) -> str:
    """Prompt to generate event blueprints."""
    concepts_text = "\n".join(
        f"- {c.get('name', 'EVENT')}: {c.get('summary', c.get('description', 'No description'))}"
        for c in concepts[:count]
    )

    return f"""Generate {count} detailed event blueprints for an FTL mod with this theme:

Theme: {theme}

Event concepts to develop:
{concepts_text}

For each event, generate:
- name: UPPERCASE_WITH_UNDERSCORES (e.g., FACTION_DERELICT_SHIP)
- text: 2-4 sentences describing the encounter (what the player sees)
- unique: true/false (can only happen once per run)
- choices: array of player choices

Each choice needs:
- text: What the player chooses (e.g., "Attack the ship.")
- req: Optional requirement ("human", "engi", "weapons", etc.)
- hidden: true if choice should be hidden when requirements not met
- event: The outcome object

Outcome objects have:
- text: 1-3 sentences describing what happens
- Rewards/penalties (optional):
  - scrap: -100 to 100
  - fuel: -10 to 10
  - missiles: -10 to 10
  - hull: -15 to 15 (negative = damage, positive = repair)
- Items (optional): weapon, drone, augment (blueprint name)
- addCrew: crew race to add ("human", "engi", etc.)
- removeCrew: true to lose a crew member
- damageSystem: system name, damageAmount: 1-5

CRITICAL - EVENT STRUCTURE RULES:
- NEVER create circular event references. Event A must not chain to Event B if B chains back to A.
- Self-referencing events (A loads A) will freeze the game.
- Every <choice> MUST have an <event> outcome with at least a <text> element. Missing outcomes crash the game.

Create events with:
1. 2-4 meaningful choices each
2. Risk/reward tradeoffs
3. Some choices that require specific crew or systems
4. Consequences that feel fair and make sense
5. FTL's tone - serious with occasional dark humor

Return a JSON object:
{{"items": [event1, event2, ...]}}"""


def single_weapon_prompt(description: str) -> str:
    """Prompt to generate a single weapon."""
    _wr = _ranges()["weapon"]
    weapons = VANILLA_REFERENCE.get("weapons", {})
    laser_examples = {k: v for k, v in weapons.items()
                      if v.get("type") == "LASER" and not v.get("noloc")}
    laser_examples = dict(list(laser_examples.items())[:5])
    vanilla_examples = json.dumps(laser_examples, indent=2)

    return f"""Create a detailed FTL weapon blueprint based on this description:

{description}

Reference - vanilla laser weapons for balance:
{vanilla_examples}

Generate a complete blueprint with:
- name: UPPERCASE_WITH_UNDERSCORES (e.g., GRAVITY_BEAM)
- type: One of LASER, BEAM, MISSILES, BOMB, ION
- title: Display name
- desc: 1-2 sentence player-facing description (SEE RULES BELOW)
- damage: {_wr["damage"][0]}-{_wr["damage"][1]}
- shots: {_wr["shots"][0]}-{_wr["shots"][1]} (for LASER/BURST/ION)
- fireChance: {_wr["fireChance"][0]}-{_wr["fireChance"][1]}
- breachChance: {_wr["breachChance"][0]}-{_wr["breachChance"][1]}
- cooldown: 8-25 seconds
- power: {_wr["power"][0]}-{_wr["power"][1]}
- cost: {_wr["cost"][0]}-{_wr["cost"][1]} scrap
- rarity: {_wr["rarity"][0]}-{_wr["rarity"][1]}

Include special fields only if relevant to the weapon concept:
- ion, missiles, length, sp, persDamage, sysDamage, hullBust, stun, lockdown

CRITICAL - DESCRIPTION RULES:
The "desc" field MUST only describe effects implemented by the stats above.
- DO NOT invent mechanics that don't exist (healing, repair, probability-based special effects, etc.)
- The description must accurately reflect what the weapon ACTUALLY DOES
- Flavor text about appearance/lore is fine, but mechanical claims must match stats

Return ONLY the weapon object as JSON (not wrapped in an array)."""


def single_event_prompt(description: str) -> str:
    """Prompt to generate a single event."""
    return f"""Create a detailed FTL event blueprint based on this description:

{description}

Generate an event with:
- name: UPPERCASE_WITH_UNDERSCORES
- text: 2-4 sentences describing the encounter
- unique: true/false
- choices: 2-4 meaningful player choices

Each choice needs:
- text: The choice text
- req: Optional requirement
- hidden: true/false
- event: Outcome with text and effects

Create an event with:
- Meaningful choices with different risk/reward profiles
- At least one choice requiring a crew type or system
- Outcomes that feel fair and consequential
- FTL's tone - serious sci-fi with occasional dark humor

Return ONLY the event object as JSON (not wrapped in an array)."""


def visual_description_prompt(weapon_name: str, weapon_type: str, description: str) -> str:
    """Prompt to get visual description for sprite generation."""
    return f"""Describe the visual appearance of this FTL weapon for pixel art sprite creation:

Weapon: {weapon_name}
Type: {weapon_type}
Description: {description}

Describe in 2-3 sentences:
1. The weapon's shape and silhouette (for a 16x60 pixel sprite)
2. Key visual features and details
3. Color palette (2-3 main colors)

Keep it simple - pixel art at this scale can only show basic shapes and a few colors.
Focus on making it visually distinct and recognizable.

Return ONLY a brief visual description, no JSON."""


def drones_prompt(theme: str, concepts: list[dict], count: int = 2) -> str:
    """Prompt to generate drone blueprints."""
    _dr = _ranges()["drone"]
    concepts_text = "\n".join(
        f"- {c.get('name', 'DRONE')}: {c.get('concept', c.get('description', 'No description'))}"
        for c in concepts[:count]
    )

    return f"""Generate {count} detailed drone blueprints for an FTL mod with this theme:

Theme: {theme}

Drone concepts to develop:
{concepts_text}

For each drone, generate a complete blueprint with:
- name: UPPERCASE_WITH_UNDERSCORES (e.g., PLASMA_COMBAT_DRONE)
- type: One of COMBAT, DEFENSE, SHIP_REPAIR, BOARDER, REPAIR, BATTLE, HACKING
- title: Display name (e.g., "Plasma Combat Drone")
- desc: 1-2 sentence description for the player
- power: {_dr["power"][0]}-{_dr["power"][1]} (power bars required)
- cost: {_dr["cost"][0]}-{_dr["cost"][1]} scrap
- rarity: {_dr["rarity"][0]}-{_dr["rarity"][1]} (0=common, 5=very rare)

For COMBAT/BATTLE drones, also include:
- cooldown: {_dr["cooldown"][0]}-{_dr["cooldown"][1]} (attack cooldown)
- speed: {_dr["speed"][0]}-{_dr["speed"][1]} (movement speed)

Drone type guidelines:
- COMBAT: Attacks enemy ship systems
- DEFENSE: Shoots down incoming projectiles
- SHIP_REPAIR: Repairs your hull over time
- BOARDER: Teleports to enemy ship to fight crew
- REPAIR: Repairs your systems (internal)
- BATTLE: Fights enemy crew on your ship
- HACKING: Disables enemy systems

CRITICAL - DESCRIPTION RULES:
The "desc" field MUST only describe what the drone type actually does.
- DO NOT invent mechanics beyond the drone type's standard behavior
- A COMBAT drone attacks systems - don't claim it "has 30% chance to disable shields permanently"
- A DEFENSE drone shoots projectiles - don't claim it "heals crew" or "repairs hull"
- Describe the drone's theme/appearance, but mechanical claims must match the type
- Flavor text is fine, but don't invent special abilities

Return a JSON object:
{{"items": [drone1, drone2, ...]}}"""


def augments_prompt(theme: str, concepts: list[dict], count: int = 2) -> str:
    """Prompt to generate augment blueprints."""
    _ar = _ranges()["augment"]
    concepts_text = "\n".join(
        f"- {c.get('name', 'AUGMENT')}: {c.get('concept', c.get('description', 'No description'))}"
        for c in concepts[:count]
    )

    return f"""Generate {count} detailed augment blueprints for an FTL mod with this theme:

Theme: {theme}

Augment concepts to develop:
{concepts_text}

For each augment, generate a complete blueprint with:
- name: UPPERCASE_WITH_UNDERSCORES (e.g., PLASMA_CAPACITOR)
- title: Display name (e.g., "Plasma Capacitor")
- desc: 1-2 sentence description explaining the effect
- cost: {_ar["cost"][0]}-{_ar["cost"][1]} scrap
- rarity: {_ar["rarity"][0]}-{_ar["rarity"][1]} (0=common, 5=very rare)
- stackable: true/false (can player have multiple?)
- value: numeric effect value if applicable (e.g., 0.15 for 15% bonus)

Augment design guidelines:
- Should provide a passive bonus or ability
- Effects should be meaningful but not overpowered
- Consider synergies with the theme's weapons/drones
- Value typically ranges from 0.1 to 0.5 for percentage bonuses

CRITICAL - DESCRIPTION RULES:
Augments in vanilla FTL have LIMITED mechanical effects. The "desc" should reflect realistic augment behavior:
- Percentage bonuses (evasion, damage, speed, etc.) - use the "value" field
- Passive effects (reveal map, auto-repair, drone recovery, etc.)
- DO NOT claim effects that require active player control or complex triggers
- Keep descriptions vague about exact mechanics, or describe in terms of vanilla augment effects
- Example good: "Improves weapon charge speed" (maps to value for weapon cooldown reduction)
- Example bad: "Every third jump, gain 50 scrap" (no such mechanic exists)

Return a JSON object:
{{"items": [augment1, augment2, ...]}}"""


def crew_prompt(theme: str, concepts: list[dict], count: int = 1) -> str:
    """Prompt to generate crew race blueprints."""
    _cr = _ranges()["crew"]
    crew_races = VANILLA_REFERENCE.get("crew_races", [])

    concepts_text = "\n".join(
        f"- {c.get('name', 'crew')}: {c.get('concept', c.get('description', 'No description'))}"
        for c in concepts[:count]
    )

    return f"""Generate {count} detailed crew race blueprint(s) for an FTL mod with this theme:

Theme: {theme}

Crew concepts to develop:
{concepts_text}

Existing vanilla races for reference: {', '.join(crew_races)}

For each crew race, generate a complete blueprint with:
- name: lowercase_with_underscores (e.g., plasma_being)
- title: Display name (e.g., "Plasma Being")
- desc: 2-3 sentence description of the race
- cost: {_cr["cost"][0]}-{_cr["cost"][1]} scrap (cost to hire)

Stats (100 = human baseline, range {_cr["maxHealth"][0]}-{_cr["maxHealth"][1]}):
- maxHealth: {_cr["maxHealth"][0]}-{_cr["maxHealth"][1]} (health points)
- moveSpeed: {_cr["moveSpeed"][0]}-{_cr["moveSpeed"][1]} (movement speed)
- repairSpeed: {_cr["repairSpeed"][0]}-{_cr["repairSpeed"][1]} (system repair speed)
- damageMultiplier: {_cr["damageMultiplier"][0]}-{_cr["damageMultiplier"][1]} (combat damage multiplier)
- fireRepair: {_cr["fireRepair"][0]}-{_cr["fireRepair"][1]} (fire extinguishing speed)
- suffocationModifier: {_cr["suffocationModifier"][0]}-{_cr["suffocationModifier"][1]} (oxygen consumption, 0 = doesn't need oxygen)

Special abilities (true/false):
- canFight: Can engage in combat (default true)
- canRepair: Can repair systems (default true)
- canMan: Can operate stations (default true)
- canSuffocate: Needs oxygen (default true)
- canBurn: Takes fire damage (default true)
- providePower: Provides power to occupied room (like Zoltan)

Design guidelines:
- Each race should have 1-2 clear strengths and 1-2 weaknesses
- Stats should feel distinct from existing races
- Abilities should fit the theme logically
- Consider gameplay implications (boarding, repair, piloting)

Return a JSON object:
{{"items": [crew1, ...]}}"""


def single_drone_prompt(description: str) -> str:
    """Prompt to generate a single drone."""
    _dr = _ranges()["drone"]
    return f"""Create a detailed FTL drone blueprint based on this description:

{description}

Generate a complete blueprint with:
- name: UPPERCASE_WITH_UNDERSCORES
- type: One of COMBAT, DEFENSE, SHIP_REPAIR, BOARDER, REPAIR, BATTLE, HACKING
- title: Display name
- desc: 1-2 sentence player-facing description
- power: {_dr["power"][0]}-{_dr["power"][1]}
- cost: {_dr["cost"][0]}-{_dr["cost"][1]} scrap
- rarity: {_dr["rarity"][0]}-{_dr["rarity"][1]}

For combat-type drones, include cooldown ({_dr["cooldown"][0]}-{_dr["cooldown"][1]}) and speed ({_dr["speed"][0]}-{_dr["speed"][1]}).

Return ONLY the drone object as JSON (not wrapped in an array)."""


def single_augment_prompt(description: str) -> str:
    """Prompt to generate a single augment."""
    _ar = _ranges()["augment"]
    return f"""Create a detailed FTL augment blueprint based on this description:

{description}

Generate a complete blueprint with:
- name: UPPERCASE_WITH_UNDERSCORES
- title: Display name
- desc: 1-2 sentence description explaining the effect
- cost: {_ar["cost"][0]}-{_ar["cost"][1]} scrap
- rarity: {_ar["rarity"][0]}-{_ar["rarity"][1]}
- stackable: true/false
- value: numeric effect value if applicable

Return ONLY the augment object as JSON (not wrapped in an array)."""


def single_crew_prompt(description: str) -> str:
    """Prompt to generate a single crew race."""
    _cr = _ranges()["crew"]
    return f"""Create a detailed FTL crew race blueprint based on this description:

{description}

Generate a complete blueprint with:
- name: lowercase_with_underscores
- title: Display name
- desc: 2-3 sentence race description
- cost: {_cr["cost"][0]}-{_cr["cost"][1]} scrap

Stats (100 = human baseline):
- maxHealth: {_cr["maxHealth"][0]}-{_cr["maxHealth"][1]}
- moveSpeed: {_cr["moveSpeed"][0]}-{_cr["moveSpeed"][1]}
- repairSpeed: {_cr["repairSpeed"][0]}-{_cr["repairSpeed"][1]}
- damageMultiplier: {_cr["damageMultiplier"][0]}-{_cr["damageMultiplier"][1]}
- fireRepair: {_cr["fireRepair"][0]}-{_cr["fireRepair"][1]}
- suffocationModifier: {_cr["suffocationModifier"][0]}-{_cr["suffocationModifier"][1]}

Abilities (include only non-default values):
- canFight, canRepair, canMan, canSuffocate, canBurn, providePower

The race should have clear strengths and weaknesses.

Return ONLY the crew object as JSON (not wrapped in an array)."""


def single_ship_prompt(description: str) -> str:
    """Prompt to generate a single ship blueprint."""
    systems = VANILLA_REFERENCE.get("systems", [])

    return f"""Create a detailed FTL ship blueprint based on this description:

{description}

Available systems: {', '.join(systems)}

Generate a complete blueprint with:
- name: UPPERCASE_WITH_UNDERSCORES (e.g., STEALTH_CRUISER_A)
- layout: layout file name (use same as name, lowercase)
- img: ship image name (use same as name, lowercase)
- class: Ship class name (e.g., "Stealth Cruiser")
- name_: Default ship name (e.g., "The Nightingale")
- desc: 2-3 sentence ship description

Systems (level 0 = not installed, 1+ = starting level):
- shields: 0-4 (each level = 1 shield bubble)
- engines: 1-4
- oxygen: 1-2
- weapons: 1-4 (weapon slots)
- drones: 0-3 (drone slots, 0 = no drone system)
- medbay: 0-2 (0 if using clonebay)
- clonebay: 0-2 (0 if using medbay)
- teleporter: 0-2
- cloaking: 0-2
- hacking: 0-2
- mind: 0-2 (mind control)
- battery: 0-2
- pilot: 1-2
- sensors: 1-2
- doors: 1-2

Resources:
- maxPower: 8-16 (starting reactor power)
- maxHull: 25-35 (hull points)
- maxCrew: 4-8 (crew capacity)
- missiles: 0-20
- droneParts: 0-15

Starting equipment (use UPPERCASE blueprint names):
- weaponsList: ["WEAPON_1", "WEAPON_2"] (up to weapon level slots)
- dronesList: ["DRONE_1"] (up to drone level slots)
- augments: ["AUGMENT_1"]
- crew: ["human", "human", "engi"] (race names)

Ship design guidelines:
- Total system levels should feel balanced (compare to vanilla ships)
- Weapons should match the weapon system level
- Crew count should not exceed maxCrew
- Consider the ship's playstyle (aggressive, defensive, boarding, stealth)

Return ONLY the ship object as JSON (not wrapped in an array)."""
