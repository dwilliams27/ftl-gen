# Game Integration

How generated mod content integrates with FTL's game systems. See [xml-modding-limits.md](xml-modding-limits.md) for a detailed breakdown of what XML patching can and can't do.

## Weapons

Weapons are **fully data-driven** and work exactly like vanilla weapons. Custom weapons appear in stores, can be purchased, equipped, and fired with correct stats and visuals.

All stats are respected: type, damage, cooldown, power, cost, rarity, shots, fire chance, breach chance, ion damage, beam length, missile cost.

## Drones

Drones are **fully data-driven** and appear in stores alongside vanilla drones. All stats are respected: type, power, cost, cooldown, speed, rarity.

## Augments (cosmetic only)

**Custom augments have no mechanical effect.** FTL hardcodes augment effects in the binary, keyed by internal `name`. A custom augment like `TRIFORCE_RESONATOR` will appear in stores and can be purchased, but does nothing — the binary doesn't recognize the name.

The **only XML-only workaround** is reskinning a vanilla augment: keep the internal `name` (e.g. `SCRAP_COLLECTOR`), change the `title`, `desc`, and `cost`. The vanilla effect still fires.

See [xml-modding-limits.md](xml-modding-limits.md#what-is-cosmetic-only-augments) for full details and [deep-modding-research.md](deep-modding-research.md) for investigation approaches.

**Rarity system (0-5) for weapons, drones, and augments:**
- `0-1`: Common, appears frequently
- `2-3`: Uncommon, moderate appearance
- `4-5`: Rare, seldom appears

The LLM assigns rarity based on item power level. Generated items appear mixed in with vanilla items at stores.

## Crew Races

Custom crew races are defined but **require additional work** to appear:
- Stats work (health, speed, repair, damage) when crew is placed on a ship
- Won't spawn on enemy ships automatically (spawn pools are hardcoded)
- Won't appear in crew hiring events (hiring pools are hardcoded)
- Need manual integration or custom events to make accessible

## Events

**Important:** Events are generated but **not patched into the game** — they cause FTL to freeze at "Blueprints Loaded!" when included in the mod.

The guard is in `ModBuilder._write_xml_files()` (`core/mod_builder.py`). Set `PATCH_EVENTS=1` env var to re-enable for testing.

Events still appear in the UI (ModDetail events tab, XML tab) for review.

### Why events don't work yet

The freeze root cause is unknown. FTL events must be hooked into sector definitions to trigger:

```xml
<!-- NOT generated — would need to be added manually -->
<sectorDescription name="CIVILIAN">
  <event name="MYMOD_EVENTS" min="1" max="2"/>
</sectorDescription>
```

Even if the freeze is fixed, auto-hooking events into sectors is non-trivial:
- Risks conflicts with other mods
- Can break game balance if done incorrectly
- Requires knowledge of which sectors fit the theme

### Workarounds

1. **Manual sector hooks** — Edit the generated mod to add sector references (needs freeze fix first)
2. **Append to vanilla lists** — Add events to existing lists like `DISTRESS_BEACON` or `PIRATE`
3. **Use Hyperspace** — Advanced modding framework with better event injection
4. **DYLD interception** — Intercept sector data loading to inject event references at runtime (see [deep-modding-research.md](deep-modding-research.md))

## Ships

Ship blueprints are generated but **require layout files** to be playable:
- `shipname.txt` — Room layout grid
- `shipname.xml` — Room definitions
- Ship sprites (hull, cloak, shields, gibs)

The generator creates the blueprint XML only. Full ship integration requires Superluminal 2 or manual layout creation.

## Sprites

**Weapon sprites** are generated via Google Gemini and formatted as 12-frame sprite sheets (16x60 pixels per frame). These work automatically — weapons display custom visuals in-game.

**Drone sprites** are generated via Gemini as 64x64 body images placed in `img/ship/drones/`. Drones display the custom body image in-game.

Augment, crew, and ship sprites are **not generated** and will use placeholder/vanilla visuals.
