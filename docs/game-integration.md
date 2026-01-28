# Game Integration

How generated mod content integrates with FTL's game systems.

## Weapons, Drones, Augments

These are added to FTL's global blueprint pools and **will appear in stores** during gameplay.

**Rarity system (0-5):**
- `0-1`: Common, appears frequently
- `2-3`: Uncommon, moderate appearance
- `4-5`: Rare, seldom appears

The LLM assigns rarity based on item power level. You'll find generated items mixed in with vanilla items at stores.

## Crew Races

Custom crew races are defined but **require additional work** to appear:
- Won't spawn on enemy ships automatically
- Won't appear in crew hiring events
- Need manual integration with crew spawn pools

## Events

**Important limitation:** Events are defined but **won't trigger automatically**.

Generated events are added to a mod-specific event list:

```xml
<eventList name="MYMOD_EVENTS">
  <event load="CUSTOM_EVENT_1"/>
  <event load="CUSTOM_EVENT_2"/>
</eventList>
```

However, FTL events must be hooked into sectors to appear. This requires modifying sector definitions:

```xml
<!-- NOT generated - would need to be added manually -->
<sectorDescription name="CIVILIAN">
  <event name="MYMOD_EVENTS" min="1" max="2"/>
</sectorDescription>
```

### Why events aren't auto-hooked

Modifying sector definitions:
- Risks conflicts with other mods
- Can break game balance if done incorrectly
- Requires knowledge of which sectors fit the theme

### Workarounds

1. **Manual sector hooks** - Edit the generated mod to add sector references
2. **Append to vanilla lists** - Add events to existing lists like `DISTRESS_BEACON` or `PIRATE`
3. **Use Hyperspace** - Advanced modding framework with better event injection

## Ships

Ship blueprints are generated but **require layout files** to be playable:
- `shipname.txt` - Room layout
- `shipname.xml` - Room definitions
- Ship sprites (hull, cloak, shields, gibs)

The generator creates the blueprint XML only. Full ship integration requires Superluminal 2 or manual layout creation.

## Sprites

Weapon sprites are generated via Google Gemini and formatted as 12-frame sprite sheets. These work automatically - weapons will display custom visuals in-game.

Drone, augment, crew, and ship sprites are **not generated** and will use placeholder/vanilla visuals.
