# Garden Actions README Storyboard

Purpose: a GitHub README visual that feels like a developer demo, not an enterprise deck. The story is: garden notes become reviewed traces, LogicPearl builds a local action artifact, and a new plant check returns the next action plus the rule that fired.

Rendered asset:

```text
docs/assets/garden-actions-demo.png
```

Render command:

```bash
python3 scripts/render_garden_demo_gif.py
```

The renderer reads the checked-in garden demo files and tries to capture real local CLI output before drawing the animation. It emits a high-quality APNG for the README and a GIF fallback.

## Tone

- Plain developer language.
- Journal notes first, artifact second.
- No claims that LogicPearl understands plants.
- No corporate funnel copy.

## Animation Frames

### 1. Notes become rows

Left side:

```text
Vera, succulent
- soil moisture read 12%
- had not been watered for a week
- used about 0.1 gallons
- perked up by morning
```

Right side:

```csv
soil_moisture_pct,days_since_watered,water_last_7_days_gallons,next_action
12%,7,0.10,water
42%,2,0.60,do_nothing
44%,2,0.55,fertilize
22%,6,0.20,repot
```

Caption: `Reviewed notes become normal trace rows.`

### 2. Build with one command

Terminal:

```bash
$ cd examples/demos/garden_actions
$ logicpearl build
Built action artifact garden_actions
  Rows 16
  Actions water, do_nothing, fertilize, repot
  Default action do_nothing
  Training parity 100.0%
  Artifact bundle /tmp/garden-actions
  Pearl IR /tmp/garden-actions/pearl.ir.json
```

Caption: `The demo config keeps the command short. LogicPearl generates readable feature metadata from the trace columns before discovery.`

### 3. Inspect the artifact

Terminal:

```text
$ logicpearl inspect
Action rules:
  1. water
     Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2
  2. fertilize
     Growth in the last 14 days at or above 2.2 and Leaf Paleness at or above 4.0
  3. repot
     Pot Crack above 0.0
  4. repot
     Root Crowding above 2.0
```

Caption: `The learned action policy is inspectable before anyone wires it into an app.`

### 4. Run today's plant check

Input:

```json
{
  "soil_moisture_pct": "14%",
  "days_since_watered": 6,
  "water_last_7_days_gallons": 0.12,
  "leaf_paleness_score": 1,
  "days_since_fertilized": 40,
  "growth_cm_last_14_days": 1.1,
  "root_crowding_score": 1,
  "pot_crack_count": 0
}
```

Output:

```text
$ logicpearl run today.json --explain
action: water
reason:
  - Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2
```

Caption: `Same input, same local answer, no tokens spent at runtime.`

## README Embed

Suggested alt text:

`LogicPearl garden demo: journal notes become reviewed traces, a local action artifact, and a deterministic next-action result.`
