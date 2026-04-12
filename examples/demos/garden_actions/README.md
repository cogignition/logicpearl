# Garden Actions Demo

This demo is the README-friendly version of the plant example.

Someone kept ordinary notes about what they tried with each plant and whether it helped. After review, those notes became normalized rows with measurements and a `next_action` column:

```csv
soil_moisture_pct,days_since_watered,water_last_7_days_gallons,leaf_paleness_score,days_since_fertilized,growth_cm_last_14_days,root_crowding_score,pot_crack_count,next_action
12%,7,0.10,1,40,1.2,1,0,water
42%,2,0.60,1,16,2.5,1,0,do_nothing
44%,2,0.55,5,45,3.1,2,0,fertilize
22%,6,0.20,2,24,1.2,5,0,repot
```

Build the action artifact from this directory:

```bash
logicpearl build
```

Run today's plant check:

```bash
logicpearl run today.json --explain
```

Expected shape:

```text
action: water
reason:
  - Soil Moisture at or below 18% and Water used in the last 7 days at or below 0.2
```

The feature dictionary is generated during `logicpearl build` from the trace column names. The build emits one action policy artifact with action-labeled rules. The point is not that LogicPearl knows plants. The point is that reviewed examples can become a small deterministic artifact that returns a next action and a reason.
