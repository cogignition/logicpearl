use pearl_runtime::ir::LogicPearlGateIr;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::fs;

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: pearl-runtime <pearl.ir.json> <input.json>".into());
    }

    let gate = LogicPearlGateIr::from_path(&args[1])?;
    let content = fs::read_to_string(&args[2])?;
    let payload: Value = serde_json::from_str(&content)?;

    match payload {
        Value::Object(object) => {
            let input = object_to_features(&object);
            let bitmask = gate.evaluate(&input)?;
            println!("{bitmask}");
        }
        Value::Array(items) => {
            let mut bitmasks = Vec::with_capacity(items.len());
            for item in items {
                let object = item
                    .as_object()
                    .ok_or("input JSON array must contain only feature objects")?;
                let input = object_to_features(object);
                let bitmask = gate.evaluate(&input)?;
                bitmasks.push(bitmask);
            }
            println!("{}", serde_json::to_string(&bitmasks)?);
        }
        _ => {
            return Err("input JSON must be an object or an array of objects mapping feature names to values".into());
        }
    }
    Ok(())
}

fn object_to_features(object: &serde_json::Map<String, Value>) -> HashMap<String, Value> {
    let mut features = HashMap::new();
    for (key, value) in object {
        features.insert(key.clone(), value.clone());
    }
    features
}
