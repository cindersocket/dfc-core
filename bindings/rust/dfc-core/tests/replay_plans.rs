//! Replays every DESFire conformance vector through the Rust binding.
//!
//! The plans under `tests/replay-plans` come from the C conformance runner
//! (`make -C tests replay-plans`): the initial credential in the library's own
//! encoding, then explicit steps. This test only replays them, so the binding is
//! held to the same expectations as the C engine.
#![cfg(not(feature = "role-target"))]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use dfc_core::{Credential, Error, VirtualPicc};

#[derive(Default)]
struct Plan {
    name: String,
    credential: Vec<u8>,
    finite_random: bool,
    skip: Option<String>,
    steps: Vec<Vec<String>>,
    final_credential: Vec<u8>,
}

fn parse_hex(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("plan hex"))
        .collect()
}

fn parse_plan(path: &Path) -> Plan {
    let mut plan = Plan {
        name: path.file_stem().unwrap().to_string_lossy().into_owned(),
        ..Plan::default()
    };
    for line in fs::read_to_string(path).unwrap().lines() {
        let (key, rest) = line.split_once(' ').unwrap_or((line, ""));
        match key {
            "credential" => plan.credential = parse_hex(rest),
            "random" => plan.finite_random = rest == "finite",
            "skip" => plan.skip = Some(rest.to_owned()),
            "step" => plan
                .steps
                .push(rest.split(' ').map(str::to_owned).collect()),
            "final" => plan.final_credential = parse_hex(rest),
            "plan" | "source" => {}
            _ => panic!("{}: unknown plan line {line:?}", plan.name),
        }
    }
    plan
}

/// Compares with `??` wildcards and `tol=offset+length:delta` clauses.
fn matches(actual: &[u8], expected: &str, tolerances: &[String]) -> bool {
    let want: Vec<&str> = if expected == "-" {
        Vec::new()
    } else {
        (0..expected.len())
            .step_by(2)
            .map(|index| &expected[index..index + 2])
            .collect()
    };
    if actual.len() != want.len() {
        return false;
    }
    let ranges: Vec<(usize, usize, u64)> = tolerances
        .iter()
        .map(|clause| {
            let (span, delta) = clause.trim_start_matches("tol=").split_once(':').unwrap();
            let (offset, length) = span.split_once('+').unwrap();
            (
                offset.parse().unwrap(),
                length.parse().unwrap(),
                delta.parse().unwrap(),
            )
        })
        .collect();
    let tolerated = |index: usize| {
        ranges
            .iter()
            .any(|&(offset, length, _)| index >= offset && index < offset + length)
    };
    for (index, token) in want.iter().enumerate() {
        if !tolerated(index)
            && *token != "??"
            && actual[index] != u8::from_str_radix(token, 16).unwrap()
        {
            return false;
        }
    }
    let little_endian = |bytes: &[u8]| {
        bytes
            .iter()
            .rev()
            .fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
    };
    ranges.iter().all(|&(offset, length, delta)| {
        let got = little_endian(&actual[offset..offset + length]);
        let expect = little_endian(&parse_hex(&expected[2 * offset..2 * (offset + length)]));
        got.abs_diff(expect) <= delta
    })
}

fn is_random_failure(error: &Error) -> bool {
    matches!(error, Error::RandomSourceFailed)
}

/// Returns failures, assertions evaluated, and assertions left to the final comparison.
fn replay(plan: &Plan) -> (Vec<String>, usize, usize) {
    let queue = Arc::new(Mutex::new(Vec::<u8>::new()));
    let source = Arc::clone(&queue);
    let credential = Credential::decode(&plan.credential).expect("plan credential decodes");
    let mut picc = if plan.finite_random {
        VirtualPicc::from_credential_with_random(credential, move |count| {
            let mut queued = source.lock().unwrap();
            if queued.len() < count {
                // A draw the queue cannot satisfy fails without consuming bytes.
                return Vec::new();
            }
            queued.drain(..count).collect()
        })
    } else {
        VirtualPicc::from_credential(credential)
    }
    .expect("virtual card");
    let mut failures = Vec::new();
    let (mut checked, mut unchecked) = (0, 0);
    let mut activation = None;
    for (index, step) in plan.steps.iter().enumerate() {
        let where_ = format!("{} step {} ({})", plan.name, index + 1, step[0]);
        let args = &step[1..];
        match step[0].as_str() {
            "scan" => match picc.activate() {
                Ok(value) => activation = Some(value),
                Err(error) => failures.push(format!("{where_}: {error:?}")),
            },
            "field-off" => {
                activation = None;
                if let Err(error) = picc.field_off() {
                    failures.push(format!("{where_}: {error:?}"));
                }
            }
            "clear-dirty" => picc.mark_persisted().expect("mark persisted"),
            "random-clear" => queue.lock().unwrap().clear(),
            "random-inject" => queue.lock().unwrap().extend(parse_hex(&args[0])),
            "advance-time" => picc
                .advance_time(args[0].parse().unwrap())
                .expect("advance time"),
            "exchange" | "frame" => {
                let request = parse_hex(&args[0]);
                let result = if step[0] == "exchange" {
                    picc.exchange(&request)
                } else {
                    picc.frame_exchange(&request)
                };
                match result {
                    Ok(actual) if matches(&actual, &args[1], &args[2..]) => {}
                    Ok(actual) => failures.push(format!(
                        "{where_}: expected {} got {}",
                        args[1],
                        actual
                            .iter()
                            .map(|byte| format!("{byte:02X}"))
                            .collect::<String>()
                    )),
                    Err(error) => failures.push(format!("{where_}: {error:?}")),
                }
            }
            "error" => {
                let random = args[0] == "random-source";
                let before = queue.lock().unwrap().len();
                let result = match args[1].as_str() {
                    "scan" => picc.activate().map(|_| Vec::new()),
                    "exchange" => picc.exchange(&parse_hex(&args[2])),
                    _ => picc.frame_exchange(&parse_hex(&args[2])),
                };
                match result {
                    Ok(_) => failures.push(format!("{where_}: expected an error")),
                    Err(error) if is_random_failure(&error) != random => {
                        failures.push(format!("{where_}: wrong error class {error:?}"));
                    }
                    Err(_) => {}
                }
                if random && queue.lock().unwrap().len() != before {
                    failures.push(format!("{where_}: failed draw consumed random bytes"));
                }
                if random && args[1] == "scan" {
                    activation = None;
                }
            }
            "assert" => {
                let (path, value) = (args[0].as_str(), args[1].as_str());
                if path == "credential.dirty" {
                    checked += 1;
                    let dirty = picc.snapshot().expect("snapshot").is_dirty();
                    if u8::from(dirty) != value.parse::<u8>().unwrap() {
                        failures.push(format!("{where_}: {path} expected {value}"));
                    }
                } else if let (Some(field), Some(card)) =
                    (path.strip_prefix("activation."), activation.as_ref())
                {
                    checked += 1;
                    let card = &card.0;
                    let actual = match field {
                        "uid" => card.uid[..card.uid_len as usize]
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect(),
                        "atqa" => card.atqa[..card.atqa_len as usize]
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect(),
                        "ats" => card.ats[..card.ats_len as usize]
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect(),
                        "uid_len" => card.uid_len.to_string(),
                        "sak" => card.sak.to_string(),
                        _ => String::from("unsupported"),
                    };
                    let number = value.strip_prefix("0x").map_or_else(
                        || value.to_owned(),
                        |hex| u64::from_str_radix(hex, 16).unwrap().to_string(),
                    );
                    let want = if matches!(field, "uid_len" | "sak") {
                        number
                    } else {
                        value.to_owned()
                    };
                    if !actual.eq_ignore_ascii_case(&want) {
                        failures.push(format!("{where_}: {path} expected {value} got {actual}"));
                    }
                } else {
                    unchecked += 1;
                }
            }
            other => failures.push(format!("{where_}: unknown plan step {other}")),
        }
    }
    let exported = picc.export().expect("export").encode().expect("encode");
    if exported != plan.final_credential {
        failures.push(format!(
            "{}: final credential differs from the C engine",
            plan.name
        ));
    }
    (failures, checked, unchecked)
}

fn plans_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tests/replay-plans")
}

#[test]
fn vector_replay_plans_match_the_c_engine() {
    let mut paths: Vec<_> = fs::read_dir(plans_directory())
        .expect("replay plans; run make -C tests replay-plans")
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "plan")
        })
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no replay plans found");
    let mut failures = Vec::new();
    let mut skipped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let (mut replayed, mut checked, mut unchecked) = (0, 0, 0);
    for path in &paths {
        let plan = parse_plan(path);
        if let Some(reason) = plan.skip.clone() {
            skipped.entry(reason).or_default().push(plan.name);
            continue;
        }
        let (plan_failures, plan_checked, plan_unchecked) = replay(&plan);
        failures.extend(plan_failures);
        replayed += 1;
        checked += plan_checked;
        unchecked += plan_unchecked;
    }
    println!(
        "rust replay: {replayed} vectors replayed, {} skipped, {} failures; \
         {checked} assertions evaluated, {unchecked} left to the final credential comparison",
        skipped.values().map(Vec::len).sum::<usize>(),
        failures.len()
    );
    for (reason, names) in &skipped {
        println!("  skipped {}: {reason}: {}", names.len(), names.join(", "));
    }
    assert!(
        failures.is_empty(),
        "{}",
        failures[..failures.len().min(20)].join("\n")
    );
    // Exactly these plans are skipped (the plan files carry the reason), and every other plan
    // is replayed: a regression that skips more would otherwise pass.
    let expected_skips: Vec<&str> = vec![
        "v4-emulator-model_key_set_invariants",
        "v4-emulator-model_sdm_encrypted_range_overflow",
        "v4-emulator-vecb-ev1-create-file-full-pool",
    ];
    let mut actual_skips: Vec<String> = skipped.values().flatten().cloned().collect();
    actual_skips.sort();
    assert_eq!(actual_skips, expected_skips);
    assert_eq!(replayed, paths.len() - expected_skips.len());
}
