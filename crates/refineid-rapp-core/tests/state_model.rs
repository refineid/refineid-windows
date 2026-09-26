//! Transcription conformance: the transition tables against the vendored
//! machine-readable model.
//!
//! The specification's YAML model is the transition source (Section 14).
//! This test expands its list-valued `from` states and compares the exact
//! `(from, event, role, guard, to)` relation with the tables in
//! `states.rs`, in both directions, so a transcription slip in either
//! artifact fails loudly.

#![allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]

use std::collections::BTreeSet;
use std::fmt::Debug;

use refineid_rapp_core::states::{
    OPERATION_TRANSITIONS, PAIRING_TRANSITIONS, SESSION_TRANSITIONS, Transition,
};
use serde::Deserialize;

const MODEL: &str = include_str!("../../../docs/protocol/rapp-state-machine-v26.9.13.yaml");

#[derive(Debug, Deserialize)]
struct Model {
    document_version: String,
    pairing: Machine,
    session: Machine,
    operation: Machine,
}

#[derive(Debug, Deserialize)]
struct Machine {
    transitions: Vec<ModelTransition>,
}

#[derive(Debug, Deserialize)]
struct ModelTransition {
    from: FromStates,
    event: String,
    role: String,
    #[serde(default)]
    guard: Option<String>,
    to: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum FromStates {
    One(String),
    Many(Vec<String>),
}

/// One transition as a comparable name tuple.
type Row = (String, String, String, String, String);

fn model() -> Model {
    serde_yaml::from_str(MODEL).expect("the vendored model must parse")
}

fn model_rows(machine: &Machine) -> BTreeSet<Row> {
    let mut rows = BTreeSet::new();
    for transition in &machine.transitions {
        let from_states: Vec<&str> = match &transition.from {
            FromStates::One(state) => vec![state.as_str()],
            FromStates::Many(states) => states.iter().map(String::as_str).collect(),
        };
        for from in from_states {
            let inserted = rows.insert((
                from.to_owned(),
                transition.event.clone(),
                transition.role.clone(),
                transition.guard.clone().unwrap_or_default(),
                transition.to.clone(),
            ));
            assert!(inserted, "duplicate model row from {from}");
        }
    }
    rows
}

/// Converts a variant's `Debug` name to the model's `snake_case`, keeping
/// digits attached to their word. The operation admission state `Idle`
/// carries the model name `none`.
fn model_name(debug_name: &str) -> String {
    if debug_name == "Idle" {
        return "none".to_owned();
    }
    let mut out = String::new();
    for (index, character) in debug_name.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}

fn table_rows<State: Debug + 'static, Event: Debug + 'static>(
    table: &[Transition<State, Event>],
) -> BTreeSet<Row> {
    let mut rows = BTreeSet::new();
    for transition in table {
        let guard = match model_name(&format!("{:?}", transition.guard)).as_str() {
            "always" => String::new(),
            name => name.to_owned(),
        };
        let inserted = rows.insert((
            model_name(&format!("{:?}", transition.from)),
            model_name(&format!("{:?}", transition.event)),
            model_name(&format!("{:?}", transition.role)),
            guard,
            model_name(&format!("{:?}", transition.to)),
        ));
        assert!(inserted, "duplicate table row {transition:?}");
    }
    rows
}

fn assert_same(machine_name: &str, model_rows: &BTreeSet<Row>, table_rows: &BTreeSet<Row>) {
    let missing: Vec<_> = model_rows.difference(table_rows).collect();
    let extra: Vec<_> = table_rows.difference(model_rows).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "{machine_name} transcription mismatch\nmodel rows absent from the table: {missing:#?}\ntable rows absent from the model: {extra:#?}"
    );
}

#[test]
fn document_version_is_the_vendored_revision() {
    assert_eq!(model().document_version, "26.9.13");
}

#[test]
fn pairing_table_matches_the_model_exactly() {
    assert_same(
        "pairing",
        &model_rows(&model().pairing),
        &table_rows(PAIRING_TRANSITIONS),
    );
}

#[test]
fn session_table_matches_the_model_exactly() {
    assert_same(
        "session",
        &model_rows(&model().session),
        &table_rows(SESSION_TRANSITIONS),
    );
}

#[test]
fn operation_table_matches_the_model_exactly() {
    assert_same(
        "operation",
        &model_rows(&model().operation),
        &table_rows(OPERATION_TRANSITIONS),
    );
}
