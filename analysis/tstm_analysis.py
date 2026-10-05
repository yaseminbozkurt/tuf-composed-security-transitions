"""
Analysis & Reporting Pipeline
TUF Bounded State-Space Composition Testing

Status: REAL DATA. Real python-tuf 7.0.0 and real go-tuf v2.4.2 have been
executed as subprocesses against tuf-conformance's RepositorySimulator/
ClientRunner harness. This module is the deterministic analysis logic that
runs over sequence_corpus.json / execution_results.json.

Hard rules enforced by this module (do not relax without re-validating
against the frozen model in state_engine.py):

1. No inferential statistics. K<=4 core generation is exhaustive/deterministic,
   not a random sample -- so we report exact counts and exact proportions
   only. No p-values, no confidence intervals.

2. Conformance classification uses a strict, fixed adjudication ORDER --
   spec-version-difference -> optional-feature-difference -> (normative-
   violation | spec-ambiguity) -> harness-artifact -> conforming, exactly as
   implemented in adjudicate_conformance() below, which is the single source
   of truth for this order (a test exercising an unsupported *optional*
   feature must not be mislabeled NORMATIVE_VIOLATION, so optional-feature-
   difference must be checked first). Majority vote between python-tuf and
   go-tuf-v2 is never used as an oracle.

3. Coverage denominators (C2-C5) are computed MECHANICALLY from the frozen
   transition alphabet + finite state domains, never hand-picked after
   seeing results. The precondition table below is a STARTING-POINT EXAMPLE
   and must be reviewed against the real RepositorySimulator behavior before
   being treated as final.

4. This module never invents ACCEPT/REJECT outcomes, conformance numbers, or
   violation counts. Every number in a real report must trace back to a row
   in a real execution_results.json produced by actually running a client.
"""

from __future__ import annotations

import hashlib
import itertools
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

import pandas as pd

# ---------------------------------------------------------------------------
# 1. Frozen model constants (must match state_engine.py's transition alphabet)
# ---------------------------------------------------------------------------

TRANSITIONS: list[str] = [
    "ROOT_ROTATE_VALID", "ROOT_ROTATE_SKIP", "ROOT_ROTATE_INSUF_THRESHOLD",
    "TIMESTAMP_ADVANCE", "TIMESTAMP_REPLAY",
    "SNAPSHOT_ADVANCE", "SNAPSHOT_REPLAY",
    "DELEGATION_CREATE", "DELEGATION_REMOVE",
    "DELEGATED_REPLAY_AFTER_REMOVAL", "METADATA_BY_REMOVED_KEY",
    "EXPIRE",
]

CORE_FAMILIES = {"F1", "F3", "F4", "F5"}
SECONDARY_FAMILIES = {"F2", "F6", "F7"}
# F8 intentionally absent -- subsumed pattern, not a distinct family.

ORACLE_PROPERTIES = ["P1", "P2", "P3", "P4", "P5"]

ORACLE_TYPE = {
    "P1": "DIRECT", "P2": "DIRECT", "P3": "DIRECT",
    "P4": "COMPOSED_UNAMBIGUOUS", "P5": "COMPOSED_UNAMBIGUOUS",
}

# Which transitions are the "payload" step for each property -- used to check
# whether a sequence actually reaches a property's precondition, not merely
# contains a superficially-related transition.
PROPERTY_PAYLOAD_TRANSITION = {
    "P1": "ROOT_ROTATE_INSUF_THRESHOLD",
    "P2": "ROOT_ROTATE_SKIP",
    "P3": {"TIMESTAMP_REPLAY", "SNAPSHOT_REPLAY"},
    "P4": "METADATA_BY_REMOVED_KEY",
    "P5": "DELEGATED_REPLAY_AFTER_REMOVAL",
}

CONFORMANCE_CLASSES = [
    "CONFORMING", "NORMATIVE_VIOLATION", "SPEC_VERSION_DIFFERENCE",
    "OPTIONAL_FEATURE_DIFFERENCE", "SPEC_AMBIGUITY", "HARNESS_ARTIFACT",
    "EXECUTION_FAILURE", "NOT_SUPPORTED",
]

# Reachability denominators (C2/C3) are no longer a hand-authored adjacency
# table. See state_engine.py: a specification-derived finite state machine
# (precondition + effect per transition, each traceable to a spec clause),
# validated against every real executed sequence in this study, whose
# breadth-first enumeration IS the denominator below. The hand table this
# replaced treated every REJECT-outcome transition as a terminal dead end,
# which made "reject -> recovery" compositions -- like this study's own
# real, executed P1 sequence -- structurally unreachable by construction,
# not because they do not occur in real TUF client behavior.
import state_engine as _engine


def sequence_id(family: str, oracle_properties: Iterable[str], transitions: Iterable[str]) -> str:
    """Deterministic content-derived ID so re-generating the same sequence
    always yields the same ID.

    THE SINGLE CANONICAL ID GENERATOR for this project -- every other place
    that ever produced a sequence_id must call this function, not
    re-implement the hash.

    Includes family and oracle_properties in the hash input (not just the
    transition trace) so that two sequences with an identical transition
    trace but a different intended oracle property do not collide.
    """
    props = "+".join(sorted(oracle_properties))
    name = f"{family}|{props}|{'->'.join(transitions)}"
    h = hashlib.sha256(name.encode()).hexdigest()[:12]
    return f"SEQ-{h}"


# ---------------------------------------------------------------------------
# 2. Denominator generation (mechanical, not hand-picked)
# ---------------------------------------------------------------------------

def reachable_ordered_pairs() -> set[tuple[str, str]]:
    """C2 denominator: every (A, B) pair mechanically found reachable by
    state_engine's breadth-first enumeration from the frozen initial state."""
    return _engine.reachable_ordered_pairs(max_depth=4)


def reachable_ordered_triples(core_transitions_only: bool = True) -> set[tuple[str, str, str]]:
    """C3 denominator: ordered triples, mechanically enumerated by
    state_engine, restricted to CORE-family-relevant transitions (kept
    finite/tractable by restriction, not by an unbounded 'all possible
    sequences' metric)."""
    core_relevant = {
        "ROOT_ROTATE_VALID", "ROOT_ROTATE_SKIP", "ROOT_ROTATE_INSUF_THRESHOLD",
        "TIMESTAMP_ADVANCE", "TIMESTAMP_REPLAY", "SNAPSHOT_ADVANCE", "SNAPSHOT_REPLAY",
        "DELEGATION_CREATE", "DELEGATION_REMOVE", "DELEGATED_REPLAY_AFTER_REMOVAL",
        "METADATA_BY_REMOVED_KEY",
    } if core_transitions_only else set(TRANSITIONS)

    triples = _engine.reachable_ordered_triples(max_depth=4)
    return {(a, b, c) for (a, b, c) in triples if a in core_relevant and b in core_relevant and c in core_relevant}


BOUNDARY_STATES = [
    "VERSION_PREVIOUS", "VERSION_CURRENT", "VERSION_NEXT", "VERSION_SKIPPED_NEXT",
    "THRESHOLD_BELOW", "THRESHOLD_EXACT",
    "KEY_ACTIVE", "KEY_REMOVED", "KEY_PARTIAL_OVERLAP", "KEY_FULL_REPLACEMENT",
    "DELEGATION_ABSENT", "DELEGATION_ACTIVE", "DELEGATION_REMOVED",
    "EXPIRATION_VALID", "EXPIRATION_EXPIRED",
]  # fixed, finite


# ---------------------------------------------------------------------------
# 3. Loading + validation
# ---------------------------------------------------------------------------

def load_corpus(path: Path) -> pd.DataFrame:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    df = pd.json_normalize(records)
    if df.empty:
        return df
    assert df["sequence_id"].is_unique, "Duplicate sequence_id found -- corpus integrity violated."
    return df


def load_results(path: Path) -> pd.DataFrame:
    records = json.loads(Path(path).read_text(encoding="utf-8"))
    df = pd.json_normalize(records)
    return df


# ---------------------------------------------------------------------------
# 4. Coverage metrics (exact counts/fractions -- no inferential statistics)
# ---------------------------------------------------------------------------

def compute_c2(df_corpus: pd.DataFrame) -> dict:
    denom = reachable_ordered_pairs()
    if df_corpus.empty:
        return {"numerator": 0, "denominator": len(denom), "coverage": 0.0, "pairs_exercised": set()}
    exercised = set()
    for pairs in df_corpus.get("c2_pairs", []):
        for p in (pairs or []):
            a, b = p.split("->")
            exercised.add((a, b))
    exercised &= denom  # only count pairs that are actually in the frozen denominator
    return {
        "numerator": len(exercised),
        "denominator": len(denom),
        "coverage": round(len(exercised) / len(denom), 4) if denom else None,
        "pairs_exercised": exercised,
    }


def compute_c3(df_corpus: pd.DataFrame) -> dict:
    denom = reachable_ordered_triples()
    if df_corpus.empty:
        return {"numerator": 0, "denominator": len(denom), "coverage": 0.0}
    exercised = set()
    for triples in df_corpus.get("c3_triples", []):
        for t in (triples or []):
            a, b, c = t.split("->")
            exercised.add((a, b, c))
    exercised &= denom
    return {
        "numerator": len(exercised),
        "denominator": len(denom),
        "coverage": round(len(exercised) / len(denom), 4) if denom else None,
    }


def compute_c4(df_corpus: pd.DataFrame) -> dict:
    """A property counts as 'exercised' only if some sequence contains its
    designated payload transition (containment of a related transition is
    NOT sufficient by itself; this checks the specific payload step, which
    is the closest a static corpus-level check can get to 'precondition was
    actually reached' -- true precondition-reachability must be reconfirmed
    at generation time, not merely at this reporting stage)."""
    if df_corpus.empty:
        return {"numerator": 0, "denominator": len(ORACLE_PROPERTIES), "coverage": 0.0, "exercised": []}
    all_transitions_per_seq = df_corpus["transitions"].apply(
        lambda ts: {t["transition_type"] for t in ts}
    )
    exercised = []
    for prop, payload in PROPERTY_PAYLOAD_TRANSITION.items():
        payload_set = payload if isinstance(payload, set) else {payload}
        if all_transitions_per_seq.apply(lambda s: bool(s & payload_set)).any():
            exercised.append(prop)
    return {
        "numerator": len(exercised),
        "denominator": len(ORACLE_PROPERTIES),
        "coverage": round(len(exercised) / len(ORACLE_PROPERTIES), 4),
        "exercised": exercised,
    }


def compute_c5(df_corpus: pd.DataFrame) -> dict:
    denom = len(BOUNDARY_STATES)
    if df_corpus.empty:
        return {"numerator": 0, "denominator": denom, "coverage": 0.0, "exercised": set()}
    exercised = set()
    for bs in df_corpus.get("boundary_states", []):
        exercised |= set(bs or [])
    exercised &= set(BOUNDARY_STATES)
    return {
        "numerator": len(exercised),
        "denominator": denom,
        "coverage": round(len(exercised) / denom, 4),
        "exercised": exercised,
    }


def baseline_vs_tstm_delta(df_corpus: pd.DataFrame) -> pd.DataFrame:
    """Splits the corpus by origin and reports each population's coverage
    separately, plus the delta. This is the core RQ1 table."""
    rows = []
    for origin in ["BASELINE_MAPPED", "TSTM_GENERATED"]:
        subset = df_corpus[df_corpus.get("origin", pd.Series(dtype=str)) == origin] if not df_corpus.empty else df_corpus
        rows.append({
            "origin": origin,
            "n_sequences": len(subset),
            "C2_coverage": compute_c2(subset)["coverage"],
            "C3_coverage": compute_c3(subset)["coverage"],
            "C4_coverage": compute_c4(subset)["coverage"],
            "C5_coverage": compute_c5(subset)["coverage"],
        })
    out = pd.DataFrame(rows).set_index("origin")
    if len(out) == 2 and not df_corpus.empty:
        delta = out.loc["TSTM_GENERATED"] - out.loc["BASELINE_MAPPED"]
        delta.name = "DELTA (TSTM - BASELINE)"
        out = pd.concat([out, delta.to_frame().T])
    return out


# ---------------------------------------------------------------------------
# 5. Conformance adjudication -- strict order, never majority vote
# ---------------------------------------------------------------------------

def adjudicate_conformance(row: pd.Series) -> str:
    """Deterministic classification. Order matters: each check is evaluated
    only if the previous ones did not already resolve the row. This function
    must be the ONLY place a conformance_class is assigned -- never
    hand-labeled, never majority-vote.
    """
    if row.get("execution_status") in {"HARNESS_ERROR", "TIMEOUT", "CRASH"}:
        return "EXECUTION_FAILURE"
    if row.get("execution_status") == "COMPLETED" and "UNSUPPORTED" in (row.get("observed_decision_trace") or []):
        return "NOT_SUPPORTED"
    # spec-version-difference must be checked BEFORE treating anything as a violation
    if row.get("spec_version_mismatch_flag") is True:
        return "SPEC_VERSION_DIFFERENCE"
    if row.get("optional_feature_flag") is True:
        return "OPTIONAL_FEATURE_DIFFERENCE"
    if row.get("oracle_match") is False:
        if row.get("oracle_type") == "AMBIGUOUS":
            return "SPEC_AMBIGUITY"
        return "NORMATIVE_VIOLATION"
    if row.get("harness_flag") is True:
        return "HARNESS_ARTIFACT"
    if row.get("oracle_match") is True:
        return "CONFORMING"
    return "EXECUTION_FAILURE"  # fallback: never leave a row unclassified


# ---------------------------------------------------------------------------
# 6. Report generation
# ---------------------------------------------------------------------------

PLACEHOLDER_NOTICE = (
    "[[ PLANNED_EXPERIMENT_PLACEHOLDER -- no real python-tuf / go-tuf-v2 "
    "execution has occurred. Every number below is either 0/empty (no data) "
    "or computed from clearly-labeled SYNTHETIC EXAMPLE rows for pipeline "
    "validation only. Do not cite these numbers as findings. ]]"
)


def generate_report(df_corpus: pd.DataFrame, df_results: pd.DataFrame, synthetic: bool) -> str:
    lines = [f"# TUF TSTM Conformance Report{'  (SYNTHETIC EXAMPLE RUN)' if synthetic else ''}", ""]
    lines.append(PLACEHOLDER_NOTICE if (df_results.empty or synthetic) else "")
    lines.append("")

    lines.append("## Coverage: Baseline vs TSTM")
    delta_table = baseline_vs_tstm_delta(df_corpus)
    lines.append(delta_table.to_markdown() if not delta_table.empty else "_no corpus data_")
    lines.append("")

    lines.append("## Conformance classification (exact counts, no inferential statistics)")
    if df_results.empty:
        lines.append("_no execution results -- nothing to classify yet_")
    else:
        counts = (
            df_results.groupby(["implementation", "family", "conformance_class"])
            .size()
            .rename("n")
            .reset_index()
        )
        pivot = counts.pivot_table(
            index=["implementation", "family"], columns="conformance_class", values="n", fill_value=0
        )
        for cls in CONFORMANCE_CLASSES:
            if cls not in pivot.columns:
                pivot[cls] = 0
        pivot = pivot[CONFORMANCE_CLASSES]
        lines.append(pivot.to_markdown())
    lines.append("")

    lines.append("## Rule reminders applied by this report")
    lines.append("- No p-values / confidence intervals (exact counts only, K<=4 is exhaustive not sampled).")
    lines.append("- conformance_class assigned only by `adjudicate_conformance()`, never by majority vote.")
    lines.append("- Zero-violation result is reported as a valid, publishable finding, not a null.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 7. Self-test / schema-validation run using clearly-labeled synthetic rows
# ---------------------------------------------------------------------------

def _synthetic_example() -> tuple[pd.DataFrame, pd.DataFrame]:
    """FOR PIPELINE VALIDATION ONLY. These are not real TUF sequences and
    EXAMPLE_IMPL_A / EXAMPLE_IMPL_B are not python-tuf or go-tuf. This exists
    solely to prove the code above executes correctly end-to-end without
    fabricating any claim about a real TUF implementation."""
    corpus = [
        {
            "sequence_id": sequence_id("F1", ["P2"], ["ROOT_ROTATE_VALID", "ROOT_ROTATE_VALID", "ROOT_ROTATE_SKIP"]),
            "family": "F1", "origin": "TSTM_GENERATED",
            "transitions": [
                {"step_index": 0, "transition_type": "ROOT_ROTATE_VALID", "parameters": {}, "counts_toward_k": True},
                {"step_index": 1, "transition_type": "ROOT_ROTATE_VALID", "parameters": {}, "counts_toward_k": True},
                {"step_index": 2, "transition_type": "ROOT_ROTATE_SKIP", "parameters": {}, "counts_toward_k": True},
            ],
            "length": 3, "initial_state": {}, "expected_state_trace": [],
            "oracle_properties": ["P2"],
            "c2_pairs": ["ROOT_ROTATE_VALID->ROOT_ROTATE_VALID", "ROOT_ROTATE_VALID->ROOT_ROTATE_SKIP"],
            "c3_triples": ["ROOT_ROTATE_VALID->ROOT_ROTATE_VALID->ROOT_ROTATE_SKIP"],
            "boundary_states": ["VERSION_SKIPPED_NEXT"],
        },
        {
            "sequence_id": sequence_id("F4", ["P5"], ["DELEGATION_CREATE", "DELEGATION_REMOVE", "DELEGATED_REPLAY_AFTER_REMOVAL"]),
            "family": "F4", "origin": "TSTM_GENERATED",
            "transitions": [
                {"step_index": 0, "transition_type": "DELEGATION_CREATE", "parameters": {}, "counts_toward_k": True},
                {"step_index": 1, "transition_type": "DELEGATION_REMOVE", "parameters": {}, "counts_toward_k": True},
                {"step_index": 2, "transition_type": "DELEGATED_REPLAY_AFTER_REMOVAL", "parameters": {}, "counts_toward_k": True},
            ],
            "length": 3, "initial_state": {}, "expected_state_trace": [],
            "oracle_properties": ["P5"],
            "c2_pairs": ["DELEGATION_CREATE->DELEGATION_REMOVE", "DELEGATION_REMOVE->DELEGATED_REPLAY_AFTER_REMOVAL"],
            "c3_triples": ["DELEGATION_CREATE->DELEGATION_REMOVE->DELEGATED_REPLAY_AFTER_REMOVAL"],
            "boundary_states": ["DELEGATION_REMOVED"],
        },
        {
            "sequence_id": sequence_id("F3", ["P3"], ["ROOT_ROTATE_VALID", "TIMESTAMP_ADVANCE", "TIMESTAMP_REPLAY"]),
            "family": "F3", "origin": "BASELINE_MAPPED",
            "baseline_source": {"file": "test_rollback.py", "test_function": "test_new_timestamp_version_rollback", "repo_commit": "EXAMPLE-NOT-REAL"},
            "transitions": [
                {"step_index": 0, "transition_type": "ROOT_ROTATE_VALID", "parameters": {}, "counts_toward_k": False},
                {"step_index": 1, "transition_type": "TIMESTAMP_ADVANCE", "parameters": {}, "counts_toward_k": True},
                {"step_index": 2, "transition_type": "TIMESTAMP_REPLAY", "parameters": {}, "counts_toward_k": True},
            ],
            "length": 2, "initial_state": {}, "expected_state_trace": [],
            "oracle_properties": ["P3"],
            "c2_pairs": ["TIMESTAMP_ADVANCE->TIMESTAMP_REPLAY"],
            "c3_triples": [],
            "boundary_states": ["VERSION_PREVIOUS"],
        },
    ]

    results = [
        {
            "sequence_id": corpus[0]["sequence_id"], "implementation": "EXAMPLE_IMPL_A",
            "implementation_version": "example-not-real", "spec_version": "example",
            "execution_status": "COMPLETED", "observed_decision_trace": ["ACCEPT", "ACCEPT", "REJECT"],
            "observed_final_state": {}, "oracle_match": True, "oracle_type": "DIRECT",
            "spec_version_mismatch_flag": False, "optional_feature_flag": False, "harness_flag": False,
            "conformance_class": None, "family": "F1",
            "failure_stage": None, "raw_log_reference": "example-not-real",
        },
        {
            "sequence_id": corpus[1]["sequence_id"], "implementation": "EXAMPLE_IMPL_B",
            "implementation_version": "example-not-real", "spec_version": "example",
            "execution_status": "COMPLETED", "observed_decision_trace": ["ACCEPT", "ACCEPT", "ACCEPT"],
            "observed_final_state": {}, "oracle_match": False, "oracle_type": "COMPOSED_UNAMBIGUOUS",
            "spec_version_mismatch_flag": False, "optional_feature_flag": False, "harness_flag": False,
            "conformance_class": None, "family": "F4",
            "failure_stage": "2", "raw_log_reference": "example-not-real",
        },
    ]

    df_c = pd.json_normalize(corpus)
    df_r = pd.json_normalize(results)
    df_r["conformance_class"] = df_r.apply(adjudicate_conformance, axis=1)
    return df_c, df_r


if __name__ == "__main__":
    print("Running SCHEMA-VALIDATION SELF-TEST on synthetic (non-TUF) example data.")
    print("This proves the pipeline executes correctly. It is NOT a TUF finding.\n")
    df_c, df_r = _synthetic_example()
    report = generate_report(df_c, df_r, synthetic=True)
    print(report)
